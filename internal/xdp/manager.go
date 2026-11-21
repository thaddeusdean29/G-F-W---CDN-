//go:build linux

package xdp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// ObjectsCore 对应 cdn_xdp.c 中与区域封禁无关的那批 map / program。
//
// 单独拆出来、而且**必须是大写开头的类型名**，是为了兼容旧 .o：
// LoadAndAssign 对 spec 里缺失的 map 是硬报错的（"missing map geo_block4"），照全量结构体
// 装旧 .o 会让 XDP 整个挂不上——面板 XDP 页一片空白，而节点其实只是没重新编译 cdn_xdp.o。
// 反射赋值时经过**未导出**的嵌入字段拿到的值是不可写的（cilium/ebpf 会返回
// "field X: can't set value"），所以嵌进来的这个类型必须是导出名。
type ObjectsCore struct {
	CdnXdpFilter *ebpf.Program `ebpf:"cdn_xdp_filter"`
	Blocklist    *ebpf.Map     `ebpf:"blocklist"`
	Whitelist    *ebpf.Map     `ebpf:"whitelist"`
	SynRate      *ebpf.Map     `ebpf:"syn_rate"`
	PpsRate      *ebpf.Map     `ebpf:"pps_rate"`
	ConnRate     *ebpf.Map     `ebpf:"conn_rate"`
	UdpRate      *ebpf.Map     `ebpf:"udp_rate"`
	IcmpRate     *ebpf.Map     `ebpf:"icmp_rate"`
	UdpDnsRate   *ebpf.Map     `ebpf:"udp_dns_rate"`
	TcpRstRate   *ebpf.Map     `ebpf:"tcp_rst_rate"`
	AckRate      *ebpf.Map     `ebpf:"ack_rate"`
	TcpFinRate   *ebpf.Map     `ebpf:"tcp_fin_rate"`
	XdpStats     *ebpf.Map     `ebpf:"xdp_stats"`
	XdpConfig    *ebpf.Map     `ebpf:"xdp_config"`
	ServicePorts *ebpf.Map     `ebpf:"service_ports"`
	// IPv6 平行 map。IPv4 的键是 __u32，装不下 128 位地址，因此 IPv6 需要独立一套。
	Blocklist6 *ebpf.Map `ebpf:"blocklist6"`
	Whitelist6 *ebpf.Map `ebpf:"whitelist6"`
	SynRate6   *ebpf.Map `ebpf:"syn_rate6"`
	AckRate6   *ebpf.Map `ebpf:"ack_rate6"`
	PpsRate6   *ebpf.Map `ebpf:"pps_rate6"`
	// UDP/ICMPv6/RST/FIN 以前与 pps_rate6 共用或根本没有 IPv6 版，AutoBlocker 看不到
	// IPv6 的这几类洪水。LoadAndAssign 要求 .o 里有这些 map：旧 .o 必须重新编译。
	UdpRate6    *ebpf.Map `ebpf:"udp_rate6"`
	IcmpRate6   *ebpf.Map `ebpf:"icmp_rate6"`
	TcpRstRate6 *ebpf.Map `ebpf:"tcp_rst_rate6"`
	TcpFinRate6 *ebpf.Map `ebpf:"tcp_fin_rate6"`
}

// xdpObjects 是完整对象集合：核心那批 + 区域封禁的四棵 LPM trie。
// geo 字段只在 .o 里确实有这四张表时才会被装载，否则它们保持 nil，
// 由 GeoState() 把"没这几张表"当成原因报出去。
type xdpObjects struct {
	ObjectsCore
	GeoBlock4 *ebpf.Map `ebpf:"geo_block4"`
	GeoBlock6 *ebpf.Map `ebpf:"geo_block6"`
	GeoExc4   *ebpf.Map `ebpf:"geo_exc4"`
	GeoExc6   *ebpf.Map `ebpf:"geo_exc6"`
}

// Stats 对应 xdp_stats map 中的 struct stats
// XDP 层统计：通过/封禁总数、各原因封禁数
type Stats struct {
	Passed              uint64 `json:"passed"`
	DroppedBlocklist    uint64 `json:"dropped_blocklist"`
	DroppedSynFlood     uint64 `json:"dropped_syn_flood"`
	DroppedPPS          uint64 `json:"dropped_pps"`
	DroppedConnLimit    uint64 `json:"dropped_conn_limit"`
	DroppedUDPFlood     uint64 `json:"dropped_udp_flood"`
	DroppedICMPFlood    uint64 `json:"dropped_icmp_flood"`
	DroppedDNSAmp       uint64 `json:"dropped_dns_amp"`
	DroppedTCPRst       uint64 `json:"dropped_tcp_rst"`
	DroppedInvalidFlags uint64 `json:"dropped_invalid_flags"`
	DroppedFragment     uint64 `json:"dropped_fragment"`
	DroppedInvalidPkt   uint64 `json:"dropped_invalid_packet"`
	DroppedAckFlood     uint64 `json:"dropped_ack_flood"`
	DroppedBogon        uint64 `json:"dropped_bogon"`
	DroppedPshAckGuard  uint64 `json:"dropped_psh_ack_guard"`
	DroppedFinFlood     uint64 `json:"dropped_fin_flood"`
	DroppedOrphanTCP    uint64 `json:"dropped_orphan_tcp"`
	// DroppedServiceOrphan：发往服务端口、只命中监听 socket 且不是合法 syncookie 握手的
	// 非 SYN 包（随机源 ACK / PSH-ACK / RST / FIN 洪水）。
	DroppedServiceOrphan uint64 `json:"dropped_service_orphan"`
	// DroppedGeo：命中区域封禁 LPM trie 丢掉的包数（v4+v6 合计）。它是"四层真的在按
	// 下发的表丢包"的唯一现场证据：EntriesV4/EntriesV6 只说明装载进去，不说明执行过。
	// 旧 .o 没有这一项，读数为 0 而不是报错。
	DroppedGeo uint64 `json:"dropped_geo"`
}

// XDPConfig 对应 xdp_config map 中的配置
type XDPConfig struct {
	SYNLimit         uint32 `json:"syn_limit"`
	PPSLimit         uint32 `json:"pps_limit"`
	UDPLimit         uint32 `json:"udp_limit"`
	ConnLimit        uint32 `json:"conn_limit"`
	Enabled          uint32 `json:"enabled"`
	ICMPLimit        uint32 `json:"icmp_limit"`
	UDPDNSLimit      uint32 `json:"udp_dns_limit"`
	TCPRstLimit      uint32 `json:"tcp_rst_limit"`
	FragmentDrop     uint32 `json:"fragment_drop"`
	InvalidFlagsDrop uint32 `json:"invalid_flags_drop"`
	AckLimit         uint32 `json:"ack_limit"`
	FinLimit         uint32 `json:"fin_limit"`
	// PortGuard=1 时启用服务端口白名单：入站新连接（纯 SYN，即 syn && !ack）的 dst port
	// 必须命中 service_ports map，否则直接 DROP。CDN 节点对外只服务 80/443，打到别的端口
	// 的新连接一定不是业务流量（扫描、无状态洪水、反射包落点）。在最前面丢掉它们，既省掉
	// 后面的速率统计开销，也不让这些包挤占 per-IP 速率预算，避免攻击者用垃圾端口把正常
	// IP 的配额刷爆。
	//
	// 注意它只拦纯 SYN：既有连接的后续包（SYN-ACK/ACK/FIN/RST）不做端口检查。边缘节点
	// 回源时是客户端，源站返回包的 dst port 是本机随机临时端口，永远不在白名单里——
	// 若一律按 dport 过滤，回源会 100% 失败（"upstream timed out while connecting"），
	// 站点全站 504 而源站侧完全正常，极难定位。历史上就踩过这个坑。
	PortGuard uint32 `json:"port_guard"`
	// BogonDrop=1 时丢弃源地址不可能合法的包：IPv4 的 127.0.0.0/8 与 224.0.0.0/3
	// （组播 + IANA 保留的 Class E + 广播），IPv6 的 ff00::/8。
	//
	// 检查位置在速率统计和封禁表之前，目的不是省流量而是保护状态表：伪造源每包一个
	// 随机地址，撞不到任何 per-IP 阈值，但会占满 LRU 速率表的条目、把真实攻击源的
	// 计数挤出去，还会被 AutoBlocker 判定后写进 blocklist 和落盘存档。
	//
	// 有意不含 169.254.0.0/16（云元数据服务 169.254.169.254 的返回包源地址）、
	// 0.0.0.0/8（DHCP）、100.64.0.0/10（运营商 CGNAT，后面是真实用户）、RFC1918
	// 私网（内网回源/前置 LB）和 IPv6 的 fe80::/10（NDP/RA，丢了 IPv6 直接断网）。
	BogonDrop uint32 `json:"bogon_drop"`
	// PshAckGuard=1 时丢弃无连接状态的 PSH-ACK 包，防止 PSH-ACK 反射攻击。
	//
	// 攻击者通过 Middlebox 转发伪造源的 PSH-ACK 包，目标服务器对每个无效 PSH-ACK
	// 都会回复 RST（TCP 协议栈行为），形成 RST 洪水。在 XDP 层检查：如果收到
	// PSH+ACK 但该源 IP 在 conn_rate map 中没有 SYN 记录（从未握手或连接已关闭），
	// 直接丢弃，避免触发内核生成 RST 响应。
	//
	// 副作用：客户端重启后复用旧连接的包会被拦截，但这本身就是无效连接，客户端会
	// 超时重连，不影响正常用户（正常流程里客户端会先发 SYN）。
	PshAckGuard uint32 `json:"psh_ack_guard"`
	// CPUSYNLimit 是**每个 CPU** 每秒放行的新连接 SYN 总数上限（0=disabled）。
	// 针对每包换一个伪造源的 SYN 洪水：per-IP 阈值对它无效，只能按总量兜底。
	// 实际全局上限 ≈ CPUSYNLimit × 真正收包的 CPU 数（= min(收包队列数, 核数)），
	// 所以默认值由 DefaultSynTotalBudget 除出来，而不是给一个裸数字——
	// 否则同样的设置在 2 队列和 16 队列节点上的放行量差 8 倍。
	// 超出的包计入 dropped_syn_flood，与 per-IP 超限同一读数。
	CPUSYNLimit uint32 `json:"cpu_syn_limit"`
	// OrphanTCPDrop=1 时丢弃发往非服务端口、且本机没有对应 socket 的 TCP 包（纯 SYN 除外）。
	// 针对 TCP 反射攻击：真实 Web 服务器被冒用本机 IP 的 SYN 诱导，把 SYN-ACK/ACK 打到本机
	// 随机高位端口，内核对每个包回 RST，上行带宽被打满。源 IP 都是真实服务器且单源量小，
	// per-IP 限速和封禁都无效。回源连接在 connect() 时就进了内核连接表，源站回包不受影响。
	// 唯一的误伤场景是本机跑 Docker 等另一个 netns 经 NAT 出网的业务。
	OrphanTCPDrop uint32 `json:"orphan_tcp_drop"`
	// ServiceOrphanDrop=1 时丢弃发往**服务端口**、不是纯 SYN、且内核里只查到监听 socket
	// （没有属于它的连接）的 TCP 包。针对随机源 ACK / PSH-ACK / RST / FIN 洪水：每包换一个源，
	// per-IP 限速无效，内核却对每个包回 RST 占满上行。syncookie 握手的第三个 ACK 先经
	// bpf_tcp_check_syncookie 验证，SYN 洪水期间真人仍能连上。需要内核 5.3+。
	ServiceOrphanDrop uint32 `json:"service_orphan_drop"`
}

// Manager 管理 XDP 程序的生命周期和封禁表。
type Manager struct {
	iface   string
	objPath string // 编译好的 .o 文件路径
	objs    *xdpObjects
	lnk     link.Link
	// mode 是实际挂载模式："native"（驱动模式）或 "generic"（SKB 模式），未挂载为空。
	mode string
	// cfgMu 保护 cfgErr：写 xdp_config 有三条来源（启动 InitDefaults、面板下发、
	// 存档恢复），并发覆盖时不能出现「成功清掉了别人的失败」这种乱序。
	cfgMu  sync.Mutex
	cfgErr string // 最近一次 SetConfig 失败的原因，成功时清空
	// geoMu 串行化四棵区域 trie 的换表，并保护下面这份区域状态。
	geoMu sync.Mutex
	geo   geoL4State
}

// geoL4State 是区域封禁在四层的状态。它只描述"网卡上现在到底有什么"，
// 判该装什么由 geo.Guard.BuildL4Install 负责。
type geoL4State struct {
	// available：.o 里 geo_block4/geo_block6/geo_exc4/geo_exc6 四张表都在。
	// 为 false 时（旧 .o）GeoState 直接报"重新编译 cdn_xdp.o"，其余字段一律不填。
	available bool
	// installed 记的是上一次成功写进内核的键，换表时靠它算出该删哪些残留。
	// 为 nil 表示从来没装成功过，四棵树里不该有本进程写进去的东西。
	installed *installedGeo
	// Fingerprint 是 trie 里这份表对应的下发指纹，用来回答"面板那张表和网卡
	// 这张表是不是同一张"。
	fingerprint string
	// reason 是"现在什么都没装"的原因（观察模式、allow、总闸关着……）。
	reason string
	// err 是最近一次装表失败的原因，成功时清空。它和 reason 分开：reason 是策略
	// 本来就不该装四层，err 是本来该装上却没装上——面板要按不同颜色显示的那一类。
	err string
	// applied 是最近一次换表的时刻（成功或清空都算）。
	applied time.Time
}

func NewManager(iface, objPath string) *Manager {
	return &Manager{iface: iface, objPath: objPath}
}

// Load 加载 XDP 程序并附加到网卡。
func (m *Manager) Load() error {
	spec, err := ebpf.LoadCollectionSpec(m.objPath)
	if err != nil {
		return fmt.Errorf("load collection spec: %w", err)
	}

	objs := &xdpObjects{}
	// 按 .o 里到底有没有 geo_* 表决定装哪个结构体，而不是先装全量、失败再降级：
	// LoadAndAssign 对 spec 里缺的 map 是硬报错的，靠错误文本来判断"缺的是哪张表"
	// 会把 XDP 挂不上这件事的成因写成一次字符串匹配。
	if hasGeoMaps(spec) {
		if err := spec.LoadAndAssign(objs, nil); err != nil {
			return fmt.Errorf("load and assign: %w", err)
		}
		m.geo.available = true
	} else {
		// 旧 .o：核心功能照常挂载，区域封禁的四层丢包如实报告为没装上。
		// 这里必须只装 ObjectsCore（不含 geo 字段），否则整个 Load 失败、
		// 节点从"少一个四层封禁"变成"L4 完全裸奔"。
		if err := spec.LoadAndAssign(&objs.ObjectsCore, nil); err != nil {
			return fmt.Errorf("load and assign: %w", err)
		}
		fmt.Fprintf(os.Stderr, "[xdp] %s: %s\n", m.objPath, geoMissingObj)
	}
	m.objs = objs

	iface, err := net.InterfaceByName(m.iface)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", m.iface, err)
	}

	// 先试原生驱动模式（在网卡驱动 rx 路径里直接 XDP_DROP，跳过 skb 分配，L4 洪水下 CPU 才不会爆）；
	// 驱动/网卡不支持时（虚拟化、老网卡）回落 SKB/generic 模式——generic 下每包都要先 alloc_skb，
	// 保护效果弱得多，但至少能拦静态 blocklist。
	lnk, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.CdnXdpFilter,
		Interface: iface.Index,
		Flags:     link.XDPDriverMode,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "[xdp] driver mode attach failed on %s (%v); falling back to generic/SKB mode\n", m.iface, err)
		lnk, err = link.AttachXDP(link.XDPOptions{
			Program:   objs.CdnXdpFilter,
			Interface: iface.Index,
			Flags:     link.XDPGenericMode,
		})
		if err != nil {
			return fmt.Errorf("attach xdp to %s (both driver and generic modes failed): %w", m.iface, err)
		}
		fmt.Fprintf(os.Stderr, "[xdp] attached to %s in generic/SKB mode\n", m.iface)
		m.mode = "generic"
	} else {
		fmt.Fprintf(os.Stderr, "[xdp] attached to %s in native driver mode\n", m.iface)
		m.mode = "native"
	}
	m.lnk = lnk
	return nil
}

// Mode 返回实际挂载模式："native" / "generic"，未挂载时为空串。
func (m *Manager) Mode() string {
	if !m.Loaded() {
		return ""
	}
	return m.mode
}

// Iface 返回 XDP 挂载（或将要挂载）的网卡名。
func (m *Manager) Iface() string {
	return m.iface
}

// Close 卸载 XDP 程序并释放资源。
func (m *Manager) Close() {
	if m.lnk != nil {
		_ = m.lnk.Close()
	}
	if m.objs != nil {
		if m.objs.CdnXdpFilter != nil {
			_ = m.objs.CdnXdpFilter.Close()
		}
		closeMap(m.objs.Blocklist)
		closeMap(m.objs.Whitelist)
		closeMap(m.objs.SynRate)
		closeMap(m.objs.PpsRate)
		closeMap(m.objs.ConnRate)
		closeMap(m.objs.UdpRate)
		closeMap(m.objs.IcmpRate)
		closeMap(m.objs.UdpDnsRate)
		closeMap(m.objs.TcpRstRate)
		closeMap(m.objs.AckRate)
		closeMap(m.objs.TcpFinRate)
		closeMap(m.objs.XdpStats)
		closeMap(m.objs.XdpConfig)
		closeMap(m.objs.ServicePorts)
		closeMap(m.objs.Blocklist6)
		closeMap(m.objs.Whitelist6)
		closeMap(m.objs.SynRate6)
		closeMap(m.objs.AckRate6)
		closeMap(m.objs.PpsRate6)
		closeMap(m.objs.UdpRate6)
		closeMap(m.objs.IcmpRate6)
		closeMap(m.objs.TcpRstRate6)
		closeMap(m.objs.TcpFinRate6)
		// 区域封禁的四棵 trie：旧 .o 上它们是 nil，closeMap 自己会跳过。
		closeMap(m.objs.GeoBlock4)
		closeMap(m.objs.GeoBlock6)
		closeMap(m.objs.GeoExc4)
		closeMap(m.objs.GeoExc6)
	}
}

func closeMap(m *ebpf.Map) {
	if m != nil {
		_ = m.Close()
	}
}

// BlockIP 将 IPv4 地址加入封禁表。不支持 IPv6（XDP map 仅存 IPv4）。
func (m *Manager) BlockIP(ip net.IP) error {
	if m.objs == nil {
		return fmt.Errorf("xdp not loaded")
	}
	if v6, ok := ipv6Key(ip); ok {
		if m.objs.Blocklist6 == nil {
			return fmt.Errorf("ipv6 blocklist map not available (edge binary predates IPv6 support?)")
		}
		return m.objs.Blocklist6.Update(v6, uint8(1), ebpf.UpdateAny)
	}
	key, ok := ipv4Key(ip)
	if !ok {
		return fmt.Errorf("invalid IP %v", ip)
	}
	return m.objs.Blocklist.Update(key, uint8(1), ebpf.UpdateAny)
}

// UnblockIP 从封禁表移除地址（IPv4/IPv6 各走对应的 map）。
func (m *Manager) UnblockIP(ip net.IP) error {
	if m.objs == nil {
		return fmt.Errorf("xdp not loaded")
	}
	if v6, ok := ipv6Key(ip); ok {
		if m.objs.Blocklist6 == nil {
			return fmt.Errorf("ipv6 blocklist map not available")
		}
		return m.objs.Blocklist6.Delete(v6)
	}
	key, ok := ipv4Key(ip)
	if !ok {
		return fmt.Errorf("invalid IP %v", ip)
	}
	return m.objs.Blocklist.Delete(key)
}

// AddToWhitelist 将地址加入白名单（绕过所有 XDP 检查）。
func (m *Manager) AddToWhitelist(ip net.IP) error {
	if m.objs == nil || m.objs.Whitelist == nil {
		return fmt.Errorf("xdp not loaded or whitelist map not available")
	}
	if v6, ok := ipv6Key(ip); ok {
		if m.objs.Whitelist6 == nil {
			return fmt.Errorf("ipv6 whitelist map not available")
		}
		return m.objs.Whitelist6.Update(v6, uint8(1), ebpf.UpdateAny)
	}
	key, ok := ipv4Key(ip)
	if !ok {
		return fmt.Errorf("invalid IP %v", ip)
	}
	return m.objs.Whitelist.Update(key, uint8(1), ebpf.UpdateAny)
}

// RemoveFromWhitelist 从白名单移除地址。
func (m *Manager) RemoveFromWhitelist(ip net.IP) error {
	if m.objs == nil || m.objs.Whitelist == nil {
		return fmt.Errorf("xdp not loaded or whitelist map not available")
	}
	if v6, ok := ipv6Key(ip); ok {
		if m.objs.Whitelist6 == nil {
			return fmt.Errorf("ipv6 whitelist map not available")
		}
		return m.objs.Whitelist6.Delete(v6)
	}
	key, ok := ipv4Key(ip)
	if !ok {
		return fmt.Errorf("invalid IP %v", ip)
	}
	return m.objs.Whitelist.Delete(key)
}

// ListWhitelisted 返回所有白名单 IP（IPv4 + IPv6）。
func (m *Manager) ListWhitelisted() ([]net.IP, error) {
	if m.objs == nil || m.objs.Whitelist == nil {
		return nil, fmt.Errorf("xdp not loaded or whitelist map not available")
	}
	return listAddrMaps(m.objs.Whitelist, m.objs.Whitelist6)
}

// ListBlocked 返回所有封禁 IP（IPv4 + IPv6）。
//
// 以前只遍历 IPv4 的 blocklist：IPv6 封禁在面板上看不到，AutoBlocker.GetBlockedIPs
// 也漏报，运维会以为 IPv6 封禁没生效而重复下发。
func (m *Manager) ListBlocked() ([]net.IP, error) {
	if m.objs == nil {
		return nil, fmt.Errorf("xdp not loaded")
	}
	return listAddrMaps(m.objs.Blocklist, m.objs.Blocklist6)
}

// listAddrMaps 遍历一对 IPv4([4]byte 键) / IPv6([16]byte 键) 的 __u8 标记 map。
// v6 为 nil（旧 .o 没有 IPv6 map）时只返回 IPv4。
func listAddrMaps(v4, v6 *ebpf.Map) ([]net.IP, error) {
	var ips []net.IP
	var (
		key4 [4]byte
		val  uint8
	)
	iter := v4.Iterate()
	for iter.Next(&key4, &val) {
		if val == 1 {
			ips = append(ips, ipv4FromKey(key4))
		}
	}
	if err := iter.Err(); err != nil {
		return ips, err
	}
	if v6 == nil {
		return ips, nil
	}
	var key6 [16]byte
	iter6 := v6.Iterate()
	for iter6.Next(&key6, &val) {
		if val == 1 {
			ip := make(net.IP, 16)
			copy(ip, key6[:])
			ips = append(ips, ip)
		}
	}
	return ips, iter6.Err()
}

// GetStats 读取 XDP 统计计数。
func (m *Manager) GetStats() (*Stats, error) {
	if m.objs == nil {
		return nil, fmt.Errorf("xdp not loaded")
	}
	// stats map 是 ARRAY，只有 index 0
	var key uint32 = 0
	// C 端 struct stats 现为 19 个 __u64 = 152 字节（旧 .o 是 18 个 = 144）。缓冲区按 map
	// 实际的 value_size 分配：cilium/ebpf 要求长度严格相等，写死长度的话 C 端加一个字段、
	// 或节点上还是旧 .o，整个 GetStats 都会失败（面板 XDP 页全空）。旧 .o 缺的尾部计数按 0 处理。
	vs := int(m.objs.XdpStats.ValueSize())
	if vs < 128 {
		return nil, fmt.Errorf("xdp_stats value size %d < 128: cdn_xdp.o too old, recompile it", vs)
	}
	raw := make([]byte, vs)
	if err := m.objs.XdpStats.Lookup(key, &raw); err != nil {
		return nil, err
	}
	if len(raw) < statsSize {
		raw = append(raw, make([]byte, statsSize-len(raw))...)
	}
	s := &Stats{
		Passed:               binary.LittleEndian.Uint64(raw[0:8]),
		DroppedBlocklist:     binary.LittleEndian.Uint64(raw[8:16]),
		DroppedSynFlood:      binary.LittleEndian.Uint64(raw[16:24]),
		DroppedPPS:           binary.LittleEndian.Uint64(raw[24:32]),
		DroppedConnLimit:     binary.LittleEndian.Uint64(raw[32:40]),
		DroppedUDPFlood:      binary.LittleEndian.Uint64(raw[40:48]),
		DroppedICMPFlood:     binary.LittleEndian.Uint64(raw[48:56]),
		DroppedDNSAmp:        binary.LittleEndian.Uint64(raw[56:64]),
		DroppedTCPRst:        binary.LittleEndian.Uint64(raw[64:72]),
		DroppedInvalidFlags:  binary.LittleEndian.Uint64(raw[72:80]),
		DroppedFragment:      binary.LittleEndian.Uint64(raw[80:88]),
		DroppedInvalidPkt:    binary.LittleEndian.Uint64(raw[88:96]),
		DroppedAckFlood:      binary.LittleEndian.Uint64(raw[96:104]),
		DroppedBogon:         binary.LittleEndian.Uint64(raw[104:112]),
		DroppedPshAckGuard:   binary.LittleEndian.Uint64(raw[112:120]),
		DroppedFinFlood:      binary.LittleEndian.Uint64(raw[120:128]),
		DroppedOrphanTCP:     binary.LittleEndian.Uint64(raw[128:136]),
		DroppedServiceOrphan: binary.LittleEndian.Uint64(raw[136:144]),
	}
	// 区域丢包这一项只有装了 geo trie 的新 .o 才有。按 map 的真实 value_size 单独判断，
	// 而不是把 statsSize 一并改成 152：那样旧 .o 上这一句会直接越界 panic，
	// 把整页 XDP 读数换成一次崩溃。
	if len(raw) >= statsSizeGeo {
		s.DroppedGeo = binary.LittleEndian.Uint64(raw[144:152])
	}
	return s, nil
}

// statsSize 是当前 cdn_xdp.c 里 struct stats 去掉区域计数后的大小（18 个 __u64）。
const statsSize = 144

// statsSizeGeo 是加上 dropped_geo 之后的大小（19 个 __u64）。
const statsSizeGeo = 152

// SetConfig 设置 XDP 参数（rate limits / master switch）。
//
// 成功与否都记进 cfgErr，供 Status().Armed 判定：写入失败时 C 侧继续用旧的（或全零的）
// 配置跑，光看 attached 完全发现不了，面板显示的阈值和实际执行的就是两套数。
func (m *Manager) SetConfig(cfg XDPConfig) error {
	err := m.applyConfig(cfg)
	m.cfgMu.Lock()
	if err != nil {
		m.cfgErr = err.Error()
	} else {
		m.cfgErr = ""
	}
	m.cfgMu.Unlock()
	return err
}

// ConfigError 返回最近一次写 xdp_config 失败的原因，成功时为空串。
func (m *Manager) ConfigError() string {
	m.cfgMu.Lock()
	defer m.cfgMu.Unlock()
	return m.cfgErr
}

func (m *Manager) applyConfig(cfg XDPConfig) error {
	if m.objs == nil || m.objs.XdpConfig == nil {
		return fmt.Errorf("xdp not loaded")
	}
	// 开启端口守卫前必须确认 service_ports 里有条目。空 map + port_guard=1 =
	// 每个 TCP 包都查不到端口 → 全部 XDP_DROP → 节点连 SSH 都进不去，只能走 VNC 救。
	if cfg.PortGuard != 0 {
		n, err := m.countServicePorts()
		if err != nil {
			return fmt.Errorf("port_guard requested but service_ports unreadable: %w", err)
		}
		if n == 0 {
			return fmt.Errorf("refusing to enable port_guard: service_ports map is empty (would drop all TCP traffic)")
		}
	}
	var key uint32 = 0
	raw := xdpConfigRaw{
		SYNLimit:          cfg.SYNLimit,
		PPSLimit:          cfg.PPSLimit,
		UDPLimit:          cfg.UDPLimit,
		ConnLimit:         cfg.ConnLimit,
		Enabled:           cfg.Enabled,
		ICMPLimit:         cfg.ICMPLimit,
		UDPDNSLimit:       cfg.UDPDNSLimit,
		TCPRSTLimit:       cfg.TCPRstLimit,
		FragmentDrop:      cfg.FragmentDrop,
		InvalidFlagsDrop:  cfg.InvalidFlagsDrop,
		AckLimit:          cfg.AckLimit,
		PortGuard:         cfg.PortGuard,
		BogonDrop:         cfg.BogonDrop,
		PshAckGuard:       cfg.PshAckGuard,
		FinLimit:          cfg.FinLimit,
		CPUSYNLimit:       cfg.CPUSYNLimit,
		OrphanTCPDrop:     cfg.OrphanTCPDrop,
		ServiceOrphanDrop: cfg.ServiceOrphanDrop,
	}
	buf, err := encodeConfigRaw(raw, int(m.objs.XdpConfig.ValueSize()))
	if err != nil {
		return err
	}
	return m.objs.XdpConfig.Update(key, buf, ebpf.UpdateAny)
}

// xdpConfigRawSize 是当前 cdn_xdp.c 里 struct xdp_config 的大小（18 个 __u32）。
const xdpConfigRawSize = 18 * 4

// encodeConfigRaw 按 map 实际的 value_size 编码配置。
//
// 新字段只会追加在结构体末尾，所以旧 .o（value_size 更小）只需截掉尾部：新版 cdnedge
// 配旧 .o 时 XDP 照常工作，只是新功能不生效，而不是 SetConfig 整体失败、连
// enabled 都写不进去（ARRAY map 全零 = XDP 形同关闭）。比当前结构体还大的 value_size
// 说明 .o 比 Go 代码新，字段含义对不上，拒绝写入。
func encodeConfigRaw(raw xdpConfigRaw, valueSize int) ([]byte, error) {
	var w bytes.Buffer
	if err := binary.Write(&w, binary.LittleEndian, raw); err != nil {
		return nil, err
	}
	buf := w.Bytes()
	if valueSize > len(buf) {
		return nil, fmt.Errorf("xdp_config value size %d > %d: cdn_xdp.o is newer than this binary", valueSize, len(buf))
	}
	if valueSize < 16*4 {
		return nil, fmt.Errorf("xdp_config value size %d too small: cdn_xdp.o too old, recompile it", valueSize)
	}
	return buf[:valueSize], nil
}

// decodeConfigRaw 是 encodeConfigRaw 的反向：旧 .o 缺的尾部字段按 0 读。
func decodeConfigRaw(b []byte) (xdpConfigRaw, error) {
	var raw xdpConfigRaw
	if len(b) < xdpConfigRawSize {
		b = append(b, make([]byte, xdpConfigRawSize-len(b))...)
	}
	err := binary.Read(bytes.NewReader(b[:xdpConfigRawSize]), binary.LittleEndian, &raw)
	return raw, err
}

// GetConfig 读取当前 XDP 配置。
func (m *Manager) GetConfig() (*XDPConfig, error) {
	if m.objs == nil || m.objs.XdpConfig == nil {
		return nil, fmt.Errorf("xdp not loaded")
	}
	var key uint32 = 0
	buf := make([]byte, m.objs.XdpConfig.ValueSize())
	if err := m.objs.XdpConfig.Lookup(key, &buf); err != nil {
		return nil, err
	}
	config, err := decodeConfigRaw(buf)
	if err != nil {
		return nil, err
	}
	return &XDPConfig{
		SYNLimit:          config.SYNLimit,
		PPSLimit:          config.PPSLimit,
		UDPLimit:          config.UDPLimit,
		ConnLimit:         config.ConnLimit,
		Enabled:           config.Enabled,
		ICMPLimit:         config.ICMPLimit,
		UDPDNSLimit:       config.UDPDNSLimit,
		TCPRstLimit:       config.TCPRSTLimit,
		FragmentDrop:      config.FragmentDrop,
		InvalidFlagsDrop:  config.InvalidFlagsDrop,
		AckLimit:          config.AckLimit,
		PortGuard:         config.PortGuard,
		BogonDrop:         config.BogonDrop,
		PshAckGuard:       config.PshAckGuard,
		FinLimit:          config.FinLimit,
		CPUSYNLimit:       config.CPUSYNLimit,
		OrphanTCPDrop:     config.OrphanTCPDrop,
		ServiceOrphanDrop: config.ServiceOrphanDrop,
	}, nil
}

// xdpConfigRaw 是与 C 侧 struct xdp_config 二进制对应的布局：连续 __u32，无填充。
// 字段顺序必须与 cdn_xdp.c 中的声明严格一致，且总长度必须等于 map 的 value_size，
// 否则 cilium/ebpf 会以 "value too small/large" 报错，SetConfig 全部失败。
type xdpConfigRaw struct {
	SYNLimit          uint32
	PPSLimit          uint32
	UDPLimit          uint32
	ConnLimit         uint32
	Enabled           uint32
	ICMPLimit         uint32
	UDPDNSLimit       uint32
	TCPRSTLimit       uint32
	FragmentDrop      uint32
	InvalidFlagsDrop  uint32
	AckLimit          uint32
	PortGuard         uint32
	BogonDrop         uint32
	PshAckGuard       uint32
	FinLimit          uint32
	CPUSYNLimit       uint32
	OrphanTCPDrop     uint32
	ServiceOrphanDrop uint32
}

// DefaultServicePorts 是 port_guard 开启后放行的 TCP 端口集合：
// 静态基线（80/443/22）+ 调用方传入的额外端口 + 本机当前所有 LISTEN 端口。
//
// 纳入 LISTEN 端口有两个原因：一是语义正确——port_guard 要丢的是"本机根本没人监听"
// 的端口上的包；二是安全兜底——SSH 常被改到非标端口，只靠硬编码 22 会把管理员锁在门外，
// 而 XDP 在驱动层丢包，iptables 都救不回来，只能从 VPS 控制台 VNC 进去。
func DefaultServicePorts(extra ...uint16) []uint16 {
	ports := []uint16{80, 443, 22}
	ports = append(ports, extra...)
	return append(ports, listeningTCPPorts()...)
}

// SetServicePorts 覆盖式写入服务端口白名单：先写入新端口，再删掉表里多余的旧端口。
// 顺序刻意如此——先加后删，中途任何时刻表都不会短暂变空，避免在 port_guard 已开启的
// 情况下出现"表空 → 全丢包"的窗口。
func (m *Manager) SetServicePorts(ports []uint16) error {
	if m.objs == nil || m.objs.ServicePorts == nil {
		return fmt.Errorf("xdp not loaded or service_ports map not available")
	}
	if len(ports) == 0 {
		return fmt.Errorf("refusing to write an empty service port list")
	}

	want := make(map[uint32]bool, len(ports))
	for _, p := range ports {
		if p == 0 {
			continue
		}
		want[uint32(p)] = true
	}
	if len(want) == 0 {
		return fmt.Errorf("refusing to write an empty service port list")
	}
	// map 是定容 HASH（max_entries=256）。写满之后 Update 会返回 E2BIG，剩下的端口
	// 静默进不去 —— 而"进不去"等于该端口流量被 DROP。宁可整体拒绝、让 port_guard
	// 保持关闭，也不要装出一个残缺的白名单。
	if max := m.objs.ServicePorts.MaxEntries(); max > 0 && uint32(len(want)) > max {
		return fmt.Errorf("service port list has %d entries, map holds %d", len(want), max)
	}

	for k := range want {
		if err := m.objs.ServicePorts.Update(k, uint8(1), ebpf.UpdateAny); err != nil {
			return fmt.Errorf("add service port %d: %w", k, err)
		}
	}

	var (
		key   uint32
		val   uint8
		stale []uint32
		iter  = m.objs.ServicePorts.Iterate()
	)
	for iter.Next(&key, &val) {
		if !want[key] {
			stale = append(stale, key)
		}
	}
	if err := iter.Err(); err != nil {
		return fmt.Errorf("iterate service ports: %w", err)
	}
	for _, k := range stale {
		_ = m.objs.ServicePorts.Delete(k)
	}
	return nil
}

// ListServicePorts 返回当前生效的服务端口白名单。
func (m *Manager) ListServicePorts() ([]uint16, error) {
	if m.objs == nil || m.objs.ServicePorts == nil {
		return nil, fmt.Errorf("xdp not loaded or service_ports map not available")
	}
	var (
		key   uint32
		val   uint8
		ports []uint16
		iter  = m.objs.ServicePorts.Iterate()
	)
	for iter.Next(&key, &val) {
		ports = append(ports, uint16(key))
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	return ports, iter.Err()
}

func (m *Manager) countServicePorts() (int, error) {
	if m.objs == nil || m.objs.ServicePorts == nil {
		return 0, fmt.Errorf("service_ports map not available")
	}
	var (
		key  uint32
		val  uint8
		n    int
		iter = m.objs.ServicePorts.Iterate()
	)
	for iter.Next(&key, &val) {
		n++
	}
	return n, iter.Err()
}

// InitDefaults 使用默认值初始化配置（仅在首次加载时调用）。
//
// extraPorts 为除 80/443/22 之外还需放行的 TCP 端口（如边缘 agent 的对外端口）。
// 端口白名单先写入、成功后才把 port_guard 打开；写入失败则退化为 port_guard=0
// （只丢失这一项优化，其余防护照常生效），绝不留下"开关已开但表是空的"状态。
func (m *Manager) InitDefaults(extraPorts ...uint16) error {
	portGuard := uint32(0)
	if err := m.SetServicePorts(DefaultServicePorts(extraPorts...)); err != nil {
		fmt.Fprintf(os.Stderr, "[xdp] service port whitelist not installed (%v); port_guard stays off\n", err)
	} else {
		portGuard = 1
	}

	return m.SetConfig(XDPConfig{
		PortGuard:   portGuard,
		SYNLimit:    DefaultSYNLimit,
		PPSLimit:    DefaultPPSLimit,
		UDPLimit:    DefaultUDPLimit,
		ConnLimit:   DefaultConnLimit,
		Enabled:     1,
		ICMPLimit:   DefaultICMPLimit,   // 挡 ping flood；不影响正常 ping 诊断
		UDPDNSLimit: 0,                  // 0 = disabled（UDP 已全站禁）
		TCPRstLimit: DefaultTCPRstLimit, // 挡 ptcp 这类 SYN+RST 脉冲攻击
		// FragmentDrop=1：本站全站禁 UDP 且只跑 HTTP/HTTPS，TCP 自己按 MSS 分段，
		// 合法 IP 分片在这个场景下几乎不存在。而分片是经典的绕过手段（首片带正常头、
		// 后续片藏载荷，让只看首片的中间设备漏判）+ 分片重组会耗内核内存。故直接丢。
		FragmentDrop:     1,
		InvalidFlagsDrop: 1,               // 1 = drop invalid TCP flags（NULL/XMAS/SYN+FIN 等）
		AckLimit:         DefaultAckLimit, // ACK flood 上限
		// BogonDrop=1：丢掉源地址不可能合法的包（127/8、224/3、ff00::/8）。
		// 无条件默认开启，因为这两段地址在真实互联网上作为源地址出现只可能是伪造。
		// 与 port_guard 不同，它不依赖任何 map，没有"开关开了但表是空的"这种自锁风险。
		BogonDrop: 1,
		// PshAckGuard 默认关闭：XDP 无连接状态，只能用「该 IP 发过 SYN」近似判断，
		// conn_rate 是 LRU，攻击时条目被挤掉后真人的正常数据包也会被丢。
		// 曾默认开启且不限目的端口，把源站回包全丢了 → 全站 504。需要时在面板手动开。
		PshAckGuard: 0,
		// FinLimit：只统计发往服务端口的 FIN（回源连接的 FIN 不计），真人每条连接一个 FIN。
		FinLimit: DefaultFinLimit,
		// CPUSYNLimit 按本机收包队列数从总预算里除出来，队列读不到时按 1 个 CPU 算。
		// 默认开启（以前恒为 0，即「每包换一个源的 SYN 洪水在 L4 完全没有总量闸门」），
		// 预算依据见 DefaultSynTotalBudget 的注释；面板可单独调这一项并落存档。
		CPUSYNLimit: CPUSYNLimitFor(rxQueues(m.iface), runtime.NumCPU()),
		// OrphanTCPDrop 默认开：边缘节点只跑 cdnedge + Tengine，本机发起的连接都在内核
		// 连接表里，查不到 socket 的非服务端口 TCP 包只可能是反射/伪造流量。
		OrphanTCPDrop: 1,
		// ServiceOrphanDrop 默认开：真人的非 SYN 包要么属于已有连接，要么是 syncookie
		// 握手（已单独验证），只命中监听 socket 的其余包只可能是伪造的。
		ServiceOrphanDrop: 1,
	})
}

// Loaded 返回 XDP 程序是否已加载。
func (m *Manager) Loaded() bool {
	return m.objs != nil && m.lnk != nil
}

// DefaultObjPath 返回默认的 .o 文件路径。
func DefaultObjPath() string {
	exe, _ := os.Executable()
	return filepath.Join(filepath.Dir(exe), "cdn_xdp.o")
}

// ipv6Key 判断地址是否为真正的 IPv6，并转成与 C 侧 struct ipv6_key 对应的 16 字节数组。
//
// 注意 net.IP 的表示陷阱：IPv4 地址在 Go 里常以 16 字节的 IPv4-mapped 形式存放
// （::ffff:a.b.c.d），len(ip)==16 并不代表它是 IPv6。必须以 ip.To4()==nil 作为判据，
// 否则 IPv4 会被错误地塞进 IPv6 map，两边都拦不住。
func ipv6Key(ip net.IP) ([16]byte, bool) {
	var key [16]byte
	if ip == nil || ip.To4() != nil {
		return key, false
	}
	v6 := ip.To16()
	if v6 == nil {
		return key, false
	}
	copy(key[:], v6)
	return key, true
}
