//go:build linux

package xdp

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

// AutoBlocker 自动封禁超速 IP
type AutoBlocker struct {
	mgr       *Manager
	interval  time.Duration // 扫描间隔
	duration  time.Duration // 封禁时长
	synLimit  uint64        // SYN 超速阈值
	ppsLimit  uint64        // PPS 超速阈值
	connLimit uint64        // 连接数超速阈值
	udpLimit  uint64        // UDP 超速阈值
	ackLimit  uint64        // ACK 超速阈值
	rstLimit  uint64        // RST 超速阈值
	finLimit  uint64        // FIN 超速阈值
	icmpLimit uint64        // ICMP 超速阈值
	dnsLimit  uint64        // UDP DNS 超速阈值
	ctx       context.Context
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	mu        sync.RWMutex

	// blockedIPs 记录 IP → **封禁过期时刻**（不是封禁起始时刻）。
	//
	// 存绝对过期时间而不是起始时间，是为了让状态能跨进程重启还原：起始时间 + duration
	// 的算法依赖「duration 这个配置项没变过」，一旦改了阈值配置或重启，同一条记录算出的
	// 剩余时长就跟封禁时的承诺不一致。存过期时刻则与配置解耦。
	blockedIPs map[string]time.Time

	// statePath 是封禁状态的落盘位置。空字符串表示不持久化（单测/非常规部署）。
	statePath string

	// dirty 标记 blockedIPs 自上次落盘后有过变更，由 run 协程在每轮扫描末尾统一写盘。
	// 不在 blockIfNeeded 里直接落盘：一轮扫描在洪水下可能命中几百个 IP，
	// 那会变成几百次整份 JSON 重写 —— 恰好发生在节点负载最高的时刻。
	dirty bool

	// rates 把速率 map 里单调递增的累计包数换算成两次扫描之间的真实 pps
	// （见 rateDiffer 的说明）。只在 run 协程里访问，无需加锁。
	rates *rateDiffer

	// ladder 是累犯递增的封禁时长阶梯（第 N 次被封用第 N 档，超出则用最后一档封顶）。
	// 为空时退化为固定时长 duration。见 DefaultBanLadder 的说明。
	ladder []time.Duration

	// offenders 记录每个 IP 的累犯次数与最近一次被封时刻，决定下次用阶梯的哪一档。
	//
	// 这张表**必须与封禁一起落盘**：只落封禁不落累犯记账的话，节点重启后所有 IP 都回到
	// 首档，攻击者只要打到节点重启（或等一次版本升级）就能把自己的档位清零 —— 递增机制
	// 形同虚设，而这恰恰是引入它要解决的问题。
	offenders map[string]*offenderRecord

	// offenderTTL 是累犯计数的遗忘窗口，超过这段时间未再犯则计数归零。
	offenderTTL time.Duration

	// banConfigFromPanel 标记 ladder/offenderTTL 是面板下发的（而非启动 flag）。
	//
	// 需要这个标记才能区分两种"当前值"：面板下发的要落盘并在重启后继续生效；启动
	// flag 的不能落盘，否则第一次落盘就把当时的 flag 值固化进存档，之后改 systemd
	// unit 再重启也不生效 —— 表现为「改了启动参数没用」，而存档是不会有人想到去看的地方。
	banConfigFromPanel bool

	// broadcastHook 在封禁成功后被调用，用于把封禁广播到其他节点（可选）。
	broadcastHook func(ip string, duration time.Duration)

	// externalBanned 判断 L7（WAF）是否仍封禁该 IP；nil 表示不检查。
	externalBanned func(ip string) bool
}

// AutoBlockerConfig 自动封禁配置
type AutoBlockerConfig struct {
	Interval time.Duration
	Duration time.Duration
	// 各 per-IP 速率阈值（包/秒）。**0 一律表示关闭该项判定**，不会被替换成任何默认值 ——
	// 默认值只在 defaults.go 里定义，要用就显式传 DefaultSYNLimit 等常量。
	SYNLimit  uint64
	PPSLimit  uint64
	ConnLimit uint64
	UDPLimit  uint64
	AckLimit  uint64
	// RST/FIN/ICMP/DNS 的 per-IP 速率阈值（包/秒），同样 0 = 关闭。
	// 以前这几类洪水只在 XDP 里被限速丢包，源地址永远不进 blocklist：攻击者可以
	// 无限期地以略高于限速的速率持续消耗 XDP 的 per-IP 计算与 LRU 容量。
	RSTLimit  uint64
	FINLimit  uint64
	ICMPLimit uint64
	DNSLimit  uint64
	// StatePath 封禁状态存档路径。留空则不落盘，重启后所有 XDP 自动封禁清零。
	StatePath string
	// BanLadder 是累犯递增的封禁时长阶梯：同一 IP 第 N 次被封用第 N 档，超出长度后
	// 一直用最后一档（封顶）。留空则使用 DefaultBanLadder；显式传长度为 1 的切片
	// 等于固定时长。Duration 只在阶梯为空且无默认值时作为兜底使用。
	BanLadder []time.Duration
	// OffenderTTL 是累犯计数的遗忘窗口，0 表示用 DefaultOffenderTTL。
	// 这个值同时决定「被误封的真人要多久才能回到首档」，不宜设得过长。
	OffenderTTL time.Duration
	// BroadcastHook 在封禁成功后被调用，用于把封禁广播到其他节点（可选）。
	// 边缘节点注入此 hook 来通知主控/其他边缘节点；主控侧无需注入（主控的 WAF
	// 封禁已通过 Pusher 广播，不走 AutoBlocker）。
	BroadcastHook func(ip string, duration time.Duration)
}

// NewAutoBlocker 创建自动封禁器
func NewAutoBlocker(mgr *Manager, cfg AutoBlockerConfig) *AutoBlocker {
	if cfg.Interval == 0 {
		cfg.Interval = 10 * time.Second
	}
	if cfg.Duration == 0 {
		cfg.Duration = 5 * time.Minute
	}
	// 阈值**不做零值兜底**。曾经这里有一串 `if cfg.XxxLimit == 0 { cfg.XxxLimit = <默认值> }`，
	// 它把 0 的语义从「关闭这项检测」悄悄改成了「用一个写死在这里的值」，后果有两层：
	//
	//   ① 关不掉。scan/rateDiffer 都按 limit==0 表示关闭来处理，调用方把 DefaultAckLimit
	//      设成 0 想停掉 ACK 判定，实际得到 2000 —— 比默认的 8000 更容易误伤，而且
	//      日志和面板都看不出阈值被换过，排查时只会觉得「明明关了却还在封」。
	//   ② 两套默认值。defaults.go 是唯一该定义默认阈值的地方，这里再写一份意味着改了
	//      defaults.go 却对没显式传值的调用方无效。
	//
	// 因此：要默认值就显式传 xdp.DefaultXxxLimit（cmd/cdnedge/main.go 就是这么做的），
	// 传 0 就是明确要求关闭这一项。

	// 阶梯留空用默认值。与阈值不同，空阶梯没有「关闭封禁」这种有用语义
	// （真要关就别启动 AutoBlocker），所以这里兜底是合适的。
	ladder := cfg.BanLadder
	if len(ladder) == 0 {
		ladder = DefaultBanLadder
	}
	offenderTTL := cfg.OffenderTTL
	if offenderTTL <= 0 {
		offenderTTL = DefaultOffenderTTL
	}

	ctx, cancel := context.WithCancel(context.Background())
	return &AutoBlocker{
		mgr:            mgr,
		interval:       cfg.Interval,
		duration:       cfg.Duration,
		synLimit:       cfg.SYNLimit,
		ppsLimit:       cfg.PPSLimit,
		connLimit:      cfg.ConnLimit,
		udpLimit:       cfg.UDPLimit,
		ackLimit:       cfg.AckLimit,
		rstLimit:       cfg.RSTLimit,
		finLimit:       cfg.FINLimit,
		icmpLimit:      cfg.ICMPLimit,
		dnsLimit:       cfg.DNSLimit,
		ctx:            ctx,
		cancel:         cancel,
		blockedIPs:     make(map[string]time.Time),
		statePath:      cfg.StatePath,
		rates:          newRateDiffer(cfg.Interval),
		ladder:         ladder,
		offenders:      make(map[string]*offenderRecord),
		offenderTTL:    offenderTTL,
		broadcastHook:  cfg.BroadcastHook,
	}
}

// Start 启动自动封禁监控。先恢复存档再开始扫描：
// eBPF blocklist 随 XDP 程序卸载一起消失，进程重启等于把所有攻击 IP 一次性放行，
// 攻击方只要让节点重启（或等一次版本升级）就能清空封禁。
func (a *AutoBlocker) Start() {
	a.restoreState()
	a.wg.Add(1)
	go a.run()
	// 启动时打出生效的阶梯：封禁时长现在不是一个固定值，日志里只写 duration 会
	// 误导 —— 运维看到「duration: 5m0s」却发现有 IP 被封了 12 小时，无从解释。
	if preview := LadderPreview(a.ladder); preview != nil {
		log.Printf("[XDP] AutoBlocker started (interval: %v, ban ladder: %v, offender TTL: %v)",
			a.interval, preview, a.offenderTTL)
	} else {
		log.Printf("[XDP] AutoBlocker started (interval: %v, fixed ban duration: %v)",
			a.interval, a.duration)
	}
}

// Stop 停止自动封禁监控，退出前落盘一次，保证优雅重启不丢封禁。
func (a *AutoBlocker) Stop() {
	a.cancel()
	a.wg.Wait()
	a.persistState()
	log.Println("[XDP] AutoBlocker stopped")
}

// SetBroadcastHook 设置封禁广播回调（可选，用于跨节点同步）。
func (a *AutoBlocker) SetBroadcastHook(hook func(ip string, duration time.Duration)) {
	a.mu.Lock()
	a.broadcastHook = hook
	a.mu.Unlock()
}

// restoreState 从存档恢复未过期的封禁，并重新写回 eBPF blocklist。
//
// 写回 map 是这里的关键：只恢复内存 map 会让 blockIfNeeded 的 alreadyBlocked 短路
// 认为「已经封了」，而 XDP 侧其实是空的 —— 攻击 IP 因此在剩余时长内获得完全免疫，
// 比不恢复更糟。
func (a *AutoBlocker) restoreState() {
	if a.statePath == "" {
		return
	}
	data, err := os.ReadFile(a.statePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Printf("[XDP] restore blocklist: read %s failed: %v", a.statePath, err)
		}
		return
	}
	st, err := decodeState(data)
	if err != nil {
		log.Printf("[XDP] restore blocklist: parse failed: %v", err)
		return
	}
	raw, offenders := st.Bans, st.Offenders

	// 先恢复面板下发过的阶梯配置，再恢复记账 —— 顺序要紧：下面的 TTL 过滤和
	// pruneOffendersLocked 都按 a.offenderTTL 判断，如果还是启动 flag 的值，
	// 就会按错误的窗口筛掉（或留下）记账。
	a.restoreBanConfig(st)

	now := time.Now()
	expired := 0
	bogons := 0
	// 先在锁外完成解析和写 eBPF map（BlockIP 是 syscall），最后一次性记账。
	revived := make(map[string]time.Time, len(raw))
	for ipStr, expStr := range raw {
		exp, err := time.Parse(time.RFC3339, expStr)
		if err != nil {
			continue
		}
		if !exp.After(now) {
			expired++
			continue
		}
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		// 丢掉存档里的伪造源地址。加入 bogon 过滤之前的存档会攒下这些条目，
		// 不过滤的话每次重启都把它们重新写回 blocklist，且因为记账也恢复了，
		// 它们会一直续命到过期为止 —— 白占 map 容量，且封它们本来就没有意义。
		if IsBogonSource(ip) {
			bogons++
			continue
		}
		if a.mgr == nil {
			continue
		}
		if err := a.mgr.BlockIP(ip); err != nil {
			// 不记账：留给后续扫描按实时速率重新判定，而不是记成已封却实际放行。
			log.Printf("[XDP] restore blocklist: re-block %s failed: %v", ipStr, err)
			continue
		}
		revived[ipStr] = exp
	}

	a.mu.Lock()
	for ip, exp := range revived {
		a.blockedIPs[ip] = exp
	}
	// 恢复累犯记账。这一步不受「封禁是否已过期」影响：一个 IP 的封禁到期了，但它
	// 的累犯次数应当保留到 offenderTTL 为止 —— 否则攻击者只要等封禁自然到期就能
	// 回到首档，递增机制只在"连续被封"时生效，挡不住 24 小时间隔轮询。
	// 已超出遗忘窗口的条目在这里直接丢掉，不必等下一次 banDurationFor 才清理。
	restoredOffenders := 0
	for ip, rec := range offenders {
		if rec == nil || rec.Count <= 0 {
			continue
		}
		if now.Sub(rec.LastSeen) > a.offenderTTL {
			continue
		}
		if IsBogonSourceStr(ip) {
			continue
		}
		a.offenders[ip] = rec
		restoredOffenders++
	}
	a.pruneOffendersLocked(now)
	a.mu.Unlock()

	log.Printf("[XDP] Restored %d blocked IPs and %d offender records from %s (%d expired, %d bogon source, dropped)",
		len(revived), restoredOffenders, a.statePath, expired, bogons)
}

// persistState 原子写出当前未过期的封禁和累犯记账。
// 先写 .tmp 再 rename：进程在写一半时被 kill 不会留下半截 JSON 导致下次启动整份存档失效。
func (a *AutoBlocker) persistState() {
	if a.statePath == "" {
		return
	}
	now := time.Now()
	a.mu.Lock()
	st := stateFile{
		Version:   stateVersion,
		Bans:      make(map[string]string, len(a.blockedIPs)),
		Offenders: make(map[string]*offenderRecord, len(a.offenders)),
	}
	// 只在面板显式下发过配置时写出这两项。没下发过就留空，让节点继续跟随启动 flag ——
	// 否则第一次落盘就把当时的 flag 值固化进存档，之后改 systemd unit 再也不生效，
	// 表现为「改了启动参数重启却没用」。
	if a.banConfigFromPanel {
		st.Ladder = FormatBanLadder(a.ladder)
		st.OffenderTTL = a.offenderTTL.String()
	}
	for ip, exp := range a.blockedIPs {
		if exp.After(now) {
			st.Bans[ip] = exp.Format(time.RFC3339)
		}
	}
	// 累犯记账即使对应封禁已到期也要写出：档位要活到 offenderTTL，否则等封禁自然
	// 到期就能回到首档（见 restoreState 的同一处说明）。只过滤已超窗口的。
	for ip, rec := range a.offenders {
		if rec == nil || now.Sub(rec.LastSeen) > a.offenderTTL {
			continue
		}
		st.Offenders[ip] = rec
	}
	a.mu.Unlock()

	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		log.Printf("[XDP] persist blocklist: marshal failed: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(a.statePath), 0755); err != nil {
		log.Printf("[XDP] persist blocklist: mkdir failed: %v", err)
		return
	}
	tmp := a.statePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		log.Printf("[XDP] persist blocklist: write failed: %v", err)
		return
	}
	if err := os.Rename(tmp, a.statePath); err != nil {
		log.Printf("[XDP] persist blocklist: rename failed: %v", err)
	}
}

func (a *AutoBlocker) run() {
	defer a.wg.Done()
	ticker := time.NewTicker(a.interval)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			a.scan()
			a.cleanupExpired()
			// 每轮扫描末尾统一落盘一次（仅在本轮有增删时真正写文件）。
			// 扫描间隔 5 秒，意味着最坏情况丢失 5 秒内新增的封禁 —— 相对于
			// 分钟级的封禁时长可以接受，换来的是洪水期间不做成百次文件写入。
			a.persistIfDirty()
		}
	}
}

// scan 读取各速率 map 的累计包数，与上一轮的快照做差分算出真实 pps，超阈值即封禁。
//
// 为什么必须差分：map 里的 total 是单调累计值，直接拿它跟 pps 阈值比较，任何长期活跃的
// 正常 IP 迟早会累计到超过阈值而被误封。差分（Δtotal / Δt）才是该 IP 在两次扫描之间的
// 真实速率，也才是 synLimit/ackLimit 这些"每秒多少包"阈值的正确语义。
func (a *AutoBlocker) scan() {
	// IPv6 的三张 map 在旧版 .o 里不存在，此时 readRateMap6 返回空，对应 sample 自然空转，
	// 不影响 IPv4 路径。
	hits := a.rates.diff(time.Now(), []rateSample{
		{name: "syn", totals: a.readRateMap("syn_rate"), limit: a.synLimit, reason: "syn_flood"},
		{name: "pps", totals: a.readRateMap("pps_rate"), limit: a.ppsLimit, reason: "pps_flood"},
		{name: "udp", totals: a.readRateMap("udp_rate"), limit: a.udpLimit, reason: "udp_flood"},
		{name: "ack", totals: a.readRateMap("ack_rate"), limit: a.ackLimit, reason: "ack_flood"},
		{name: "rst", totals: a.readRateMap("tcp_rst_rate"), limit: a.rstLimit, reason: "rst_flood"},
		{name: "fin", totals: a.readRateMap("tcp_fin_rate"), limit: a.finLimit, reason: "fin_flood"},
		{name: "icmp", totals: a.readRateMap("icmp_rate"), limit: a.icmpLimit, reason: "icmp_flood"},
		{name: "dns", totals: a.readRateMap("udp_dns_rate"), limit: a.dnsLimit, reason: "dns_flood"},
		{name: "syn6", totals: a.readRateMap6("syn_rate6"), limit: a.synLimit, reason: "syn_flood_v6"},
		{name: "ack6", totals: a.readRateMap6("ack_rate6"), limit: a.ackLimit, reason: "ack_flood_v6"},
		{name: "pps6", totals: a.readRateMap6("pps_rate6"), limit: a.ppsLimit, reason: "pps_flood_v6"},
		{name: "udp6", totals: a.readRateMap6("udp_rate6"), limit: a.udpLimit, reason: "udp_flood_v6"},
		{name: "icmp6", totals: a.readRateMap6("icmp_rate6"), limit: a.icmpLimit, reason: "icmp_flood_v6"},
		{name: "rst6", totals: a.readRateMap6("tcp_rst_rate6"), limit: a.rstLimit, reason: "rst_flood_v6"},
		{name: "fin6", totals: a.readRateMap6("tcp_fin_rate6"), limit: a.finLimit, reason: "fin_flood_v6"},
	})
	for _, h := range hits {
		a.blockIfNeeded(h.IP, h.Reason)
	}

	// 半开连接数是"当前瞬时值"而非累计量（conn_check 每 60 秒衰减一半），
	// 因此直接与 connLimit 比较，不做差分。
	for ipStr, count := range a.readConnRateMap() {
		if a.connLimit > 0 && uint64(count) > a.connLimit {
			a.blockIfNeeded(ipStr, "conn_flood")
		}
	}
}

// rateEntrySize 是 C 侧 struct rate_entry 的大小：count + window_start + total，
// 三个 __u64 共 24 字节。必须与 cdn_xdp.c 严格一致，否则 Iterate 会因 value size
// 不匹配而失败，所有速率 map 都读不出来（自动封禁静默失效）。
const rateEntrySize = 24

// readRateMap 读取速率 map 中所有条目的**累计包数**（struct rate_entry.total）。
//
// 这里刻意读 total 而不是 count：count 是 1 秒滑窗字段，每秒被 XDP 重置，而扫描每 10 秒
// 才跑一次 —— 读 count 只能看到扫描那一瞬间所在窗口的值，其余 9 秒多的攻击数据早已清零；
// 且 count 超过 XDP 侧 limit 后就不再自增（rate_check 提前 return），实际封顶在 limit+1，
// 永远到不了 AutoBlocker 更高的封禁阈值。total 单调累加，配合 pps() 的差分才能得到真实速率。
func (a *AutoBlocker) readRateMap(mapName string) map[string]int64 {
	result := make(map[string]int64)
	if a.mgr == nil || a.mgr.objs == nil {
		return result
	}
	var m *ebpf.Map
	switch mapName {
	case "syn_rate":
		m = a.mgr.objs.SynRate
	case "pps_rate":
		m = a.mgr.objs.PpsRate
	case "udp_rate":
		m = a.mgr.objs.UdpRate
	case "icmp_rate":
		m = a.mgr.objs.IcmpRate
	case "ack_rate":
		m = a.mgr.objs.AckRate
	case "tcp_rst_rate":
		m = a.mgr.objs.TcpRstRate
	case "tcp_fin_rate":
		m = a.mgr.objs.TcpFinRate
	case "udp_dns_rate":
		m = a.mgr.objs.UdpDnsRate
	default:
		return result
	}
	if m == nil {
		return result
	}
	// 键必须按 [4]byte 读：见 ipv4Key 的字节序说明。
	var (
		key [4]byte
		val [rateEntrySize]byte
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		total := binary.LittleEndian.Uint64(val[16:24])
		if total == 0 {
			continue
		}
		result[ipv4FromKey(key).String()] = int64(total)
	}
	return result
}

// readRateMap6 读取 IPv6 速率 map（键为 16 字节地址）。IPv6 的 map 键类型与 IPv4 不同，
// 无法共用 readRateMap；若不单独扫这些 map，IPv6 洪水虽然在 XDP 里会被限速丢包，
// 但源地址永远不会被自动加进 blocklist6，防护会弱一档。
func (a *AutoBlocker) readRateMap6(mapName string) map[string]int64 {
	result := make(map[string]int64)
	if a.mgr == nil || a.mgr.objs == nil {
		return result
	}
	var m *ebpf.Map
	switch mapName {
	case "syn_rate6":
		m = a.mgr.objs.SynRate6
	case "ack_rate6":
		m = a.mgr.objs.AckRate6
	case "pps_rate6":
		m = a.mgr.objs.PpsRate6
	case "udp_rate6":
		m = a.mgr.objs.UdpRate6
	case "icmp_rate6":
		m = a.mgr.objs.IcmpRate6
	case "tcp_rst_rate6":
		m = a.mgr.objs.TcpRstRate6
	case "tcp_fin_rate6":
		m = a.mgr.objs.TcpFinRate6
	default:
		return result
	}
	// 旧版边缘二进制加载的 .o 里没有这些 map，此时为 nil，直接返回空（不影响 IPv4 逻辑）。
	if m == nil {
		return result
	}
	var (
		key [16]byte
		val [rateEntrySize]byte
	)
	iter := m.Iterate()
	for iter.Next(&key, &val) {
		// 与 IPv4 一致读 total（见 readRateMap 注释）。
		total := binary.LittleEndian.Uint64(val[16:24])
		if total == 0 {
			continue
		}
		ip := make(net.IP, 16)
		copy(ip, key[:])
		result[ip.String()] = int64(total)
	}
	return result
}

// readConnRateMap 读取 conn_rate map 中每 IP 的半开连接计数。
// eBPF value 布局是 C 侧的 struct conn_entry，共 24 字节：
// 4 字节 count + 4 字节 _pad + 8 字节 last_update + 8 字节 decay_start。
// 尺寸必须与 C 侧严格一致，否则 Iterate 会以 value size 不匹配失败，
// 结果是半开连接超限的 IP 一个都进不了 blocklist（静默失效）。
func (a *AutoBlocker) readConnRateMap() map[string]int64 {
	result := make(map[string]int64)
	if a.mgr == nil || a.mgr.objs == nil || a.mgr.objs.ConnRate == nil {
		return result
	}
	var (
		key [4]byte
		val [24]byte
	)
	iter := a.mgr.objs.ConnRate.Iterate()
	for iter.Next(&key, &val) {
		count := binary.LittleEndian.Uint32(val[0:4])
		if count == 0 {
			continue
		}
		result[ipv4FromKey(key).String()] = int64(count)
	}
	return result
}

// blockIfNeeded 如果 IP 未被封禁则封禁。
//
// 记账必须在 BlockIP 成功之后。此前是先写 blockedIPs 再调 BlockIP，一旦 BlockIP 失败
// （map 满、IPv6 map 缺失、权限问题）就直接 return —— 那个 IP 从此被记为"已封禁"，
// 开头的 alreadyBlocked 短路让后续每轮扫描都跳过它，而 XDP blocklist 里其实没有它。
// 结果是攻击 IP 在整个 duration 内获得完全免疫，且日志只有一行失败、之后再无动静。
func (a *AutoBlocker) blockIfNeeded(ipStr, reason string) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return
	}

	// 伪造源地址不记账。eBPF 侧（bogon_drop）已经在驱动层丢了这些包，能走到这里说明
	// 节点跑的是旧 .o 或 bogon_drop 被关掉了。关键在于**封它没有意义**：无状态洪水的
	// 伪造源每个包都不一样，封一条只是白占 blocklist（65536 上限）和落盘存档的容量，
	// 把真实攻击源挤出去。直接跳过，让速率表的 LRU 自己淘汰它们。
	if IsBogonSource(ip) {
		return
	}

	a.mu.Lock()
	if _, alreadyBlocked := a.blockedIPs[ipStr]; alreadyBlocked {
		a.mu.Unlock()
		return
	}
	a.mu.Unlock()

	if err := a.mgr.BlockIP(ip); err != nil {
		// 不记账：下一轮扫描会重试，而不是把这个 IP 静默放行整个封禁周期。
		log.Printf("[XDP] Failed to block IP %s (reason: %s): %v", ipStr, reason, err)
		return
	}

	// 按累犯次数取本次时长：首次 5 分钟，反复被封则逐级拉长到 24 小时封顶。
	// 记账放在 BlockIP 成功之后，与 blockedIPs 一致 —— 失败的尝试不该推高档位，
	// 否则一个因为 map 满而反复失败的 IP 会在几轮扫描里被推到最高档。
	now := time.Now()
	a.mu.Lock()
	dur := a.banDurationFor(ipStr, now)
	a.blockedIPs[ipStr] = now.Add(dur)
	count := a.offenderCount(ipStr)
	a.dirty = true
	a.mu.Unlock()

	// 日志里带上档位和次数：排查「为什么这个 IP 被关了 12 小时」时，这是唯一能
	// 直接回答的地方 —— 面板只看到剩余时间，看不出它是第几次累犯。
	log.Printf("[XDP] Auto-blocked IP %s (reason: %s, offense #%d, duration %v)",
		ipStr, reason, count, dur)

	// 触发广播 hook：把封禁同步到 WAF 封禁表并广播到其他节点
	a.mu.RLock()
	hook := a.broadcastHook
	a.mu.RUnlock()
	if hook != nil {
		hook(ipStr, dur)
	}
}

// cleanupExpired 清理过期的封禁记录，并同步从 eBPF blocklist 摘除。
func (a *AutoBlocker) cleanupExpired() {
	now := time.Now()
	a.mu.Lock()
	var removed []string
	for ip, expiresAt := range a.blockedIPs {
		if now.After(expiresAt) {
			delete(a.blockedIPs, ip)
			removed = append(removed, ip)
		}
	}
	if len(removed) > 0 {
		a.dirty = true
	}
	a.mu.Unlock()

	if len(removed) == 0 || a.mgr == nil {
		return
	}
	// 解封的 UnblockIP 放在锁外：它是 syscall，持锁期间调用会阻塞
	// blockIfNeeded 和 GetBlockedIPs（面板拉取封禁列表的路径）。
	a.mu.RLock()
	external := a.externalBanned
	a.mu.RUnlock()
	for _, ipStr := range removed {
		// L7 还有更长的封禁（主控下发、WAF 判定）时不摘：那条封禁的到期由 WAF 的
		// expire hook 负责摘除。
		if external != nil && external(ipStr) {
			continue
		}
		if ip := net.ParseIP(ipStr); ip != nil {
			_ = a.mgr.UnblockIP(ip)
		}
	}
}

// IsBlocked 返回 AutoBlocker 自己是否仍在封禁该 IP（未到期）。
func (a *AutoBlocker) IsBlocked(ip string) bool {
	a.mu.RLock()
	exp, ok := a.blockedIPs[ip]
	a.mu.RUnlock()
	return ok && time.Now().Before(exp)
}

// SetExternalBanCheck 注入「L7 是否仍封禁该 IP」的判定，AutoBlocker 到期时据此决定
// 是否从 XDP 摘除（见 cleanupExpired）。
func (a *AutoBlocker) SetExternalBanCheck(fn func(ip string) bool) {
	a.mu.Lock()
	a.externalBanned = fn
	a.mu.Unlock()
}

// persistIfDirty 仅在有变更时落盘，避免空闲节点每轮都重写文件。
func (a *AutoBlocker) persistIfDirty() {
	a.mu.Lock()
	dirty := a.dirty
	a.dirty = false
	a.mu.Unlock()
	if dirty {
		a.persistState()
	}
}

// BlockedIPEntry 表示一个被封禁的 IP 及其剩余时间
type BlockedIPEntry struct {
	IP            string  `json:"ip"`
	RemainingTime float64 `json:"remaining_time"` // 剩余秒数
	// OffenseCount 是该 IP 的累犯次数（第几次被封），0 表示无记账
	// （主控下发或 WAF 沉下来的封禁，不经过 AutoBlocker 的阶梯）。
	//
	// 必须暴露给面板：只看剩余时间无法回答「为什么这个 IP 被关了 12 小时而另一个
	// 只有 5 分钟」，而这正是运维看到长时封禁时的第一个问题。日志里有，但面板上
	// 看不到就等于要登机器 grep。
	OffenseCount int `json:"offense_count"`
	// BanDuration 是本次封禁的**总时长**秒数（不是剩余）。与 OffenseCount 一起
	// 才能看出当前处在阶梯的哪一档：剩余 3 小时既可能是 12 小时档过了 9 小时，
	// 也可能是 24 小时档刚开始不久。
	BanDuration float64 `json:"ban_duration"`
	// 归属地信息（由主控填充）
	Country  string `json:"country,omitempty"`  // ISO 国家码
	Location string `json:"location,omitempty"` // 可读归属地
	// 封禁时间（由主控填充）
	BlockedAt int64 `json:"blocked_at,omitempty"` // Unix 时间戳
}

// GetBlockedIPs 返回当前所有被封禁的 IP 及其剩余封禁时间。
//
// 不只返回 AutoBlocker 自己判定的封禁：eBPF blocklist 里还有主控下发的封禁和
// WAF/CC 通过 l4BlockHook 沉下来的封禁，它们不经过 blockedIPs。只报自己那部分会让
// 面板上的「XDP 网卡层防护」漏掉大半实际生效的封禁，看起来像没同步过来。
func (a *AutoBlocker) GetBlockedIPs() []BlockedIPEntry {
	now := time.Now()
	a.mu.Lock()
	entries := make([]BlockedIPEntry, 0, len(a.blockedIPs))
	seen := make(map[string]bool, len(a.blockedIPs))
	for ip, expiresAt := range a.blockedIPs {
		if remaining := expiresAt.Sub(now); remaining > 0 {
			seen[ip] = true
			count := a.offenderCount(ip)
			// 总时长由「累犯次数 + 当前阶梯」反推，而不是另存一份。少一张需要
			// 落盘和清理的表，重启后也照样准确。代价：如果在封禁生效期间改了阶梯
			// 配置，这里显示的总时长会是新阶梯的值，而实际过期时刻仍按封禁时算
			// （blockedIPs 存的是绝对时刻）。运维改配置时看到一次偏差可以接受，
			// 换成多存一张表则是长期的一致性负担。
			var total float64
			if count > 0 {
				total = ladderDuration(a.ladder, count, a.duration).Seconds()
			}
			entries = append(entries, BlockedIPEntry{
				IP:            ip,
				RemainingTime: remaining.Seconds(),
				OffenseCount:  count,
				BanDuration:   total,
			})
		}
	}
	a.mu.Unlock()

	// 补上 map 里存在但不在 blockedIPs 里的条目。这些封禁的到期由下发方管理
	// （主控存档 / WAF ipBlockList），AutoBlocker 无从得知剩余时长，故留 0
	// 表示「时长未知」而不是「已过期」。
	if ips, err := a.listBlockedFromMap(); err == nil {
		for _, ip := range ips {
			s := ip.String()
			if !seen[s] {
				entries = append(entries, BlockedIPEntry{IP: s, RemainingTime: 0})
			}
		}
	}
	return entries
}

// Forget 把一个 IP 从自动封禁记账中移除，用于外部（主控/面板）主动解封。
//
// 必须调用，否则解封只清掉 eBPF map 而记账仍在：
//   - blockIfNeeded 的 alreadyBlocked 短路会认为它还在封禁中，本轮之后即使它继续
//     超速也不再重新封禁；
//   - 这条记账会被 persistState 写进存档，节点下次启动时 restoreState 又把它塞回
//     blocklist —— 用户会看到「解封后重启又被封」。
//
// 累犯记账也要一起清掉：手动解封是运维在明确声明「这个 IP 不该被封」，通常正是
// 误封 NAT 出口的场景。只清封禁不清记账的话，它下次撞线就直接进第 N+1 档 ——
// 运维刚解封的 IP 几分钟后被关 12 小时，而且面板上看不出原因（档位是从存档里
// 带过来的）。攻击者靠这个能省下的只有一档，代价远小于误封无法真正恢复。
func (a *AutoBlocker) Forget(ip string) {
	a.mu.Lock()
	_, existed := a.blockedIPs[ip]
	if existed {
		delete(a.blockedIPs, ip)
		a.dirty = true
	}
	if _, hadRecord := a.offenders[ip]; hadRecord {
		delete(a.offenders, ip)
		a.dirty = true
		existed = true // 只有记账没有封禁时（封禁已到期）也要落盘，否则重启后档位复活
	}
	a.mu.Unlock()
	if existed {
		// 立即落盘：解封是用户的显式操作，不能在下一轮扫描前被重启吞掉。
		a.persistState()
	}
}

// listBlockedFromMap 读 eBPF blocklist，mgr 为 nil（单测）时返回空而不是 panic。
func (a *AutoBlocker) listBlockedFromMap() ([]net.IP, error) {
	if a.mgr == nil {
		return nil, nil
	}
	return a.mgr.ListBlocked()
}

// Stats 扩展统计（包含新增字段）
type ExtendedStats struct {
	Passed           uint64 `json:"passed"`
	DroppedBlocklist uint64 `json:"dropped_blocklist"`
	DroppedSynFlood  uint64 `json:"dropped_syn_flood"`
	DroppedPPS       uint64 `json:"dropped_pps"`
	DroppedConnLimit uint64 `json:"dropped_conn_limit"`
	DroppedUDPFlood  uint64 `json:"dropped_udp_flood"`
}

// GetExtendedStats 获取扩展统计
func (m *Manager) GetExtendedStats() (*ExtendedStats, error) {
	if m.objs == nil {
		return nil, nil
	}
	var key uint32 = 0
	// 长度必须等于 map 的 value_size（C 侧 struct stats 的完整大小），否则 Lookup 因
	// value size 不匹配失败。按 map 实际大小分配，兼容新旧 .o。ExtendedStats 只取前 6 项。
	raw := make([]byte, m.objs.XdpStats.ValueSize())
	if len(raw) < 48 {
		return nil, fmt.Errorf("xdp_stats value size %d too small", len(raw))
	}
	if err := m.objs.XdpStats.Lookup(key, &raw); err != nil {
		return nil, err
	}
	return &ExtendedStats{
		Passed:           binary.LittleEndian.Uint64(raw[0:8]),
		DroppedBlocklist: binary.LittleEndian.Uint64(raw[8:16]),
		DroppedSynFlood:  binary.LittleEndian.Uint64(raw[16:24]),
		DroppedPPS:       binary.LittleEndian.Uint64(raw[24:32]),
		DroppedConnLimit: binary.LittleEndian.Uint64(raw[32:40]),
		DroppedUDPFlood:  binary.LittleEndian.Uint64(raw[40:48]),
	}, nil
}
