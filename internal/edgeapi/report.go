package edgeapi

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	"cdn/internal/stats"
	"cdn/internal/version"
	"cdn/internal/xdp"
)

// 上报给主控的数据由边缘节点在进程内直接生成（不再由主控回连 /edge/* 拉取）。
// 解析 access log 与遍历缓存目录较重，结果缓存 slowRefresh 后再刷新；其余字段每次现取。
const slowRefresh = 60 * time.Second

type slowReport struct {
	mu       sync.Mutex
	at       time.Time
	overview *stats.Overview
	domains  []*stats.DomainStats
	cache    map[string]any
}

// BuildStatus 生成心跳用的节点状态，与 GET /edge/status 返回的内容一致。
func (h *Handler) BuildStatus() map[string]any {
	xst := h.xdpMgr.Status()
	result := map[string]any{
		"tengine": h.controller.Status(),
		"domains": len(h.store.List()),
		// version：我是哪一次构建产出来的。主控 apiv2.mapEdgeStatus 早就在读这个键，
		// 只是边缘一直没发，所以节点列表的版本列永远是空的。带上它之后，面板能拿它和
		// 自己同目录那个 cdnedge 里嵌的构建标识比，判出「一致 / 落后 / 未知」——
		// 这是「重装最新版」唯一的验收依据，光看进程在不在线看不出跑的是旧版。
		"version": version.Build,
	}
	for k, v := range xdpStatusFields(xst) {
		result[k] = v
	}
	if xst.Attached {
		if s, err := h.xdpMgr.GetStats(); err == nil {
			result["xdp_stats"] = s
		}
	}
	if sysStats, err := CollectStats(""); err == nil {
		result["system"] = sysStats
	}
	return result
}

// xdpStatusFields 把 XDP 的生效状态摊平成心跳键。键名是跨版本契约：主控
// apiv2.mapEdgeStatus 按这些名字读，写错一个键不会报错，只会让面板上的 L4 状态永远
// 停在「未确认」——所以单独提成一个可测的函数。
//
// "xdp" 保留为「程序是否挂在网卡上」的老语义，老主控只读这个键；armed 才是
// 「阈值真的写进内核并在生效」。
func xdpStatusFields(xs xdp.Status) map[string]any {
	result := map[string]any{
		"xdp":              xs.Attached,
		"xdp_armed":        xs.Armed,
		"xdp_enabled":      xs.Enabled,
		"xdp_cpu_syn":      xs.CPUSYNLimit,
		"xdp_rx_queues":    xs.RXQueues,
		"xdp_config_error": xs.ConfigError,
	}
	if xs.Attached {
		// 挂载模式与网卡：generic/SKB 模式下每个包都先分配 skb 再丢，洪水下 CPU 会先于
		// 带宽打满；网卡选错则 XDP 根本看不到攻击流量。两者都得让面板看得见。
		result["xdp_mode"] = xs.Mode
		result["xdp_iface"] = xs.Iface
	}
	return result
}

// BuildReport 生成完整的统计上报。键名与主控 apiv2 的 report* 常量一一对应。
func (h *Handler) BuildReport() map[string]any {
	ov, ds, cache := h.slowParts()
	r := map[string]any{
		"status":        h.BuildStatus(),
		"overview":      ov,
		"domain_stats":  ds,
		"cache":         cache,
		"xdp_stats":     h.xdpStatsData(),
		"xdp_blocklist": h.xdpBlocklistData(),
		"waf_bans":      h.wafBansData(),
		// 托管规则的实际执行档：面板要回答"我下发的策略在这台节点上算什么"，
		// 只能靠这个键 —— 主控不回连边缘取数。
		"waf_stats": h.wafReportData(),
		// 区域规则同理，而且它带的还是"这台节点现在装的是哪张表"的指纹：
		// 主控拿它决定要不要重发表，也拿它回答"面板显示的和网卡上跑的是不是同一张"。
		"geo_stats": h.geoStatsData(),
	}
	if h.ccDefense != nil {
		r["cc_stats"] = h.ccDefense.GetStats()
		r["cc_ips"] = map[string]any{"ips": h.ccDefense.GetTrackedIPs()}
	}
	return r
}

func (h *Handler) slowParts() (*stats.Overview, []*stats.DomainStats, map[string]any) {
	s := &h.slow
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.overview == nil || time.Since(s.at) >= slowRefresh {
		names := h.domainNames()
		c := stats.NewCollector("/var/log/tengine")
		s.overview = c.CollectOverview(names)
		s.domains = c.CollectAll(names)
		s.cache = cacheUsage()
		s.at = time.Now()
	}
	return s.overview, s.domains, s.cache
}

func (h *Handler) domainNames() []string {
	domains := h.store.List()
	names := make([]string, len(domains))
	for i, d := range domains {
		names[i] = d.Domain
	}
	return names
}

func (h *Handler) xdpStatsData() any {
	if !h.xdpMgr.Loaded() {
		return map[string]uint64{}
	}
	s, err := h.xdpMgr.GetStats()
	if err != nil {
		return map[string]uint64{}
	}
	return s
}

// xdpBlocklistData 有 AutoBlocker 时返回带剩余时间的对象数组，否则只返回 IP 字符串数组。
func (h *Handler) xdpBlocklistData() any {
	if ab := h.blocker(); ab != nil {
		return ab.GetBlockedIPs()
	}
	if !h.xdpMgr.Loaded() {
		return []string{}
	}
	ips, err := h.xdpMgr.ListBlocked()
	if err != nil {
		return []string{}
	}
	strs := make([]string, len(ips))
	for i, ip := range ips {
		strs[i] = ip.String()
	}
	return strs
}

func (h *Handler) wafBansData() map[string]any {
	if h.wafEngine == nil {
		return map[string]any{"ips": []string{}, "bans": map[string]int64{}, "now": time.Now().Unix()}
	}
	snap := h.wafEngine.SnapshotBans()
	ips := make([]string, 0, len(snap))
	bans := make(map[string]int64, len(snap))
	for ip, exp := range snap {
		ips = append(ips, ip)
		bans[ip] = exp.Unix()
	}
	return map[string]any{"ips": ips, "bans": bans, "now": time.Now().Unix(), "capacity": h.wafEngine.BanCapacity()}
}

// cacheUsage 扫描边缘磁盘缓存目录，返回已用字节数与文件数。
func cacheUsage() map[string]any {
	const cacheDir = "/var/cache/tengine/edge"
	var files, size int64
	_ = filepath.Walk(cacheDir, func(_ string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if !info.IsDir() {
			files++
			size += info.Size()
		}
		return nil
	})
	return map[string]any{"bytes": size, "files": files}
}
