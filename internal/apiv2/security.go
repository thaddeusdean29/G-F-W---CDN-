package apiv2

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"cdn/internal/config"
	"cdn/internal/geo"
	"cdn/internal/geoip"
	"cdn/internal/master"
	"cdn/internal/stats"
	"cdn/internal/waf"
	"cdn/internal/xdp"
)

// securityHandler 实现 /api/v2/security/* ：流量统计、XDP / CC / WAF 防御配置与封禁列表、
// 攻击列表、缓存统计。所有数据只来自「本代理自己装的节点」（nodes.tenant_id），域名维度的数据
// 再按本代理自己的域名过滤——节点换过主人时边缘上可能残留旧域名，不能因此泄露给新代理。
// 配置按代理各存一份（tenant_settings），修改后只下发到本代理的节点。
type securityHandler struct {
	db         *sql.DB
	nodeRepo   *NodeRepo
	domainRepo *DomainRepo
	pusher     *master.Pusher
	// geo 只给流量页的来源 IP 查归属地；为 nil 或两个库都没就位时，响应里 geo.ready=false。
	geo *geoip.Locator
	// country 是国家级地理库，区域封禁的前缀表由它编译。它是 nil 或 Ready()=false 时，
	// 区域规则在保存那一层就被拒绝——那种状态下节点查什么都算"未知"，
	// 面板上"已封禁"会变成一句假话。
	country *geo.DB
}

const (
	settingCCConfig   = "cc_config"
	settingXDPConfig  = "xdp_config"
	settingXDPBanConf = "xdp_ban_config"
)

// ── 通用：本代理节点 / 域名、并发扇出、tenant_settings ─────────────────────────

// tenantEdgeNodes 取出该代理全部启用的节点（已解密 token，可直接交给 Pusher）。
func tenantEdgeNodes(ctx context.Context, repo *NodeRepo, tenantID string) ([]*config.Node, error) {
	var out []*config.Node
	page := 1
	for {
		rows, total, err := repo.List(ctx, tenantID, "", nil, "added_at ASC", page, maxPageSize)
		if err != nil {
			return nil, err
		}
		for _, n := range rows {
			if !n.Enabled {
				continue
			}
			cn, err := toConfigNode(n)
			if err != nil {
				log.Printf("[apiv2] decrypt token of node %s: %v", n.ID, err)
				continue
			}
			out = append(out, cn)
		}
		if len(rows) == 0 || page*maxPageSize >= total {
			break
		}
		page++
	}
	return out, nil
}

// fanoutNodes 并发对每个节点执行 fn，返回 节点名 → "ok" / 错误信息。
func fanoutNodes(nodes []*config.Node, fn func(n *config.Node) error) map[string]string {
	res := make(map[string]string, len(nodes))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		go func(n *config.Node) {
			defer wg.Done()
			msg := "ok"
			if err := fn(n); err != nil {
				msg = err.Error()
			}
			mu.Lock()
			res[nodeLabel(n)] = msg
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	return res
}

func nodeLabel(n *config.Node) string {
	if n.Name != "" {
		return n.Name
	}
	if n.IP != "" {
		return n.IP
	}
	return n.ID
}

// nodeResult 是一次按节点拉取的结果；Err 非空时 Data 无意义。
type nodeResult[T any] struct {
	Node *config.Node
	Data T
	Err  error
}

type nodeError struct {
	Node  string `json:"node"`
	Error string `json:"error"`
}

func collectErrors[T any](rs []nodeResult[T]) []nodeError {
	errs := []nodeError{}
	for _, r := range rs {
		if r.Err != nil {
			errs = append(errs, nodeError{Node: nodeLabel(r.Node), Error: r.Err.Error()})
		}
	}
	return errs
}

// tenantDomainSet 返回该代理全部域名（小写），用于过滤节点上报的域名维度数据。
func tenantDomainSet(ctx context.Context, repo *DomainRepo, tenantID string) (map[string]bool, error) {
	set := map[string]bool{}
	page := 1
	for {
		rows, total, err := repo.List(ctx, tenantID, "", "", nil, "", "created_at ASC", page, maxPageSize)
		if err != nil {
			return nil, err
		}
		for _, d := range rows {
			set[strings.ToLower(d.Domain)] = true
		}
		if len(rows) == 0 || page*maxPageSize >= total {
			break
		}
		page++
	}
	return set, nil
}

// normHost 去掉端口并转小写（CC 记录的 block_host 可能带 :443）。
func normHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if host, _, err := net.SplitHostPort(h); err == nil {
		return host
	}
	return h
}

func loadTenantSetting(ctx context.Context, db *sql.DB, tenantID, name string, out any) (bool, error) {
	var raw []byte
	err := db.QueryRowContext(ctx, `SELECT value FROM tenant_settings WHERE tenant_id = ? AND name = ?`, tenantID, name).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal(raw, out)
}

func saveTenantSetting(ctx context.Context, db *sql.DB, tenantID, name string, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO tenant_settings (tenant_id, name, value) VALUES (?, ?, ?)
		ON DUPLICATE KEY UPDATE value = VALUES(value)`, tenantID, name, raw)
	return err
}

// ── 配置模型 ────────────────────────────────────────────────────────────────

// ccSetting 是代理保存的 CC 阈值。block_duration 用秒（面板友好），下发边缘时换成纳秒。
type ccSetting struct {
	Enabled           bool     `json:"enabled"`
	RequestsPerSecond int      `json:"requests_per_second"`
	RequestsPerMinute int      `json:"requests_per_minute"`
	BurstSize         int      `json:"burst_size"`
	BlockDuration     int      `json:"block_duration"`
	WhitelistIPs      []string `json:"whitelist_ips"`
	PathWhitelist     []string `json:"path_whitelist"`
}

func defaultCCSetting() ccSetting {
	return ccSetting{Enabled: true, RequestsPerSecond: 20, RequestsPerMinute: 300, BurstSize: 5,
		BlockDuration: 600, WhitelistIPs: []string{}, PathWhitelist: []string{"/health", "/ping"}}
}

func (c ccSetting) edgePayload() map[string]any {
	wl := c.WhitelistIPs
	if wl == nil {
		wl = []string{}
	}
	pw := c.PathWhitelist
	if pw == nil {
		pw = []string{}
	}
	return map[string]any{
		"enabled":             c.Enabled,
		"requests_per_second": c.RequestsPerSecond,
		"requests_per_minute": c.RequestsPerMinute,
		"burst_size":          c.BurstSize,
		"block_duration":      int64(time.Duration(c.BlockDuration) * time.Second),
		"whitelist_ips":       wl,
		"path_whitelist":      pw,
	}
}

func (c ccSetting) validate() error {
	fields := map[string]string{}
	if c.RequestsPerSecond <= 0 {
		fields["requests_per_second"] = "必须大于 0"
	}
	if c.RequestsPerMinute <= 0 {
		fields["requests_per_minute"] = "必须大于 0"
	}
	if c.BurstSize < 0 {
		fields["burst_size"] = "不能为负数"
	}
	if c.BlockDuration <= 0 {
		fields["block_duration"] = "必须大于 0（秒）"
	}
	for _, ip := range c.WhitelistIPs {
		if net.ParseIP(ip) == nil {
			if _, _, err := net.ParseCIDR(ip); err != nil {
				fields["whitelist_ips"] = "包含非法 IP/CIDR: " + ip
				break
			}
		}
	}
	for _, p := range c.PathWhitelist {
		if !strings.HasPrefix(p, "/") {
			fields["path_whitelist"] = "路径必须以 / 开头: " + p
			break
		}
	}
	if len(fields) > 0 {
		return NewApiError("validation_failed", "CC 配置不合法").WithDetails(map[string]any{"fields": fields})
	}
	return nil
}

func defaultXDPConfig() xdp.XDPConfig {
	return xdp.XDPConfig{
		SYNLimit: xdp.DefaultSYNLimit, PPSLimit: xdp.DefaultPPSLimit, UDPLimit: xdp.DefaultUDPLimit,
		ConnLimit: xdp.DefaultConnLimit, Enabled: 1, ICMPLimit: xdp.DefaultICMPLimit, TCPRstLimit: xdp.DefaultTCPRstLimit,
		FragmentDrop: 1, InvalidFlagsDrop: 1, AckLimit: xdp.DefaultAckLimit, BogonDrop: 1, FinLimit: xdp.DefaultFinLimit,
		OrphanTCPDrop: 1, ServiceOrphanDrop: 1,
	}
}

type banSetting struct {
	Ladder      string `json:"ladder"`
	OffenderTTL string `json:"offender_ttl"`
}

func defaultBanSetting() banSetting {
	return banSetting{Ladder: xdp.FormatBanLadder(xdp.DefaultBanLadder), OffenderTTL: xdp.DefaultOffenderTTL.String()}
}

func (b banSetting) validate() error {
	ladder, err := xdp.ParseBanLadder(b.Ladder)
	if err != nil {
		return NewApiError("validation_failed", "封禁阶梯格式不正确: "+err.Error())
	}
	ttl, err := time.ParseDuration(b.OffenderTTL)
	if err != nil || ttl <= 0 {
		return NewApiError("validation_failed", "offender_ttl 必须是正的时长，如 48h")
	}
	if err := xdp.ValidateBanConfig(ladder, ttl); err != nil {
		return NewApiError("validation_failed", err.Error())
	}
	return nil
}

// pushTenantDefense 把代理保存过的 CC / XDP / 封禁阶梯 / WAF 策略推给一个节点（新节点接入时补发）。
// 从未保存过的项返回 skipped，不推默认值——边缘自带同样的默认值，推了反而可能覆盖边缘的端口探测结果。
func pushTenantDefense(ctx context.Context, db *sql.DB, p *master.Pusher, country *geo.DB, tenantID string, n *config.Node, res map[string]string) {
	var cc ccSetting
	if ok, err := loadTenantSetting(ctx, db, tenantID, settingCCConfig, &cc); err != nil {
		res["cc"] = err.Error()
	} else if !ok {
		res["cc"] = "skipped: not configured"
	} else if err := p.PostToNode(n, "/edge/cc/config", cc.edgePayload()); err != nil {
		res["cc"] = err.Error()
	} else {
		res["cc"] = "ok"
	}

	var xc xdp.XDPConfig
	if ok, err := loadTenantSetting(ctx, db, tenantID, settingXDPConfig, &xc); err != nil {
		res["xdp"] = err.Error()
	} else if !ok {
		res["xdp"] = "skipped: not configured"
	} else if err := p.PostToNode(n, "/edge/xdp/config", xc); err != nil {
		res["xdp"] = err.Error()
	} else {
		res["xdp"] = "ok"
	}

	var bc banSetting
	if ok, err := loadTenantSetting(ctx, db, tenantID, settingXDPBanConf, &bc); err != nil {
		res["xdp_ban"] = err.Error()
	} else if !ok {
		res["xdp_ban"] = "skipped: not configured"
	} else if err := p.PostToNode(n, "/edge/xdp/ban-config", bc); err != nil {
		res["xdp_ban"] = err.Error()
	} else {
		res["xdp_ban"] = "ok"
	}

	// 托管规则的策略与规则包：策略按代理走（tenant_settings），包是平台级的。
	// 新装节点出厂就是主控这一份的前提是"主控与边缘同一次构建"，管理员换过包之后
	// 这个前提就没了，所以两项都要补发一次。
	pushWAFPolicy(ctx, db, p, tenantID, n, res)
	wafPackageForTenant(ctx, db, p, n, res)
	// 区域规则与前两层不同：策略分平台（范围、四层）与域名两份，但前缀表是节点上共用的那一张。
	// 新节点出厂带的表是编译进二进制的那一份，管理员后来选的国家全都不在里面——
	// 不补发，域名的区域规则就会把所有访客查成"未知"。
	geoForTenant(ctx, db, p, country, n, res)
}

// ── 路由 ────────────────────────────────────────────────────────────────────

func (h *securityHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tenantID := SessionFromContext(r.Context()).TenantID
	sub := strings.TrimPrefix(r.URL.Path, "/api/v2/security/")
	key := r.Method + " " + sub
	switch key {
	case "GET traffic":
		h.traffic(w, r, tenantID)
	case "GET attacks":
		h.attacks(w, r, tenantID)
	case "GET cache/stats":
		h.cacheStats(w, r, tenantID)
	case "GET cache/config":
		h.getCacheConfig(w, r, tenantID)
	case "PUT cache/config":
		h.putCacheConfig(w, r, tenantID)
	case "GET cc/stats":
		h.ccStats(w, r, tenantID)
	case "GET cc/ips":
		h.ccIPs(w, r, tenantID)
	case "GET cc/config":
		h.getCC(w, r, tenantID)
	case "PUT cc/config":
		h.putCC(w, r, tenantID)
	case "GET xdp/stats":
		h.xdpStats(w, r, tenantID)
	case "GET xdp/blocklist":
		h.xdpBlocklist(w, r, tenantID)
	case "GET xdp/config":
		h.getXDP(w, r, tenantID)
	case "PUT xdp/config":
		h.putXDP(w, r, tenantID)
	case "GET xdp/ban-config":
		h.getBan(w, r, tenantID)
	case "PUT xdp/ban-config":
		h.putBan(w, r, tenantID)
	case "GET waf/banned":
		h.wafBanned(w, r, tenantID)
	case "GET waf/config":
		h.getWAFConfig(w, r, tenantID)
	case "PUT waf/config":
		h.putWAFConfig(w, r, tenantID)
	case "GET waf/stats":
		h.wafStats(w, r, tenantID)
	case "GET geo/options":
		h.geoOptions(w, r, tenantID)
	case "GET geo/stats":
		h.geoStats(w, r, tenantID)
	case "POST block":
		h.block(w, r, tenantID)
	case "POST unblock":
		h.unblock(w, r, tenantID)
	case "POST push":
		h.pushAll(w, r, tenantID)
	default:
		WriteError(w, NewApiError("not_found", "未找到该资源"))
	}
}

func (h *securityHandler) nodes(w http.ResponseWriter, r *http.Request, tenantID string) ([]*config.Node, bool) {
	nodes, err := tenantEdgeNodes(r.Context(), h.nodeRepo, tenantID)
	if err != nil {
		WriteError(w, err)
		return nil, false
	}
	return nodes, true
}

// ── 流量统计 ────────────────────────────────────────────────────────────────

type trafficNode struct {
	Node          string `json:"node"`
	IP            string `json:"ip"`
	TotalRequests uint64 `json:"total_requests"`
	TotalBytes    uint64 `json:"total_bytes"`
	TotalBlocked  uint64 `json:"total_blocked"`
	Error         string `json:"error,omitempty"`
}

func (h *securityHandler) traffic(w http.ResponseWriter, r *http.Request, tenantID string) {
	nodes, ok := h.nodes(w, r, tenantID)
	if !ok {
		return
	}
	domSet, err := tenantDomainSet(r.Context(), h.domainRepo, tenantID)
	if err != nil {
		WriteError(w, err)
		return
	}
	// ?domain= 只影响热门来源 IP 这一块：小时曲线、总量、按域名今日表仍是本代理的全量，
	// 免得前端切了筛选之后，上面的数字悄悄换了口径。别人的域名一律 404，不区分"不存在"
	// 和"不归你"——代理之间连域名清单都不该互相探到。
	wantDomain := ""
	if q := strings.TrimSpace(r.URL.Query().Get("domain")); q != "" {
		wantDomain = normHost(q)
		if !domSet[wantDomain] {
			WriteError(w, NewApiError("not_found", "没有这个域名"))
			return
		}
	}

	// 数据来自边缘节点主动上报（edge_report.go），主控不回连节点。
	ovs := reportField[stats.Overview](nodes, reportOverview)
	dss := reportField[[]*stats.DomainStats](nodes, reportDomainStats)

	hourly := make([]stats.HourBucket, 24)
	for i := range hourly {
		hourly[i].Hour = i
	}
	topDomains := map[string]*stats.TopItem{}
	topIPs := map[string]*stats.TopItem{}
	perNode := make([]trafficNode, 0, len(nodes))
	var totReq, totBytes, totBlocked uint64
	uniqueIPs := 0
	for _, o := range ovs {
		tn := trafficNode{Node: nodeLabel(o.Node), IP: o.Node.IP}
		if o.Err != nil {
			tn.Error = o.Err.Error()
			perNode = append(perNode, tn)
			continue
		}
		// 节点上可能残留不属于本代理的域名，总量只累加本代理域名的部分（Top 域名是边缘按域名汇总的）。
		for _, it := range o.Data.TopDomains {
			if it == nil || !domSet[normHost(it.Key)] {
				continue
			}
			k := normHost(it.Key)
			if topDomains[k] == nil {
				topDomains[k] = &stats.TopItem{Key: k}
			}
			topDomains[k].Requests += it.Requests
			topDomains[k].Bytes += it.Bytes
			tn.TotalRequests += it.Requests
			tn.TotalBytes += it.Bytes
		}
		tn.TotalBlocked = o.Data.TotalBlocked
		// 热门来源 IP 只从逐域名明细里合并，并且必须先过 domSet。原来这里直接累加
		// o.Data.TopIPs（节点的全站排行，条目里不带域名），同一节点上别人家域名的来源 IP
		// 会整列出现在本代理的统计里——那是跨代理泄露，不是统计误差。
		for _, di := range o.Data.DomainIPs {
			if di == nil {
				continue
			}
			dn := normHost(di.Domain)
			if !domSet[dn] || (wantDomain != "" && dn != wantDomain) {
				continue
			}
			for _, it := range di.Items {
				if it == nil {
					continue
				}
				if topIPs[it.Key] == nil {
					topIPs[it.Key] = &stats.TopItem{Key: it.Key}
				}
				topIPs[it.Key].Requests += it.Requests
				topIPs[it.Key].Bytes += it.Bytes
			}
		}
		for _, b := range o.Data.Hourly {
			if b != nil && b.Hour >= 0 && b.Hour < 24 {
				hourly[b.Hour].Requests += b.Requests
				hourly[b.Hour].Bytes += b.Bytes
				hourly[b.Hour].Blocked += b.Blocked
			}
		}
		uniqueIPs += o.Data.UniqueIPs
		totReq += tn.TotalRequests
		totBytes += tn.TotalBytes
		totBlocked += tn.TotalBlocked
		perNode = append(perNode, tn)
	}

	domains := map[string]*stats.DomainStats{}
	for d := range domSet {
		domains[d] = &stats.DomainStats{Domain: d}
	}
	for _, d := range dss {
		if d.Err != nil {
			continue
		}
		for _, s := range d.Data {
			if s == nil {
				continue
			}
			agg := domains[normHost(s.Domain)]
			if agg == nil {
				continue
			}
			agg.TodayBytes += s.TodayBytes
			agg.Requests += s.Requests
			agg.Blocked += s.Blocked
			agg.UniqueIPs += s.UniqueIPs
		}
	}
	domainList := make([]*stats.DomainStats, 0, len(domains))
	for _, d := range domains {
		d.TodayMB = float64(d.TodayBytes) / 1024 / 1024
		domainList = append(domainList, d)
	}
	sort.Slice(domainList, func(i, j int) bool {
		if domainList[i].Requests != domainList[j].Requests {
			return domainList[i].Requests > domainList[j].Requests
		}
		return domainList[i].Domain < domainList[j].Domain
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"total_requests": totReq,
		"total_bytes":    totBytes,
		"total_blocked":  totBlocked,
		"unique_ips":     uniqueIPs,
		"hourly":         hourly,
		"top_domains":    sortTop(topDomains, 20),
		"top_ips":        trafficIPs(sortTop(topIPs, 50), h.geo),
		// 回显本次生效的域名筛选（空串=全部域名），前端下拉框靠它对上选中项。
		"domain":       wantDomain,
		"domains":      domainList,
		"nodes":        perNode,
		"errors":       collectErrors(ovs),
		"geo":          geoStatus(h.geo),
		"collected_at": time.Now().UTC().Format(rfc3339Milli),
	})
}

// trafficIPRow 是热门来源 IP 的一行。TopItem 的 Key 在这里明确叫 ip，因为它只装 IP。
type trafficIPRow struct {
	IP       string `json:"ip"`
	Requests uint64 `json:"requests"`
	Bytes    uint64 `json:"bytes"`
	Country  string `json:"country,omitempty"`
	Region   string `json:"region,omitempty"`
	City     string `json:"city,omitempty"`
}

// trafficIPs 给已截断的排行逐条查归属地。查不到就三列都空——私网、保留段或库没覆盖，
// 这是数据本身的样子；"库根本没装"是另一回事，由 geoStatus 单独告诉页面。
// 参数叫 locator 而不是 geo：本包同时用了 internal/geo（国家级前缀表那套），
// 同名参数会把包名在这个函数作用域里遮掉。
func trafficIPs(items []*stats.TopItem, locator *geoip.Locator) []trafficIPRow {
	out := make([]trafficIPRow, 0, len(items))
	for _, it := range items {
		row := trafficIPRow{IP: it.Key, Requests: it.Requests, Bytes: it.Bytes}
		if r, ok := locator.Lookup(it.Key); ok {
			row.Country, row.Region, row.City = r.Country, r.Region, r.City
		}
		out = append(out, row)
	}
	return out
}

// geoStatus 暴露地理库状态。Missing 里带着找过的绝对路径，运维照抄就能补文件。
// DB-IP 是 CC BY 4.0，用了就必须在页面上署名回链，所以这里把状态透出去而不是静默隐藏列。
func geoStatus(locator *geoip.Locator) map[string]any {
	if locator == nil {
		return map[string]any{
			"ready":   false,
			"missing": []string{geoip.FileIPv4 + " 未加载（面板未启用地理库）", geoip.FileIPv6 + " 未加载（面板未启用地理库）"},
		}
	}
	return map[string]any{
		"ready":   locator.Ready(),
		"loaded":  locator.Loaded,
		"missing": locator.Missing,
	}
}

func sortTop(m map[string]*stats.TopItem, n int) []*stats.TopItem {
	out := make([]*stats.TopItem, 0, len(m))
	for _, v := range m {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		return out[i].Key < out[j].Key
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

// ── 缓存统计 ────────────────────────────────────────────────────────────────

func (h *securityHandler) cacheStats(w http.ResponseWriter, r *http.Request, tenantID string) {
	nodes, ok := h.nodes(w, r, tenantID)
	if !ok {
		return
	}
	type cs struct {
		Bytes int64 `json:"bytes"`
		Files int64 `json:"files"`
	}
	rs := reportField[cs](nodes, reportCache)
	var total cs
	per := []map[string]any{}
	for _, x := range rs {
		item := map[string]any{"node": nodeLabel(x.Node), "ip": x.Node.IP}
		if x.Err != nil {
			item["error"] = x.Err.Error()
		} else {
			item["bytes"], item["files"] = x.Data.Bytes, x.Data.Files
			total.Bytes += x.Data.Bytes
			total.Files += x.Data.Files
		}
		per = append(per, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"bytes": total.Bytes, "files": total.Files, "nodes": per})
}

// ── CC ─────────────────────────────────────────────────────────────────────

func (h *securityHandler) ccStats(w http.ResponseWriter, r *http.Request, tenantID string) {
	nodes, ok := h.nodes(w, r, tenantID)
	if !ok {
		return
	}
	rs := reportField[waf.CCStats](nodes, reportCCStats)
	var total waf.CCStats
	per := []map[string]any{}
	for _, x := range rs {
		item := map[string]any{"node": nodeLabel(x.Node), "ip": x.Node.IP}
		if x.Err != nil {
			item["error"] = x.Err.Error()
		} else {
			item["stats"] = x.Data
			total.TotalTracked += x.Data.TotalTracked
			total.ActiveIPs += x.Data.ActiveIPs
			total.ViolatingIPs += x.Data.ViolatingIPs
			total.BlockedIPs += x.Data.BlockedIPs
			total.DowngradedIPs += x.Data.DowngradedIPs
			total.Capacity.Add(x.Data.Capacity)
			// 开盾域名数是瞬时水位而不是流量计数：同一个域名在三个节点开盾只是"一个域名
			// 在被攻击"，相加会变成 3，所以取各节点最大值。具体哪几个域名在哪些节点开盾，
			// 看下面 nodes[].stats 里的逐节点读数。
			if x.Data.DomainsInChallenge > total.DomainsInChallenge {
				total.DomainsInChallenge = x.Data.DomainsInChallenge
			}
			if x.Data.DomainsInStrict > total.DomainsInStrict {
				total.DomainsInStrict = x.Data.DomainsInStrict
			}
		}
		per = append(per, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": total, "nodes": per})
}

type ccIPRow struct {
	waf.IPStatus
	Nodes []string `json:"nodes"`
}

// mergedCCIPs 拉取本代理全部节点的 CC 追踪 IP，按 IP 合并（取最大速率/违规数、最晚解封）。
// 带域名的记录只保留本代理的域名；无域名的（尚未触发封禁、只在计数）保留，因为节点本身属于本代理。
func (h *securityHandler) mergedCCIPs(ctx context.Context, nodes []*config.Node, domSet map[string]bool) ([]*ccIPRow, []nodeError) {
	type resp struct {
		IPs []waf.IPStatus `json:"ips"`
	}
	rs := reportField[resp](nodes, reportCCIPs)
	merged := map[string]*ccIPRow{}
	for _, x := range rs {
		if x.Err != nil {
			continue
		}
		for _, s := range x.Data.IPs {
			if s.BlockHost != "" && !domSet[normHost(s.BlockHost)] {
				continue
			}
			row := merged[s.IP]
			if row == nil {
				row = &ccIPRow{IPStatus: s}
				merged[s.IP] = row
			} else {
				if s.RequestsPerSecond > row.RequestsPerSecond {
					row.RequestsPerSecond = s.RequestsPerSecond
				}
				if s.RequestsPerMinute > row.RequestsPerMinute {
					row.RequestsPerMinute = s.RequestsPerMinute
				}
				row.Violations += s.Violations
				if s.Blocked {
					row.Blocked = true
					if s.BlockedUntil.After(row.BlockedUntil) {
						row.BlockedUntil = s.BlockedUntil
						row.BlockedAt = s.BlockedAt
						row.BlockRule, row.BlockHost, row.BlockPath = s.BlockRule, s.BlockHost, s.BlockPath
					}
				}
				if s.LastRequest.After(row.LastRequest) {
					row.LastRequest = s.LastRequest
				}
			}
			row.Nodes = append(row.Nodes, nodeLabel(x.Node))
		}
	}
	out := make([]*ccIPRow, 0, len(merged))
	for _, v := range merged {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Blocked != out[j].Blocked {
			return out[i].Blocked
		}
		if out[i].Violations != out[j].Violations {
			return out[i].Violations > out[j].Violations
		}
		return out[i].RequestsPerMinute > out[j].RequestsPerMinute
	})
	return out, collectErrors(rs)
}

func (h *securityHandler) ccIPs(w http.ResponseWriter, r *http.Request, tenantID string) {
	nodes, ok := h.nodes(w, r, tenantID)
	if !ok {
		return
	}
	domSet, err := tenantDomainSet(r.Context(), h.domainRepo, tenantID)
	if err != nil {
		WriteError(w, err)
		return
	}
	rows, errs := h.mergedCCIPs(r.Context(), nodes, domSet)
	if r.URL.Query().Get("blocked") == "true" {
		filtered := rows[:0]
		for _, x := range rows {
			if x.Blocked {
				filtered = append(filtered, x)
			}
		}
		rows = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": rows, "total": len(rows), "errors": errs})
}

func (h *securityHandler) getCC(w http.ResponseWriter, r *http.Request, tenantID string) {
	cfg := defaultCCSetting()
	saved, err := loadTenantSetting(r.Context(), h.db, tenantID, settingCCConfig, &cfg)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": cfg, "saved": saved})
}

func (h *securityHandler) putCC(w http.ResponseWriter, r *http.Request, tenantID string) {
	cfg := defaultCCSetting()
	if _, err := loadTenantSetting(r.Context(), h.db, tenantID, settingCCConfig, &cfg); err != nil {
		WriteError(w, err)
		return
	}
	raw, _, err := decodeKnownFields(r, []string{"enabled", "requests_per_second", "requests_per_minute", "burst_size", "block_duration", "whitelist_ips", "path_whitelist"})
	if err != nil {
		WriteError(w, err)
		return
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		WriteError(w, NewApiError("validation_failed", "字段类型不正确: "+err.Error()))
		return
	}
	if err := cfg.validate(); err != nil {
		WriteError(w, err)
		return
	}
	if err := saveTenantSetting(r.Context(), h.db, tenantID, settingCCConfig, cfg); err != nil {
		WriteError(w, err)
		return
	}
	nodes, ok := h.nodes(w, r, tenantID)
	if !ok {
		return
	}
	payload := cfg.edgePayload()
	res := fanoutNodes(nodes, func(n *config.Node) error { return h.pusher.PostToNode(n, "/edge/cc/config", payload) })
	writeJSON(w, http.StatusOK, map[string]any{"config": cfg, "push": res})
}

// ── XDP ────────────────────────────────────────────────────────────────────

func (h *securityHandler) xdpStats(w http.ResponseWriter, r *http.Request, tenantID string) {
	nodes, ok := h.nodes(w, r, tenantID)
	if !ok {
		return
	}
	rs := reportField[map[string]any](nodes, reportXDPStats)
	total := map[string]float64{}
	per := []map[string]any{}
	for _, x := range rs {
		item := map[string]any{"node": nodeLabel(x.Node), "ip": x.Node.IP}
		if x.Err != nil {
			item["error"] = x.Err.Error()
		} else {
			item["stats"] = x.Data
			item["loaded"] = len(x.Data) > 0
			for k, v := range x.Data {
				if f, ok := v.(float64); ok {
					total[k] += f
				}
			}
		}
		per = append(per, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"total": total, "nodes": per})
}

type xdpBlockRow struct {
	IP            string   `json:"ip"`
	RemainingTime float64  `json:"remaining_time"`
	OffenseCount  int      `json:"offense_count"`
	BanDuration   float64  `json:"ban_duration"`
	Nodes         []string `json:"nodes"`
}

func (h *securityHandler) mergedXDPBlocks(nodes []*config.Node) ([]*xdpBlockRow, []nodeError) {
	rs := reportField[json.RawMessage](nodes, reportXDPBlocklist)
	merged := map[string]*xdpBlockRow{}
	add := func(e xdpBlockRow, node string) {
		row := merged[e.IP]
		if row == nil {
			cp := e
			cp.Nodes = nil
			row = &cp
			merged[e.IP] = row
		} else {
			if e.RemainingTime > row.RemainingTime {
				row.RemainingTime = e.RemainingTime
			}
			if e.OffenseCount > row.OffenseCount {
				row.OffenseCount = e.OffenseCount
			}
			if e.BanDuration > row.BanDuration {
				row.BanDuration = e.BanDuration
			}
		}
		row.Nodes = append(row.Nodes, node)
	}
	for _, x := range rs {
		if x.Err != nil || len(x.Data) == 0 {
			continue
		}
		// 边缘有 AutoBlocker 时返回带剩余时间的对象数组，否则只返回 IP 字符串数组。
		var entries []xdpBlockRow
		if err := json.Unmarshal(x.Data, &entries); err == nil {
			for _, e := range entries {
				if e.IP != "" {
					add(e, nodeLabel(x.Node))
				}
			}
			continue
		}
		var ips []string
		if err := json.Unmarshal(x.Data, &ips); err == nil {
			for _, ip := range ips {
				add(xdpBlockRow{IP: ip}, nodeLabel(x.Node))
			}
		}
	}
	out := make([]*xdpBlockRow, 0, len(merged))
	for _, v := range merged {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RemainingTime > out[j].RemainingTime })
	return out, collectErrors(rs)
}

func (h *securityHandler) xdpBlocklist(w http.ResponseWriter, r *http.Request, tenantID string) {
	nodes, ok := h.nodes(w, r, tenantID)
	if !ok {
		return
	}
	rows, errs := h.mergedXDPBlocks(nodes)
	writeJSON(w, http.StatusOK, map[string]any{"items": rows, "total": len(rows), "errors": errs})
}

func (h *securityHandler) getXDP(w http.ResponseWriter, r *http.Request, tenantID string) {
	cfg := defaultXDPConfig()
	saved, err := loadTenantSetting(r.Context(), h.db, tenantID, settingXDPConfig, &cfg)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": cfg, "saved": saved})
}

func (h *securityHandler) putXDP(w http.ResponseWriter, r *http.Request, tenantID string) {
	cfg := defaultXDPConfig()
	if _, err := loadTenantSetting(r.Context(), h.db, tenantID, settingXDPConfig, &cfg); err != nil {
		WriteError(w, err)
		return
	}
	raw, err := readBody(r)
	if err != nil {
		WriteError(w, err)
		return
	}
	known := []string{"syn_limit", "pps_limit", "udp_limit", "conn_limit", "enabled", "icmp_limit", "udp_dns_limit",
		"tcp_rst_limit", "fragment_drop", "invalid_flags_drop", "ack_limit", "fin_limit", "port_guard", "bogon_drop",
		"psh_ack_guard", "cpu_syn_limit", "orphan_tcp_drop", "service_orphan_drop"}
	if bad := UnknownFields(raw, known); len(bad) > 0 {
		WriteError(w, unknownFieldError(bad))
		return
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		WriteError(w, NewApiError("validation_failed", "XDP 配置字段必须是非负整数"))
		return
	}
	for _, sw := range []*uint32{&cfg.Enabled, &cfg.FragmentDrop, &cfg.InvalidFlagsDrop, &cfg.PortGuard, &cfg.BogonDrop,
		&cfg.PshAckGuard, &cfg.OrphanTCPDrop, &cfg.ServiceOrphanDrop} {
		if *sw > 1 {
			*sw = 1
		}
	}
	if err := saveTenantSetting(r.Context(), h.db, tenantID, settingXDPConfig, cfg); err != nil {
		WriteError(w, err)
		return
	}
	nodes, ok := h.nodes(w, r, tenantID)
	if !ok {
		return
	}
	res := fanoutNodes(nodes, func(n *config.Node) error { return h.pusher.PostToNode(n, "/edge/xdp/config", cfg) })
	writeJSON(w, http.StatusOK, map[string]any{"config": cfg, "push": res})
}

func (h *securityHandler) getBan(w http.ResponseWriter, r *http.Request, tenantID string) {
	cfg := defaultBanSetting()
	saved, err := loadTenantSetting(r.Context(), h.db, tenantID, settingXDPBanConf, &cfg)
	if err != nil {
		WriteError(w, err)
		return
	}
	var preview []string
	if ladder, err := xdp.ParseBanLadder(cfg.Ladder); err == nil {
		preview = xdp.LadderPreview(ladder)
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": cfg, "saved": saved, "preview": preview})
}

func (h *securityHandler) putBan(w http.ResponseWriter, r *http.Request, tenantID string) {
	raw, _, err := decodeKnownFields(r, []string{"ladder", "offender_ttl"})
	if err != nil {
		WriteError(w, err)
		return
	}
	cfg := defaultBanSetting()
	if _, err := loadTenantSetting(r.Context(), h.db, tenantID, settingXDPBanConf, &cfg); err != nil {
		WriteError(w, err)
		return
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		WriteError(w, NewApiError("validation_failed", "ladder / offender_ttl 必须是字符串"))
		return
	}
	cfg.Ladder, cfg.OffenderTTL = strings.TrimSpace(cfg.Ladder), strings.TrimSpace(cfg.OffenderTTL)
	if err := cfg.validate(); err != nil {
		WriteError(w, err)
		return
	}
	if err := saveTenantSetting(r.Context(), h.db, tenantID, settingXDPBanConf, cfg); err != nil {
		WriteError(w, err)
		return
	}
	nodes, ok := h.nodes(w, r, tenantID)
	if !ok {
		return
	}
	res := fanoutNodes(nodes, func(n *config.Node) error { return h.pusher.PostToNode(n, "/edge/xdp/ban-config", cfg) })
	writeJSON(w, http.StatusOK, map[string]any{"config": cfg, "push": res})
}

// ── WAF 封禁 ────────────────────────────────────────────────────────────────

type wafBanRow struct {
	IP        string   `json:"ip"`
	ExpiresAt string   `json:"expires_at"`
	Remaining int64    `json:"remaining"`
	Nodes     []string `json:"nodes"`
}

func (h *securityHandler) mergedWAFBans(nodes []*config.Node) ([]*wafBanRow, waf.CapacityPressure, []nodeError) {
	type resp struct {
		IPs      []string             `json:"ips"`
		Bans     map[string]int64     `json:"bans"`
		Now      int64                `json:"now"`
		Capacity waf.CapacityPressure `json:"capacity"`
	}
	rs := reportField[resp](nodes, reportWAFBans)
	now := time.Now()
	merged := map[string]*wafBanRow{}
	var capacity waf.CapacityPressure
	for _, x := range rs {
		if x.Err != nil {
			continue
		}
		capacity.Add(x.Data.Capacity)
		for _, ip := range x.Data.IPs {
			var remaining int64
			if exp, ok := x.Data.Bans[ip]; ok && x.Data.Now > 0 {
				remaining = exp - x.Data.Now // 用节点自己的时钟算剩余，避免节点间时钟偏差
			}
			row := merged[ip]
			if row == nil {
				row = &wafBanRow{IP: ip}
				merged[ip] = row
			}
			if remaining > row.Remaining {
				row.Remaining = remaining
			}
			row.Nodes = append(row.Nodes, nodeLabel(x.Node))
		}
	}
	out := make([]*wafBanRow, 0, len(merged))
	for _, v := range merged {
		if v.Remaining > 0 {
			v.ExpiresAt = now.Add(time.Duration(v.Remaining) * time.Second).UTC().Format(rfc3339Milli)
		}
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Remaining > out[j].Remaining })
	return out, capacity, collectErrors(rs)
}

func (h *securityHandler) wafBanned(w http.ResponseWriter, r *http.Request, tenantID string) {
	nodes, ok := h.nodes(w, r, tenantID)
	if !ok {
		return
	}
	rows, capacity, errs := h.mergedWAFBans(nodes)
	writeJSON(w, http.StatusOK, map[string]any{"items": rows, "total": len(rows), "capacity": capacity, "errors": errs})
}

// ── 攻击列表（按域名被攻击次数降序）───────────────────────────────────────────

type attackIP struct {
	IP           string   `json:"ip"`
	Rule         string   `json:"rule"`
	Path         string   `json:"path"`
	Violations   int      `json:"violations"`
	Blocked      bool     `json:"blocked"`
	BlockedAt    string   `json:"blocked_at,omitempty"`
	BlockedUntil string   `json:"blocked_until,omitempty"`
	RPM          int      `json:"requests_per_minute"`
	Nodes        []string `json:"nodes"`
}

type attackDomain struct {
	Domain     string      `json:"domain"`
	Attacks    int         `json:"attacks"`
	BlockedIPs int         `json:"blocked_ips"`
	LastAttack string      `json:"last_attack,omitempty"`
	IPs        []*attackIP `json:"ips"`
}

func (h *securityHandler) attacks(w http.ResponseWriter, r *http.Request, tenantID string) {
	nodes, ok := h.nodes(w, r, tenantID)
	if !ok {
		return
	}
	domSet, err := tenantDomainSet(r.Context(), h.domainRepo, tenantID)
	if err != nil {
		WriteError(w, err)
		return
	}

	var cc []*ccIPRow
	var ccErrs []nodeError
	var xb []*xdpBlockRow
	var wb []*wafBanRow
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); cc, ccErrs = h.mergedCCIPs(r.Context(), nodes, domSet) }()
	go func() { defer wg.Done(); xb, _ = h.mergedXDPBlocks(nodes) }()
	go func() { defer wg.Done(); wb, _, _ = h.mergedWAFBans(nodes) }()
	wg.Wait()

	byDomain := map[string]*attackDomain{}
	var last = map[string]time.Time{}
	for _, row := range cc {
		if row.BlockHost == "" || (row.Violations == 0 && !row.Blocked) {
			continue
		}
		d := normHost(row.BlockHost)
		ad := byDomain[d]
		if ad == nil {
			ad = &attackDomain{Domain: d}
			byDomain[d] = ad
		}
		hits := row.Violations
		if hits == 0 {
			hits = 1
		}
		ad.Attacks += hits
		ai := &attackIP{IP: row.IP, Rule: row.BlockRule, Path: row.BlockPath, Violations: row.Violations,
			Blocked: row.Blocked, RPM: row.RequestsPerMinute, Nodes: row.Nodes}
		if row.Blocked {
			ad.BlockedIPs++
			if !row.BlockedAt.IsZero() {
				ai.BlockedAt = row.BlockedAt.UTC().Format(rfc3339Milli)
				if row.BlockedAt.After(last[d]) {
					last[d] = row.BlockedAt
				}
			}
			if !row.BlockedUntil.IsZero() {
				ai.BlockedUntil = row.BlockedUntil.UTC().Format(rfc3339Milli)
			}
		}
		ad.IPs = append(ad.IPs, ai)
	}
	list := make([]*attackDomain, 0, len(byDomain))
	for d, ad := range byDomain {
		if t, ok := last[d]; ok {
			ad.LastAttack = t.UTC().Format(rfc3339Milli)
		}
		sort.Slice(ad.IPs, func(i, j int) bool { return ad.IPs[i].Violations > ad.IPs[j].Violations })
		list = append(list, ad)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Attacks != list[j].Attacks {
			return list[i].Attacks > list[j].Attacks
		}
		if list[i].BlockedIPs != list[j].BlockedIPs {
			return list[i].BlockedIPs > list[j].BlockedIPs
		}
		return list[i].Domain < list[j].Domain
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"domains": list,
		"summary": map[string]int{
			"attacked_domains": len(list),
			"cc_blocked":       countBlocked(cc),
			"waf_banned":       len(wb),
			"xdp_blocked":      len(xb),
		},
		"errors": ccErrs,
	})
}

func countBlocked(rows []*ccIPRow) int {
	n := 0
	for _, r := range rows {
		if r.Blocked {
			n++
		}
	}
	return n
}

// ── 手动封禁 / 解封、重新下发 ─────────────────────────────────────────────────

type ipAction struct {
	IP      string `json:"ip"`
	Layer   string `json:"layer"`
	Minutes int    `json:"minutes"`
}

func parseIPAction(r *http.Request) (*ipAction, error) {
	raw, _, err := decodeKnownFields(r, []string{"ip", "layer", "minutes"})
	if err != nil {
		return nil, err
	}
	var a ipAction
	if err := json.Unmarshal(raw, &a); err != nil {
		return nil, NewApiError("validation_failed", "字段类型不正确")
	}
	a.IP = strings.TrimSpace(a.IP)
	if net.ParseIP(a.IP) == nil {
		return nil, NewApiError("validation_failed", "ip 不是合法的 IPv4/IPv6 地址").
			WithDetails(map[string]any{"fields": map[string]string{"ip": "格式不正确"}})
	}
	if a.Layer == "" {
		a.Layer = "all"
	}
	return &a, nil
}

func (h *securityHandler) block(w http.ResponseWriter, r *http.Request, tenantID string) {
	a, err := parseIPAction(r)
	if err != nil {
		WriteError(w, err)
		return
	}
	if a.Minutes <= 0 {
		a.Minutes = 60
	}
	if a.Minutes > 30*24*60 {
		WriteError(w, NewApiError("validation_failed", "封禁时长最长 30 天"))
		return
	}
	nodes, ok := h.nodes(w, r, tenantID)
	if !ok {
		return
	}
	// 不允许把自己的节点 IP 封掉（节点间回源/探活会断）。
	for _, n := range nodes {
		if n.IP == a.IP {
			WriteError(w, NewApiError("validation_failed", "不能封禁自己的节点 IP"))
			return
		}
	}
	var res map[string]string
	switch a.Layer {
	case "waf", "all":
		res = fanoutNodes(nodes, func(n *config.Node) error {
			return h.pusher.PostToNode(n, "/edge/waf/block", map[string]any{"ip": a.IP, "minutes": a.Minutes, "seconds": a.Minutes * 60})
		})
	case "xdp":
		res = fanoutNodes(nodes, func(n *config.Node) error {
			return h.pusher.PostToNode(n, "/edge/xdp/block", map[string]string{"ip": a.IP})
		})
	default:
		WriteError(w, NewApiError("validation_failed", "layer 必须是 waf / xdp"))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ip": a.IP, "layer": a.Layer, "push": res})
}

func (h *securityHandler) unblock(w http.ResponseWriter, r *http.Request, tenantID string) {
	a, err := parseIPAction(r)
	if err != nil {
		WriteError(w, err)
		return
	}
	var paths []string
	switch a.Layer {
	case "all":
		paths = []string{"/edge/waf/unblock", "/edge/cc/unblock", "/edge/xdp/unblock"}
	case "waf":
		paths = []string{"/edge/waf/unblock"}
	case "cc":
		// CC 封禁落在同一个 waf.Engine 上，只清 CC 计数不清引擎封禁会让 IP 仍被拦。
		paths = []string{"/edge/cc/unblock", "/edge/waf/unblock"}
	case "xdp":
		paths = []string{"/edge/xdp/unblock"}
	default:
		WriteError(w, NewApiError("validation_failed", "layer 必须是 all / waf / cc / xdp"))
		return
	}
	nodes, ok := h.nodes(w, r, tenantID)
	if !ok {
		return
	}
	body := map[string]string{"ip": a.IP}
	res := fanoutNodes(nodes, func(n *config.Node) error {
		var errs []string
		for _, p := range paths {
			if err := h.pusher.PostToNode(n, p, body); err != nil {
				errs = append(errs, p+": "+err.Error())
			}
		}
		if len(errs) > 0 {
			return errors.New(strings.Join(errs, "; "))
		}
		return nil
	})
	writeJSON(w, http.StatusOK, map[string]any{"ip": a.IP, "layer": a.Layer, "push": res})
}

// pushAll 把本代理保存的 CC / XDP / 封禁阶梯配置重新下发到全部节点。
func (h *securityHandler) pushAll(w http.ResponseWriter, r *http.Request, tenantID string) {
	nodes, ok := h.nodes(w, r, tenantID)
	if !ok {
		return
	}
	out := map[string]map[string]string{}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, n := range nodes {
		wg.Add(1)
		go func(n *config.Node) {
			defer wg.Done()
			res := map[string]string{}
			pushTenantDefense(r.Context(), h.db, h.pusher, h.country, tenantID, n, res)
			mu.Lock()
			out[nodeLabel(n)] = res
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	writeJSON(w, http.StatusOK, map[string]any{"push": out, "nodes": len(nodes)})
}
