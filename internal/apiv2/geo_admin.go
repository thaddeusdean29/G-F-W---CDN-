package apiv2

import (
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"cdn/internal/config"
	"cdn/internal/geo"
	"cdn/internal/master"
)

// ---------------------------------------------------------------------------
// 区域封禁：管理员侧接口与下发。
//
// 一张表两层用：面板把"被引用到的那些国家"编译成前缀表，同一份字节既给七层做二分查表，
// 也给四层装进 LPM trie 丢包。Fingerprint 是这两层唯一的对照物——节点上报的指纹和面板算出来的
// 指纹不一致，就意味着"面板显示的那张表"与"网卡上生效的那张表"已经不是同一件事。
//
// 只有被引用的国家进表：只允许 CN 的策略不需要别人的 60 万个前缀，
// 实测 CN+US+RU 三国家 31 万段、gzip 后 0.98MB。
// ---------------------------------------------------------------------------

const (
	// geoPushTimeout 按 MB 级载荷写，不能沿用 master.post 里那个 10 秒：
	// 那是给 CC/XDP 几百字节的配置定的，跨机房慢链路上几 MB 真的传不完。
	geoPushTimeout = 90 * time.Second
	// geoMaxTable 是下发体的上限。全库所有国家约 4MB 原始 / 1.5MB gz，
	// 留出四倍余量，同时拒绝明显是灌进来的东西。
	geoMaxTable = 8 << 20
	// geoCfgPushTimeout 比"几百字节的配置"该有的超时宽得多：边缘收到配置后要顺手把
	// 四棵 LPM trie 整表重装（几十万条 bpf 地图写入，实测秒级、上限十秒级）。
	// 沿用原来的 20 秒，就会出现"四层其实装上了、面板显示下发失败"这种最难查的假故障。
	geoCfgPushTimeout = 60 * time.Second
)

// geoPlan 是"现在应该让节点跑什么"的完整答案：范围、要编进表的国家、编出来的表和四层开关。
type geoPlan struct {
	Scope     geo.Scope
	Countries []string
	Table     *geo.Table
	Payload   geo.TablePayload
	// L4Enabled 是主控这一侧的意愿：四层能不能真丢包只有节点自己知道（XDP 装没装上），
	// 所以这里只表达"应该装"，节点用 L4State.Want/Armed 两个字段把现实报回来。
	L4Enabled bool
	Notes     []string
}

// geoDomainPolicy 是 domains.geo_policy 解出来的那一行。
type geoDomainPolicy struct {
	Domain string
	Policy geo.Policy
}

// geoActiveDomainPolicies 取出所有代理所有域名里启用了的区域规则。
//
// 为什么跨租户：表是"一台节点上一份"的东西，节点同时服务多个租户的域名，
// 按单个租户编译会让另一个租户的规则查不到归属——那种情况下 allow 语义会把
// 别人的合法访客当成"未知"放行或拦掉，两边看到的表不是同一张。
func geoActiveDomainPolicies(ctx context.Context, db *sql.DB) ([]geoDomainPolicy, error) {
	rows, err := db.QueryContext(ctx, `SELECT domain, geo_policy FROM domains WHERE enabled`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []geoDomainPolicy
	for rows.Next() {
		var (
			host string
			raw  []byte
		)
		if err := rows.Scan(&host, &raw); err != nil {
			return nil, err
		}
		if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "{}" {
			continue
		}
		var p geo.Policy
		if err := json.Unmarshal(raw, &p); err != nil {
			// 绕过接口写进库的坏值：跳过它并把原因记下来。整条编译链不该因为
			// 一行脏数据失败——那会让所有租户的区域规则一起停止更新。
			log.Printf("[geo] 域名 %s 的 geo_policy 解析失败，已跳过: %v", host, err)
			continue
		}
		if !p.Enabled {
			continue
		}
		out = append(out, geoDomainPolicy{Domain: host, Policy: p})
	}
	return out, rows.Err()
}

// buildGeoPlan 编译当前应该生效的表。country 为 nil 或库没就位时返回带原因的 plan，
// 不返回 error：管理员页要能显示"为什么编不出表"，而不是整个接口 500。
func buildGeoPlan(ctx context.Context, db *sql.DB, country *geo.DB) (*geoPlan, error) {
	scope, _, err := loadGeoScope(ctx, db)
	if err != nil {
		return nil, err
	}
	domains, err := geoActiveDomainPolicies(ctx, db)
	if err != nil {
		return nil, err
	}
	policies := make([]geo.Policy, 0, len(domains)+1)
	policies = append(policies, scope.Node)
	for _, d := range domains {
		policies = append(policies, d.Policy)
	}
	want := geo.CountriesFrom(policies...)

	plan := &geoPlan{Scope: scope, Countries: want}
	switch {
	case len(want) == 0:
		// 一条启用的规则都没有：不需要表，也不该编一张空表出去。
		// 空表会让节点把"没有表"和"表里查不到"混成同一件事。
		plan.Notes = append(plan.Notes, "当前没有任何启用的区域规则，未编译表")
	case country == nil || !country.Ready():
		plan.Notes = append(plan.Notes, "国家级地理库未就位，表没编出来：区域规则不会生效")
		// 库缺位时"面板显示已开、节点没表"正是本项目最忌讳的失效形态，所以：
		// 编译不出表就不让四层装表。
	default:
		tbl, err := country.Compile(want)
		if err != nil {
			return nil, fmt.Errorf("编译区域前缀表失败: %w", err)
		}
		plan.Table = tbl
		plan.Payload = geo.TablePayload{
			Fingerprint: tbl.Fingerprint,
			Countries:   tbl.Countries,
			Total:       tbl.Total(),
			GzipB64:     base64.StdEncoding.EncodeToString(gzBytes(tbl.Bytes())),
			Built:       time.Now().UTC().Format(time.RFC3339),
		}
		if len(plan.Payload.GzipB64) > geoMaxTable {
			return nil, fmt.Errorf("区域前缀表超过 %d 字节上限（选了多少国家？）", geoMaxTable)
		}
	}
	// 四层意愿：总闸开 + 节点策略启用 + 真的编出了表 + deny + block 模式。
	// allow 在四层做不到（分不清"归属未知"和"不在允许清单"），所以不给它装表；
	// 这种组合在 ValidateScope 里就被拒了，走到这里说明是存量配置或库变化，报原因。
	// observe 同样不给：四层丢包没有"只记账不拦"这种动作，把它算成"该装表"会让
	// 面板显示四层在生效、实际一条都不该丢。
	plan.L4Enabled = scope.Enabled && scope.Node.Enabled && plan.Table != nil &&
		scope.Node.Action == geo.ActionDeny && scope.Node.Mode == geo.ModeBlock
	if scope.Enabled && scope.Node.Enabled && scope.Node.Action == geo.ActionAllow {
		plan.Notes = append(plan.Notes, "整节点策略是 allow：四层做不到，只下发七层，四层不装表")
	}
	if scope.Enabled && scope.Node.Enabled && scope.Node.Mode == geo.ModeObserve {
		plan.Notes = append(plan.Notes, "整节点策略是观察模式：四层只会丢包，不装表；七层照常记账并放行")
	}
	return plan, nil
}

func gzBytes(in []byte) []byte {
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	_, _ = w.Write(in)
	_ = w.Close()
	return out.Bytes()
}

// geoPushNode 把表（如果节点还没有）和节点配置推给一台节点，返回逐步结果。
//
// 表按指纹跳过：节点现在装着的指纹和要下发的相同就不再传那 1MB。"现在装着哪张"取
// 上报与最近一次成功下发里更新的那份（见 geoNodeTableFingerprint）；两者都拿不到时照常传
// ——宁可多传一次，也不要因为"以为它有了"而让节点拿着旧表跑。
func geoPushNode(p *master.Pusher, n *config.Node, plan *geoPlan) map[string]any {
	res := map[string]any{}
	have := geoNodeTableFingerprint(n)
	if plan.Table != nil {
		switch {
		case have == plan.Table.Fingerprint:
			res["table"] = "skipped: fingerprint " + have + " already loaded"
		default:
			status, body, err := p.PostToNodeResp(n, "/edge/geo/table", plan.Payload, geoPushTimeout)
			switch {
			case err != nil:
				res["table"] = "failed: " + err.Error()
				log.Printf("[geo] 下发前缀表到 %s (%s) 失败: %v", nodeLabel(n), n.Address, err)
			case status >= 400:
				msg := strings.TrimSpace(string(body))
				if msg == "" {
					msg = fmt.Sprintf("边缘返回 %d", status)
				}
				res["table"] = fmt.Sprintf("rejected(%d): %s", status, msg)
				log.Printf("[geo] 节点 %s 拒收前缀表 (%d): %s", nodeLabel(n), status, msg)
			default:
				res["table"] = "ok"
				var ack geo.EdgeTableResult
				if json.Unmarshal(body, &ack) == nil {
					res["table_fingerprint"] = ack.Fingerprint
					if ack.AppliedButNotStored {
						// 换表成功、落盘失败：这台节点重启就回到旧表，必须单独显示。
						res["table_not_persisted"] = true
					}
				}
				if have != "" && have != plan.Table.Fingerprint {
					res["table_was"] = have
				}
				geoRememberTable(n.ID, plan.Table.Fingerprint)
			}
		}
	} else if have != "" {
		// 没有启用的规则了，但节点上还装着表：不撤的话那几十万条前缀会一直留在网卡上，
		// 一条也不会执行，却继续占内存、继续让读数显示"已装载某张表"。
		status, body, err := p.PostToNodeResp(n, "/edge/geo/table", geo.TablePayload{}, geoPushTimeout)
		switch {
		case err != nil:
			res["table"] = "failed: 撤表没成功：" + err.Error()
		case status >= 400:
			res["table"] = fmt.Sprintf("rejected(%d): %s", status, strings.TrimSpace(string(body)))
		default:
			res["table"] = "cleared: 已撤下指纹 " + have + "（当前没有启用的区域规则）"
			geoRememberTable(n.ID, "")
		}
	} else {
		res["table"] = "skipped: nothing to compile"
	}

	cfg := geo.ConfigPayload{ScopeEnabled: plan.Scope.Enabled, Node: plan.Scope.Node, L4Enabled: plan.L4Enabled}
	// 配置永远照常推，不按"节点已经有了"跳过：它是边缘重装四层 trie 的触发器之一。
	if status, body, err := p.PostToNodeResp(n, "/edge/geo/config", cfg, geoCfgPushTimeout); err != nil {
		res["config"] = "failed: " + err.Error()
	} else if status >= 400 {
		msg := strings.TrimSpace(string(body))
		if msg == "" {
			msg = fmt.Sprintf("边缘返回 %d", status)
		}
		res["config"] = fmt.Sprintf("rejected(%d): %s", status, msg)
	} else {
		res["config"] = "ok"
	}
	return res
}

// geoHandedTables 记住主控最后一次成功交给每台节点的表（指纹 + 交出去的时间）。
// 空指纹表示"成功撤表"。进程内存储就够了：面板重启后节点的下一次上报会接管。
var geoHandedTables sync.Map

type geoHandedTable struct {
	fingerprint string
	at          time.Time
}

func geoRememberTable(nodeID, fingerprint string) {
	geoHandedTables.Store(nodeID, geoHandedTable{fingerprint: fingerprint, at: time.Now()})
}

// geoNodeTableFingerprint 回答"这台节点现在装的是哪张表"，用来决定这次要不要真的传那 1MB。
//
// 取上报与最近一次成功下发里更新的那一份，不能只信上报：上报是十秒级的，一次成功的下发
// 完全可能比最近那份上报更新。只按上报跳过就会撞上这种情形——租户刚把节点换成 B 表，
// 最近那份上报还写着 A，而管理员这次要发的恰好又是 A：跳过之后节点拿着 B 跑、面板显示 A，
// deny 规则在 B 里没有的那些国家上全部查成"归属未知"然后放行，四层 trie 也少了那些段。
//
// 上报缺失或过期时一律返回空串（照常传）：这时连"节点还活着吗"都不知道，
// 更不能拿一份旧的下发记录当它现在装着的表。
func geoNodeTableFingerprint(n *config.Node) string {
	raw, err := reports.get(n.ID, reportGeoStats, time.Now())
	if err != nil {
		return ""
	}
	var r geo.Readings
	if json.Unmarshal(raw, &r) != nil {
		return ""
	}
	if v, ok := geoHandedTables.Load(n.ID); ok {
		if h, _ := v.(geoHandedTable); h.at.After(reports.reportedAt(n.ID)) {
			return h.fingerprint
		}
	}
	return r.Table.Fingerprint
}

// geoFanout 并发下发到给定节点集合，返回带 per_node 的汇总。
//
// 逐节点结果必须回给前端："点了保存"不等于"全网都在拦"。某台节点没接住意味着它还在用旧表，
// 而来自那个国家的流量不会因为这台节点没更新就绕开它。
func geoFanout(ctx context.Context, p *master.Pusher, nodes []*config.Node, plan *geoPlan) map[string]any {
	if p == nil {
		return map[string]any{"nodes": len(nodes), "ok": 0, "error": "主控未启用节点推送，区域配置没能下发"}
	}
	per := make(map[string]map[string]any, len(nodes))
	var (
		mu     sync.Mutex
		wg     sync.WaitGroup
		ok     int
		failed []string
	)
	for _, n := range nodes {
		wg.Add(1)
		go func(n *config.Node) {
			defer wg.Done()
			res := geoPushNode(p, n, plan)
			good := geoPushError(res) == ""
			mu.Lock()
			per[nodeLabel(n)] = res
			if good {
				ok++
			} else {
				failed = append(failed, nodeLabel(n))
			}
			mu.Unlock()
		}(n)
	}
	wg.Wait()
	out := map[string]any{
		"nodes":     len(nodes),
		"ok":        ok,
		"per_node":  per,
		"total":     0,
		"countries": plan.Countries,
	}
	if plan.Table != nil {
		out["fingerprint"] = plan.Table.Fingerprint
		out["total"] = plan.Table.Total()
	}
	if len(failed) > 0 {
		sort.Strings(failed)
		out["failed"] = failed
	}
	if len(plan.Notes) > 0 {
		out["notes"] = plan.Notes
	}
	return out
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}

// ── 管理员接口 ─────────────────────────────────────────────────────────────

type adminGeoHandler struct {
	db      *sql.DB
	pusher  *master.Pusher
	nodes   *NodeRepo
	country *geo.DB
}

func (h *adminGeoHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/api/v2/admin/geo":
		switch r.Method {
		case http.MethodGet:
			h.get(w, r)
		case http.MethodPut:
			h.put(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	case "/api/v2/admin/geo/push":
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		h.push(w, r)
	case "/api/v2/admin/geo/nodes":
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		h.nodesReading(w, r)
	default:
		WriteError(w, NewApiError("not_found", "未找到该资源"))
	}
}

// geoDBReading 是"面板这一侧到底有没有库"的说法。管理员页要先回答这个，
// 因为所有"配了没生效"的排查都从这里开始。
func geoDBReading(d *geo.DB) map[string]any {
	haveV4, haveV6 := d.Available()
	out := map[string]any{
		"ready":   d.Ready(),
		"ipv4":    haveV4,
		"ipv6":    haveV6,
		"loaded":  d.Loaded,
		"missing": d.Missing,
	}
	if d.Ready() {
		out["countries"] = d.CountryCodes()
		if e := d.CountryCodesErr(); e != "" {
			out["catalog_error"] = e
		}
	}
	return out
}

func (h *adminGeoHandler) get(w http.ResponseWriter, r *http.Request) {
	plan, err := buildGeoPlan(r.Context(), h.db, h.country)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"scope":    plan.Scope,
		"saved":    h.scopeSaved(r.Context()),
		"plan":     planView(plan),
		"geo_db":   geoDBReading(h.country),
		"readings": h.summary(r.Context()),
	})
}

func planView(plan *geoPlan) map[string]any {
	out := map[string]any{
		"countries":   plan.Countries,
		"l4_enabled":  plan.L4Enabled,
		"notes":       plan.Notes,
		"total":       0,
		"fingerprint": "",
	}
	if plan.Table != nil {
		out["total"] = plan.Table.Total()
		out["fingerprint"] = plan.Table.Fingerprint
		out["gzip_bytes"] = len(plan.Payload.GzipB64) * 3 / 4
	}
	return out
}

func (h *adminGeoHandler) scopeSaved(ctx context.Context) bool {
	var n int
	_ = h.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM platform_settings WHERE name = ?`, settingGeoScope).Scan(&n)
	return n > 0
}

// put 保存范围并下发。校验全部在碰库之前完成；下发在保存之后，失败逐节点报出来。
func (h *adminGeoHandler) put(w http.ResponseWriter, r *http.Request) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		WriteError(w, NewApiError("invalid_json", "请求体读取失败"))
		return
	}
	if bad := UnknownFields(raw, []string{"enabled", "selectable", "node"}); len(bad) > 0 {
		WriteError(w, unknownFieldError(bad))
		return
	}
	var in geo.Scope
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		WriteError(w, NewApiError("validation_failed", "字段类型不正确: "+err.Error()))
		return
	}
	in.Normalize()
	in.Node = in.Node.WithDefaults()
	if bad := geo.ValidateScope(in); !bad.OK() {
		WriteError(w, geoFieldError("区域封禁配置不合法", bad))
		return
	}
	// 开了总闸或四层却编不出表，就不许存：存下去的结果是"面板显示已启用、
	// 节点一张表都没有"，而这条路径上没有任何一处会报错。
	if (in.Enabled || in.Node.Enabled) && !h.country.Ready() {
		WriteError(w, NewApiError("unavailable", "国家级地理库未就位（"+geo.FileIPv4+" / "+geo.FileIPv6+
			"），开不了区域封禁：装不出前缀表就没有任何判决依据").
			WithDetails(map[string]any{"fields": map[string]string{"enabled": "地理库未就位"}}))
		return
	}
	// 划给租户的可选国家里，库里没有网段的那些当场拒掉：管理员挑了它、租户选了它、
	// 规则启用了它，最后节点上一个段都查不到——那条规则会一直"看起来生效"。
	if in.Enabled {
		missing, scanErr := geoUncataloged(h.country, in.Selectable)
		if scanErr != "" {
			WriteError(w, NewApiError("unavailable", "国家级地理库读不出国家目录，无法确认这些国家有没有可下发的网段: "+scanErr))
			return
		}
		if len(missing) > 0 {
			WriteError(w, NewApiError("validation_failed", "库里没有这些国家的网段，选了也拦不到任何地址: "+strings.Join(missing, "、")).
				WithDetails(map[string]any{"fields": map[string]string{"selectable": "无可用网段: " + strings.Join(missing, "、")}}))
			return
		}
	}
	if err := saveGeoScope(r.Context(), h.db, in); err != nil {
		WriteError(w, err)
		return
	}
	plan, err := buildGeoPlan(r.Context(), h.db, h.country)
	if err != nil {
		WriteError(w, err)
		return
	}
	nodes, err := allEnabledNodes(r.Context(), h.db, h.nodes)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"scope": plan.Scope,
		"plan":  planView(plan),
		"push":  geoFanout(r.Context(), h.pusher, nodes, plan),
	})
}

func (h *adminGeoHandler) push(w http.ResponseWriter, r *http.Request) {
	plan, err := buildGeoPlan(r.Context(), h.db, h.country)
	if err != nil {
		WriteError(w, err)
		return
	}
	nodes, err := allEnabledNodes(r.Context(), h.db, h.nodes)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"plan": planView(plan), "push": geoFanout(r.Context(), h.pusher, nodes, plan)})
}

// nodesReading 逐节点报"实跑的表"与"面板要它跑的表"是否同一张，以及四层状态和计数。
//
// matches_fingerprint 是这一页唯一的真相来源：它比的是节点自己上报的指纹。
// 某台节点还在跑旧表（下发时它不在线、或它是没升级的旧 cdnedge）只有这一列能看出来。
func (h *adminGeoHandler) nodesReading(w http.ResponseWriter, r *http.Request) {
	nodes, err := allEnabledNodes(r.Context(), h.db, h.nodes)
	if err != nil {
		WriteError(w, err)
		return
	}
	plan, err := buildGeoPlan(r.Context(), h.db, h.country)
	if err != nil {
		WriteError(w, err)
		return
	}
	type row struct {
		Node         string   `json:"node"`
		IP           string   `json:"ip"`
		Fingerprint  string   `json:"fingerprint,omitempty"`
		Total        int      `json:"total"`
		Countries    []string `json:"countries,omitempty"`
		Loaded       bool     `json:"loaded"`
		ScopeEnabled bool     `json:"scope_enabled"`
		NodeMode     string   `json:"node_mode,omitempty"`
		L4Armed      bool     `json:"l4_armed"`
		L4Want       bool     `json:"l4_want"`
		L4Entries    int      `json:"l4_entries"`
		L4Dropped    uint64   `json:"l4_dropped"`
		L4Error      string   `json:"l4_error,omitempty"`
		// L4Fingerprint 是网卡上那四棵 trie 来自哪张表，L4Applied 是节点最后一次动它们的时刻。
		// 有这两个才答得出"面板这张表和网卡正在丢包的那张表是不是同一张"：
		// 光有 l4_armed 只说明装过东西，不说明装的是现在这份。
		L4Fingerprint string `json:"l4_fingerprint,omitempty"`
		L4Applied     string `json:"l4_applied,omitempty"`
		// L4Matches 只在四层确实在丢包时给结论。观察模式、allow、总闸关着这些
		// "本来就不该装四层"的组合留 nil：给成 false 就是满屏红叉，真故障反而埋在里面。
		L4Matches  *bool  `json:"l4_matches,omitempty"`
		Observe    uint64 `json:"observe"`
		Blocked    uint64 `json:"blocked"`
		Pass       uint64 `json:"pass"`
		Unknown    uint64 `json:"unknown"`
		Exception  uint64 `json:"exception"`
		TableError string `json:"table_error,omitempty"`
		Reported   string `json:"reported_at,omitempty"`
		Matches    *bool  `json:"matches_plan_fingerprint"`
		Error      string `json:"error,omitempty"`
	}
	rs := reportField[geo.Readings](nodes, reportGeoStats)
	items := make([]row, 0, len(rs))
	var totalObs, totalBlock, totalUnk, totalExc uint64
	for _, x := range rs {
		it := row{Node: nodeLabel(x.Node), IP: x.Node.IP}
		if x.Err != nil {
			it.Error = x.Err.Error()
			items = append(items, it)
			continue
		}
		d := x.Data
		it.Fingerprint = d.Table.Fingerprint
		it.Total = d.Table.Total
		it.Countries = d.Table.Countries
		it.Loaded = d.Table.Loaded
		it.TableError = d.Table.Error
		it.ScopeEnabled = d.ScopeEnabled
		it.NodeMode = d.Node.Mode
		it.L4Armed = d.L4.Armed
		it.L4Want = d.L4.Want
		it.L4Entries = d.L4.EntriesV4 + d.L4.EntriesV6
		it.L4Dropped = d.L4.Dropped
		it.L4Error = d.L4.Error
		it.L4Fingerprint = d.L4.Fingerprint
		it.L4Applied = d.L4.Applied
		// 网卡那张表的身份对不上面板这张表时，四层正在丢的是一批已经不该丢的地址。
		// 比的是面板这张（plan），不是节点自己上报的七层那张：节点上下两层可能一起停在旧表上，
		// 自己跟自己一致不等于跟面板一致——那种时候给个 true 就是把故障显示成正常。
		// 只在 armed 时判：没装四层的时候"不一致"是设计如此，不是故障。
		if d.L4.Armed {
			want := planFingerprint(plan)
			m4 := d.L4.Fingerprint != "" && want != "" && d.L4.Fingerprint == want
			it.L4Matches = &m4
		}
		it.Observe = d.Counters.Observe
		it.Blocked = d.Counters.Blocked
		it.Pass = d.Counters.Pass
		it.Unknown = d.Counters.Unknown
		it.Exception = d.Counters.Exception
		it.Reported = d.At
		totalObs += it.Observe
		totalBlock += it.Blocked
		totalUnk += it.Unknown
		totalExc += it.Exception
		if plan.Table != nil {
			m := it.Fingerprint == plan.Table.Fingerprint && it.Loaded
			it.Matches = &m
		}
		items = append(items, it)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"expected_fingerprint": planFingerprint(plan),
		"expected_total":       planTotal(plan),
		"items":                items,
		"total":                map[string]uint64{"observe": totalObs, "blocked": totalBlock, "unknown": totalUnk, "exception": totalExc},
		"notes":                plan.Notes,
	})
}

func planFingerprint(plan *geoPlan) string {
	if plan.Table == nil {
		return ""
	}
	return plan.Table.Fingerprint
}

func planTotal(plan *geoPlan) int {
	if plan.Table == nil {
		return 0
	}
	return plan.Table.Total()
}

// summary 汇总各节点上报的读数，供管理员页顶部那一排数字用。
// 没有上报的节点不算"0 次"，而是单独报"还没有上报过"——把没数据显示成 0
// 会让人以为这台节点真的放行过 0 个请求。
func (h *adminGeoHandler) summary(ctx context.Context) map[string]any {
	nodes, err := allEnabledNodes(ctx, h.db, h.nodes)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	rs := reportField[geo.Readings](nodes, reportGeoStats)
	out := map[string]any{"nodes": len(rs), "reported": 0, "silent": 0}
	byCountry := map[string]*geo.CountryCount{}
	var counters geo.Counters
	for _, x := range rs {
		if x.Err != nil {
			out["silent"] = asInt(out["silent"]) + 1
			continue
		}
		out["reported"] = asInt(out["reported"]) + 1
		d := x.Data
		counters.Observe += d.Counters.Observe
		counters.Blocked += d.Counters.Blocked
		counters.Pass += d.Counters.Pass
		counters.Unknown += d.Counters.Unknown
		counters.Exception += d.Counters.Exception
		counters.Off += d.Counters.Off
		counters.NoTable += d.Counters.NoTable
		for _, c := range d.Countries {
			cur := byCountry[c.Country]
			if cur == nil {
				cp := c
				byCountry[c.Country] = &cp
				continue
			}
			cur.Observe += c.Observe
			cur.Blocked += c.Blocked
			cur.Pass += c.Pass
		}
	}
	list := make([]geo.CountryCount, 0, len(byCountry))
	for _, c := range byCountry {
		list = append(list, *c)
	}
	sort.Slice(list, func(i, j int) bool {
		si, sj := list[i].Observe+list[i].Blocked, list[j].Observe+list[j].Blocked
		if si != sj {
			return si > sj
		}
		return list[i].Country < list[j].Country
	})
	out["counters"] = counters
	out["countries"] = list
	return out
}

func asInt(v any) int {
	n, _ := v.(int)
	return n
}

// geoEnsureTable 在域名区域规则改动后，把当前应该生效的表补发给给定节点集合。
//
// 只发表、不发节点配置：节点级策略（平台总闸、四层丢包）归管理员所有，
// 由管理员的保存动作和新节点接入负责。租户改自己域名时去覆盖它，
// 等于让一个代理能改到别的代理共用的那台节点的四层行为。
//
// 为什么每次改完都要发：新选中的国家可能还没进节点上那张表，不补就会在边缘查成"未知"
// 然后放行 —— 面板上"这个国家已封禁"当场变成一句假话。指纹相同时代码里会直接跳过，
// 所以正常情况下这一次调用不产生流量。
func geoEnsureTable(ctx context.Context, db *sql.DB, p *master.Pusher, country *geo.DB, nodes []*config.Node) map[string]any {
	if p == nil {
		return map[string]any{"error": "主控未启用节点推送，区域前缀表没能补发"}
	}
	plan, err := buildGeoPlan(ctx, db, country)
	if err != nil {
		return map[string]any{"error": err.Error()}
	}
	if plan.Table == nil {
		out := map[string]any{"skipped": strings.Join(plan.Notes, "; ")}
		// 规则全关不等于表已经撤下来：还装着表的节点要清掉，否则它带着几十万条永远不会执行的
		// 前缀继续跑，读数里那张"已装载"也还会让面板显示成有规则在跑。
		// 这里只发表：节点级策略（总闸、四层丢包）归管理员，一次域名保存不该改它。
		var cleared, fails []string
		for _, n := range nodes {
			have := geoNodeTableFingerprint(n)
			if have == "" {
				continue
			}
			status, body, err := p.PostToNodeResp(n, "/edge/geo/table", geo.TablePayload{}, geoPushTimeout)
			if err != nil {
				fails = append(fails, nodeLabel(n)+": 撤表没成功——"+err.Error())
				continue
			}
			if status >= 400 {
				fails = append(fails, nodeLabel(n)+fmt.Sprintf(": 撤表被拒(%d): %s", status, strings.TrimSpace(string(body))))
				continue
			}
			cleared = append(cleared, nodeLabel(n)+"("+have+")")
			geoRememberTable(n.ID, "")
		}
		if len(cleared) > 0 {
			out["cleared"] = cleared
		}
		if len(fails) > 0 {
			out["failed"] = fails
			out["error"] = strings.Join(fails, "; ")
		}
		return out
	}
	per := map[string]map[string]any{}
	var bad []string
	for _, n := range nodes {
		have := geoNodeTableFingerprint(n)
		if have == plan.Table.Fingerprint {
			per[nodeLabel(n)] = map[string]any{"table": "skipped: already loaded"}
			continue
		}
		status, body, err := p.PostToNodeResp(n, "/edge/geo/table", plan.Payload, geoPushTimeout)
		item := map[string]any{}
		switch {
		case err != nil:
			item["table"] = "failed: " + err.Error()
		case status >= 400:
			msg := strings.TrimSpace(string(body))
			if msg == "" {
				msg = fmt.Sprintf("边缘返回 %d", status)
			}
			item["table"] = fmt.Sprintf("rejected(%d): %s", status, msg)
		default:
			item["table"] = "ok"
			geoRememberTable(n.ID, plan.Table.Fingerprint)
		}
		per[nodeLabel(n)] = item
		if item["table"] != "ok" {
			bad = append(bad, nodeLabel(n)+": "+asString(item["table"]))
		}
	}
	out := map[string]any{
		"fingerprint": plan.Table.Fingerprint,
		"total":       plan.Table.Total(),
		"countries":   plan.Countries,
		"per_node":    per,
	}
	if len(bad) > 0 {
		out["failed"] = bad
		out["error"] = strings.Join(bad, "; ")
	}
	return out
}
