package apiv2

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"cdn/internal/config"
	"cdn/internal/master"
	"cdn/internal/waf"
)

// ---------------------------------------------------------------------------
// 租户级 WAF 托管规则配置。
//
// 策略按代理各存一份（tenant_settings.waf_config），改完只下发到本代理自己的节点，
// 与 CC / XDP 配置完全同构。规则包本体不在这里：那是平台级的，见 waf_packages.go。
//
// 存储与下发都用 waf.Policy 这个结构：它的 JSON tag 就是边缘 PolicyPatch 的字段名，
// 少一层翻译就少一处会翻译错的地方。
// ---------------------------------------------------------------------------

const settingWAFConfig = "waf_config"

// wafNodeStats 是边缘上报的 WAF 读数（internal/edgeapi.wafStatsView 的镜像，不含 catalog）。
// 两边字段名对不上时这里只会解出零值，所以改边缘的读数结构必须同步改这一段。
type wafNodeStats struct {
	Policy    waf.Policy          `json:"policy"`
	Packages  waf.PackageReadings `json:"packages"`
	Effective []string            `json:"effective"`
	Hits      []waf.HitRow        `json:"hits"`
	Observe   uint64              `json:"observe_total"`
	Blocked   uint64              `json:"blocked_total"`
	At        string              `json:"at"`
}

// loadWAFPolicy 读出代理保存的策略。没保存过就返回 DefaultPolicy 和 saved=false，
// 由调用方决定"要不要下发"（默认不下发：边缘自带同一份默认值）。
func loadWAFPolicy(ctx context.Context, db *sql.DB, tenantID string) (waf.Policy, bool, error) {
	pol := waf.DefaultPolicy()
	saved, err := loadTenantSetting(ctx, db, tenantID, settingWAFConfig, &pol)
	if err != nil {
		return pol, false, err
	}
	return pol, saved, nil
}

// wafCatalogIDs 从包目录里取出可选的规则集 id 与规则 id。
func wafCatalogIDs(pkg waf.RulePackage) (sets, rules map[string]bool) {
	sets, rules = map[string]bool{}, map[string]bool{}
	for _, s := range pkg.Sets {
		sets[s.ID] = true
	}
	for _, r := range pkg.Rules {
		rules[r.ID] = true
	}
	return sets, rules
}

// validateWAFPolicy 在保存前把策略卡死。这里必须"拒绝"而不是"纠正"：
// waf.Policy.Normalize 会把认不出的 mode/level 静默改成 block/medium，把包里不存在
// 的规则 id 直接丢掉 —— 那样面板上会显示一份"节点其实不认"的配置，界面就成了假账。
// 所以非法值一律 400，让改的人当场看见。
func validateWAFPolicy(pol waf.Policy, pair *wafPkgPair) error {
	fields := map[string]string{}
	switch pol.Mode {
	case waf.ModeBlock, waf.ModeObserve:
	default:
		fields["mode"] = "只能是 block 或 observe"
	}
	switch pol.Level {
	case waf.LevelOff, waf.LevelLow, waf.LevelMedium, waf.LevelHigh, waf.LevelAttack:
	default:
		fields["level"] = "只能是 off / low / medium / high / attack"
	}
	if pol.GrayPercent < 0 || pol.GrayPercent > 99 {
		fields["gray_percent"] = "必须在 0~99 之间"
	}
	allowed := pair.versions()
	known := false
	for _, v := range allowed {
		if v == pol.RulesVersion {
			known = true
			break
		}
	}
	if !known {
		fields["rules_version"] = "只能固定到节点上有的包：" + strings.Join(versionLabels(allowed), "、")
	}
	setIDs, ruleIDs := wafCatalogIDs(pair.Active.Package())
	for _, id := range pol.Sets {
		if !setIDs[id] {
			fields["sets"] = "规则集 " + id + " 不在当前规则包里"
			break
		}
	}
	for id := range pol.Rules {
		if !ruleIDs[id] {
			fields["rules"] = "规则 " + id + " 不在当前规则包里"
			break
		}
	}
	if len(fields) > 0 {
		return NewApiError("validation_failed", "WAF 配置不合法").WithDetails(map[string]any{"fields": fields})
	}
	return nil
}

// validateWAFPatch 只校验"提交上来的那一个字面量"。必须在 Apply 之前跑：
// Apply 尾部的 Normalize 会把认不出的 mode/level 静默改成 block/medium，
// 等合并后的策略走到 validateWAFPolicy 时早已看不出用户填错过，于是变成
// "界面填的是 bogus、库里存的是 medium"这种没人报错的假账。
func validateWAFPatch(patch waf.PolicyPatch) error {
	fields := map[string]string{}
	if patch.Mode != nil {
		switch *patch.Mode {
		case waf.ModeBlock, waf.ModeObserve:
		default:
			fields["mode"] = "只能是 block 或 observe"
		}
	}
	if patch.Level != nil {
		switch *patch.Level {
		case waf.LevelOff, waf.LevelLow, waf.LevelMedium, waf.LevelHigh, waf.LevelAttack:
		default:
			fields["level"] = "只能是 off / low / medium / high / attack"
		}
	}
	if patch.GrayPercent != nil && (*patch.GrayPercent < 0 || *patch.GrayPercent > 99) {
		fields["gray_percent"] = "必须在 0~99 之间"
	}
	if len(fields) > 0 {
		return NewApiError("validation_failed", "WAF 配置不合法").WithDetails(map[string]any{"fields": fields})
	}
	return nil
}

// versionLabels 把 rules_version 的可选值写成面向人的说明（空串=跟随活动包）。
func versionLabels(vs []string) []string {
	out := make([]string, 0, len(vs))
	for _, v := range vs {
		if v == "" {
			out = append(out, "空（跟随活动包）")
			continue
		}
		out = append(out, v)
	}
	return out
}

// ── 代理侧接口（securityHandler 的方法）─────────────────────────────────────

func (h *securityHandler) getWAFConfig(w http.ResponseWriter, r *http.Request, tenantID string) {
	pol, saved, err := loadWAFPolicy(r.Context(), h.db, tenantID)
	if err != nil {
		WriteError(w, err)
		return
	}
	pair, err := wafPackages.get(r.Context(), h.db)
	if err != nil {
		WriteError(w, err)
		return
	}
	// catalog 用边缘那份而不是主控库里的包算出来的目录，是因为界面要显示的就是
	// "节点上真有的那些规则"。两者正常情况下是同一份（同一次下发），坏包时上面已经报错。
	writeJSON(w, http.StatusOK, map[string]any{
		"config":          pol,
		"saved":           saved,
		"catalog":         pair.Active.Package(),
		"versions":        pair.versions(),
		"active_version":  pair.Active.Version(),
		"builtin_version": pair.BuiltinVersion,
	})
}

func (h *securityHandler) putWAFConfig(w http.ResponseWriter, r *http.Request, tenantID string) {
	raw, _, err := decodeKnownFields(r, []string{"enabled", "mode", "level", "sets", "rules", "rules_version", "gray_percent"})
	if err != nil {
		WriteError(w, err)
		return
	}
	pair, err := wafPackages.get(r.Context(), h.db)
	if err != nil {
		WriteError(w, err)
		return
	}
	cur, _, err := loadWAFPolicy(r.Context(), h.db, tenantID)
	if err != nil {
		WriteError(w, err)
		return
	}
	// 与边缘同一个 patch 语义：payload 里没出现的字段保持原值。面板表单理论上全量提交，
	// 但少传一个 enabled 就把整段防护关掉这种后果，不能指望前端不出错。
	var patch waf.PolicyPatch
	if err := json.Unmarshal(raw, &patch); err != nil {
		WriteError(w, NewApiError("validation_failed", "字段类型不正确: "+err.Error()))
		return
	}
	if err := validateWAFPatch(patch); err != nil {
		WriteError(w, err)
		return
	}
	in := cur
	in.Apply(patch)
	if err := validateWAFPolicy(in, pair); err != nil {
		WriteError(w, err)
		return
	}
	// Apply 里已经 Normalize 过一遍（去重、排序、rules 归一成非 nil map），存的就是
	// 边缘会执行的那一份，两边比字节也能对上。
	if err := saveTenantSetting(r.Context(), h.db, tenantID, settingWAFConfig, in); err != nil {
		WriteError(w, err)
		return
	}
	nodes, ok := h.nodes(w, r, tenantID)
	if !ok {
		return
	}
	res := fanoutNodes(nodes, func(n *config.Node) error { return h.pusher.PostToNode(n, "/edge/waf/config", in) })
	writeJSON(w, http.StatusOK, map[string]any{
		"config": in,
		"push":   res,
		// 生效规则条数与 id 清单：改一次级别到底少跑了哪几条，前端直接能列出来，
		// 不用等节点上报（新节点还没上报过，那时无可显示）。
		"effective": waf.EffectiveRules(pair.Active, in),
	})
}

// wafStats 汇总本代理各节点的 WAF 读数。
//
// 除了总量，这里最有用的字段是 per_node[].matches_policy：它比的是"面板存的策略"与
// "节点实跑的策略"。下发时某个节点不在线、或者它还是个没升级的旧 cdnedge，
// 只有这一列能看出来。
func (h *securityHandler) wafStats(w http.ResponseWriter, r *http.Request, tenantID string) {
	nodes, ok := h.nodes(w, r, tenantID)
	if !ok {
		return
	}
	saved, _, err := loadWAFPolicy(r.Context(), h.db, tenantID)
	if err != nil {
		WriteError(w, err)
		return
	}
	want, err := json.Marshal(saved)
	if err != nil {
		WriteError(w, err)
		return
	}
	rs := reportField[wafNodeStats](nodes, reportWAFStats)
	type nodeRow struct {
		Node          string `json:"node"`
		IP            string `json:"ip"`
		Enabled       bool   `json:"enabled"`
		Mode          string `json:"mode"`
		Level         string `json:"level"`
		GrayPercent   int    `json:"gray_percent"`
		Active        string `json:"active_version"`
		Previous      string `json:"previous_version"`
		Pinned        string `json:"rules_version,omitempty"`
		PinMissing    bool   `json:"pin_missing"`
		Effective     int    `json:"effective_rules"`
		Observe       uint64 `json:"observe"`
		Blocked       uint64 `json:"blocked"`
		MatchesPolicy *bool  `json:"matches_policy"`
		Reported      string `json:"reported_at,omitempty"`
		Error         string `json:"error,omitempty"`
	}
	per := make([]nodeRow, 0, len(rs))
	var totalObserve, totalBlocked uint64
	merged := map[string]*waf.HitRow{}
	names := map[string]string{}
	for _, x := range rs {
		row := nodeRow{Node: nodeLabel(x.Node), IP: x.Node.IP}
		if x.Err != nil {
			row.Error = x.Err.Error()
			per = append(per, row)
			continue
		}
		d := x.Data
		row.Enabled = d.Policy.Enabled
		row.Mode = d.Policy.Mode
		row.Level = d.Policy.Level
		row.GrayPercent = d.Policy.GrayPercent
		row.Active = d.Packages.Active
		row.Previous = d.Packages.Previous
		row.Pinned = d.Packages.Pinned
		row.PinMissing = d.Packages.PinMissing
		row.Effective = len(d.Effective)
		row.Observe = d.Observe
		row.Blocked = d.Blocked
		row.Reported = d.At
		totalObserve += d.Observe
		totalBlocked += d.Blocked
		// 策略是否真的落到了这台节点：比序列化后的字节。两边都是同一套 Normalize 出来的，
		// 差一个字段就是没吃到（或它还是旧版边缘）。
		if got, err := json.Marshal(d.Policy); err == nil {
			m := string(got) == string(want)
			row.MatchesPolicy = &m
		}
		for _, hit := range d.Hits {
			cur := merged[hit.Rule]
			if cur == nil {
				cp := hit
				merged[hit.Rule] = &cp
			} else {
				cur.Observe += hit.Observe
				cur.Blocked += hit.Blocked
			}
			if hit.Name != "" {
				names[hit.Rule] = hit.Name
			}
		}
		per = append(per, row)
	}
	hits := make([]waf.HitRow, 0, len(merged))
	for id, hit := range merged {
		if hit.Name == "" {
			hit.Name = names[id]
		}
		hits = append(hits, *hit)
	}
	sort.Slice(hits, func(i, j int) bool {
		si, sj := hits[i].Observe+hits[i].Blocked, hits[j].Observe+hits[j].Blocked
		if si != sj {
			return si > sj
		}
		return hits[i].Rule < hits[j].Rule
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"total":  map[string]any{"observe": totalObserve, "blocked": totalBlocked, "rules": len(hits)},
		"hits":   hits,
		"nodes":  per,
		"errors": collectErrors(rs),
		// 面板存的策略一并回显：读数与预期并排显示，才看得出"改成功了没有"。
		"policy": saved,
	})
}

// pushWAFPolicy 把代理保存的策略推给一个节点（新节点接入时补发）。
// 从没保存过就不推：边缘自带的默认策略与这里完全一致，多此一举反而会把节点上
// 已有的、别处改过的存档盖掉。
func pushWAFPolicy(ctx context.Context, db *sql.DB, p *master.Pusher, tenantID string, n *config.Node, res map[string]string) {
	pol, saved, err := loadWAFPolicy(ctx, db, tenantID)
	if err != nil {
		res["waf"] = err.Error()
		return
	}
	if !saved {
		res["waf"] = "skipped: not configured"
		return
	}
	if err := p.PostToNode(n, "/edge/waf/config", pol); err != nil {
		res["waf"] = err.Error()
		return
	}
	res["waf"] = "ok"
}

// wafPackageForTenant 把当前活动包补发给一个节点。新节点出厂包可能就是主控这一份
// （同一次构建），但"可能"不够：管理员换过包之后，新装节点必须补发一次才吃得到。
func wafPackageForTenant(ctx context.Context, db *sql.DB, p *master.Pusher, n *config.Node, res map[string]string) {
	if p == nil {
		return
	}
	pair, err := wafPackages.get(ctx, db)
	if err != nil {
		res["waf_rules"] = err.Error()
		return
	}
	if !pair.ActiveFromDB {
		// 没有管理员维护的包：节点用出厂包就是对的，不用推一份一模一样的过去。
		res["waf_rules"] = "skipped: builtin package"
		return
	}
	if err := pushWafPairToNode(p, n, pair); err != nil {
		res["waf_rules"] = err.Error()
		return
	}
	res["waf_rules"] = "ok"
}
