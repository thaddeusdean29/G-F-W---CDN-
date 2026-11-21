package apiv2

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"sort"
	"strings"

	"cdn/internal/config"
	"cdn/internal/geo"
	"cdn/internal/master"
)

// ---------------------------------------------------------------------------
// 区域封禁：代理侧接口与新节点补发。
//
// 这一层只读，不写。域名规则本身跟着 PATCH /api/v2/domains/:id 走（见 domains.go），
// 平台总闸、可选国家、整节点的四层丢包都由管理员那份范围决定（见 geo_admin.go）。
// 页面进门前必须先问清两件事：我能选哪些国家，和我选的那些到底落到节点上没有。
// ---------------------------------------------------------------------------

// geoPushError 从逐步骤结果里挑出第一个没成功的，返回它的说法；全成功返回空串。
//
// "skipped" 算成功：那是"这一层本来就没有要发的东西"（没有启用的规则、表指纹已经对上），
// 不是失败。"cleared" 也算成功——规则全关之后主动把表从节点上撤下来，正是该有的结果。
// 但 applied_not_persisted 算失败——那种节点一重启就回到旧表。
func geoPushError(per map[string]any) string {
	for _, k := range []string{"table", "config"} {
		v := asString(per[k])
		if v == "" || v == "ok" || strings.HasPrefix(v, "skipped") || strings.HasPrefix(v, "cleared") {
			continue
		}
		return k + ": " + v
	}
	if nt, _ := per["table_not_persisted"].(bool); nt {
		return "table: 换表成功但没落盘，这台节点重启会回到旧表"
	}
	return ""
}

// geoForTenant 给一个节点补发区域封禁要的表与节点级配置（新节点接入、pushAll 都走这里）。
//
// 为什么不能像 WAF 策略那样"没配过就不推"：域名的区域规则跟着域名配置走，域名一下发节点
// 就会按它判决，而判决用的那张表是节点上共用的另一样东西。新装节点出厂带的是编译进二进制
// 的那一份，管理员后来选的国家全都不在里面——不补发，规则就把所有访客查成"未知"。
func geoForTenant(ctx context.Context, db *sql.DB, p *master.Pusher, country *geo.DB, n *config.Node, res map[string]string) {
	if p == nil {
		return
	}
	plan, err := buildGeoPlan(ctx, db, country)
	if err != nil {
		res["geo"] = err.Error()
		return
	}
	per := geoPushNode(p, n, plan)
	if bad := geoPushError(per); bad != "" {
		res["geo"] = bad
		return
	}
	if s := asString(per["table"]); strings.HasPrefix(s, "skipped") {
		res["geo"] = s
		return
	}
	res["geo"] = "ok"
}

// geoOptions 回答租户页面的第一个问题：功能开没开、我能选哪些国家。
//
// selectable 原样报管理员划的范围，同时把"这些里哪些在库里真有网段"分出来报成 available：
// 两者不等时页面要能指出差集，否则租户选了个管理员划了但库覆盖不到的国家，
// 保存会被拒（见 cleanGeoPolicy），页面却只能显示一句"不在可选范围内"——那是误导。
func (h *securityHandler) geoOptions(w http.ResponseWriter, r *http.Request, tenantID string) {
	scope, saved, err := loadGeoScope(r.Context(), h.db)
	if err != nil {
		WriteError(w, err)
		return
	}
	codes, note := geoCountryCatalog(h.country)
	have := map[string]bool{}
	for _, c := range codes {
		have[c] = true
	}
	available := make([]string, 0, len(scope.Selectable))
	unavailable := []string{}
	for _, c := range scope.Selectable {
		if have[c] {
			available = append(available, c)
		} else {
			unavailable = append(unavailable, c)
		}
	}
	// 本代理已经用上的国家：页面据此把"别的域名已经在封这些"显示出来，
	// 免得租户重复配一份或误以为改一个地方就改了全网。
	used, err := tenantGeoCountries(r.Context(), h.db, tenantID)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"enabled":      scope.Enabled,
		"saved":        saved,
		"selectable":   scope.Selectable,
		"available":    available,
		"unavailable":  unavailable,
		"catalog":      codes,
		"catalog_note": note,
		"db_ready":     h.country.Ready(),
		"used":         used,
		"note":         geoTenantNote(scope, h.country, note),
	})
}

// geoTenantNote 把"这个功能现在到底能不能用"说成一句人话。
// 页面顶部只留一句，不要让运维从三个布尔值里自己推。
func geoTenantNote(scope geo.Scope, country *geo.DB, catalogNote string) string {
	switch {
	case !scope.Enabled:
		return "平台还没开启区域封禁：域名上可以先把规则存成未启用，开启后即可生效。"
	case !country.Ready():
		return "平台已开启，但国家级地理库未就位，规则还无法生效（需管理员安装 DB-IP Country Lite）。"
	case catalogNote != "":
		return "地理库不完整：" + catalogNote
	default:
		return ""
	}
}

// tenantGeoCountries 列出本代理所有域名上启用中的区域规则用到的国家（去重排序）。
func tenantGeoCountries(ctx context.Context, db *sql.DB, tenantID string) ([]string, error) {
	rows, err := db.QueryContext(ctx, `SELECT geo_policy FROM domains WHERE tenant_id = ? AND enabled`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var policies []geo.Policy
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "{}" {
			continue
		}
		var p geo.Policy
		if err := json.Unmarshal(raw, &p); err != nil {
			// 坏值只跳过这一行：一个绕过接口写进来的脏值不该让整个配置页打不开。
			continue
		}
		if p.Enabled {
			policies = append(policies, p)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := geo.CountriesFrom(policies...)
	sort.Strings(out)
	return out, nil
}

// geoStats 是本代理各节点的区域判决读数。
//
// 最有用的一列是 matches_plan_fingerprint：它比的是"面板这张表"与"这台节点网卡上那张表"。
// 下发时某节点不在线、或者它还是个没升级的旧 cdnedge，只有这一列能看出来。
// 计数按判决来由分开报，尤其"归属未知"必须单列：那是区域规则唯一放行的口子，
// 也是"我只封了 A 国，为什么 B 国访客也进不来"这类工单唯一能自证的地方。
func (h *securityHandler) geoStats(w http.ResponseWriter, r *http.Request, tenantID string) {
	nodes, ok := h.nodes(w, r, tenantID)
	if !ok {
		return
	}
	plan, err := buildGeoPlan(r.Context(), h.db, h.country)
	if err != nil {
		WriteError(w, err)
		return
	}
	type nodeRow struct {
		Node         string   `json:"node"`
		IP           string   `json:"ip"`
		Loaded       bool     `json:"loaded"`
		Fingerprint  string   `json:"fingerprint,omitempty"`
		Total        int      `json:"total"`
		Countries    []string `json:"countries,omitempty"`
		ScopeEnabled bool     `json:"scope_enabled"`
		L4Armed      bool     `json:"l4_armed"`
		L4Want       bool     `json:"l4_want"`
		L4Dropped    uint64   `json:"l4_dropped"`
		TableError   string   `json:"table_error,omitempty"`
		L4Error      string   `json:"l4_error,omitempty"`
		Reported     string   `json:"reported_at,omitempty"`
		Matches      *bool    `json:"matches_plan_fingerprint"`
		Error        string   `json:"error,omitempty"`
	}
	rs := reportField[geo.Readings](nodes, reportGeoStats)
	items := make([]nodeRow, 0, len(rs))
	var counters geo.Counters
	byCountry := map[string]*geo.CountryCount{}
	for _, x := range rs {
		it := nodeRow{Node: nodeLabel(x.Node), IP: x.Node.IP}
		if x.Err != nil {
			it.Error = x.Err.Error()
			items = append(items, it)
			continue
		}
		d := x.Data
		it.Loaded = d.Table.Loaded
		it.Fingerprint = d.Table.Fingerprint
		it.Total = d.Table.Total
		it.Countries = d.Table.Countries
		it.ScopeEnabled = d.ScopeEnabled
		it.L4Armed = d.L4.Armed
		it.L4Want = d.L4.Want
		it.L4Dropped = d.L4.Dropped
		it.TableError = d.Table.Error
		it.L4Error = d.L4.Error
		it.Reported = d.At
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
		if plan.Table != nil {
			m := it.Loaded && it.Fingerprint == plan.Table.Fingerprint
			it.Matches = &m
		}
		items = append(items, it)
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
	writeJSON(w, http.StatusOK, map[string]any{
		"counters":             counters,
		"countries":            list,
		"nodes":                items,
		"errors":               collectErrors(rs),
		"expected_fingerprint": planFingerprint(plan),
		"expected_total":       planTotal(plan),
		"expected_countries":   plan.Countries,
		"notes":                plan.Notes,
		"report_interval_secs": 10,
		"scope_enabled":        plan.Scope.Enabled,
		"db_ready":             h.country.Ready(),
	})
}
