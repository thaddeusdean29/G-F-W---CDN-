package apiv2

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"cdn/internal/geo"
)

// ---------------------------------------------------------------------------
// 区域封禁（按国家）控制面。
//
// 两层配置，一份判定：
//   - 平台管理员那一份（platform_settings 的 "geo_scope"）定能力总闸、租户可选的国家范围，
//     以及整节点的四层丢包策略。四层看不到 HTTP host，所以它按节点生效、不可能按域名生效，
//     这也是它只能由管理员维护的原因。
//   - 每个域名一份（domains.geo_policy），租户在自己域名上选国家清单。可选范围受管理员那份限制。
//
// 两边存的都是 geo.Policy 序列化后的字节，而边缘解出来的也是同一个结构体：
// 本项目已经吃过一次"面板存了一份节点其实不认的配置"的亏（WAF 的 normalize 静默改值），
// 所以这里非法值一律 400 拒绝、不纠正，且下发前后比指纹。
// ---------------------------------------------------------------------------

const settingGeoScope = "geo_scope"

// loadGeoScope 读出平台范围。没保存过返回 DefaultScope() 和 saved=false：
// 管理员没碰过这个功能时，能力总闸是关的、四层策略是观察且不丢任何包，
// 与升级到这一版之前的行为完全一致。
func loadGeoScope(ctx context.Context, db *sql.DB) (geo.Scope, bool, error) {
	s := geo.DefaultScope()
	var raw []byte
	err := db.QueryRowContext(ctx, `SELECT value FROM platform_settings WHERE name = ?`, settingGeoScope).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return s, false, nil
	}
	if err != nil {
		return s, false, err
	}
	// 用指针区分"当年没存这个键"和"存了但清空"，理由和 branding 的 login_features 一样：
	// 直接解进值类型会让"管理员显式选了空范围"读回来变成默认值。
	var saved struct {
		Enabled    *bool         `json:"enabled"`
		Selectable *[]string     `json:"selectable"`
		Node       *geoPolicyRaw `json:"node"`
	}
	if err := json.Unmarshal(raw, &saved); err != nil {
		return s, false, err
	}
	if saved.Enabled != nil {
		s.Enabled = *saved.Enabled
	}
	if saved.Selectable != nil {
		s.Selectable = *saved.Selectable
	}
	if saved.Node != nil {
		s.Node = saved.Node.Policy
	}
	s.Node = s.Node.WithDefaults()
	s.Normalize()
	return s, true, nil
}

func saveGeoScope(ctx context.Context, db *sql.DB, s geo.Scope) error {
	raw, err := json.Marshal(s)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `INSERT INTO platform_settings (name, value) VALUES (?, ?)
		ON DUPLICATE KEY UPDATE value = VALUES(value)`, settingGeoScope, raw)
	return err
}

// geoPolicyRaw 让 geo.Policy 能作为 Scope.Node 的可选键解出来（指针区分没写过）。
type geoPolicyRaw struct {
	geo.Policy
}

func (r *geoPolicyRaw) UnmarshalJSON(b []byte) error {
	p, err := decodeGeoPolicyJSON(b)
	if err != nil {
		return err
	}
	r.Policy = p
	return nil
}

// decodeGeoPolicyJSON 严格解析：出现未知字段就拒绝。
// 放过去等于允许"拼错的字段名"存进库里并让节点按默认值跑——面板上看着配好了，
// 边缘其实什么都没做，而且没有任何一处会报错。
func decodeGeoPolicyJSON(b []byte) (geo.Policy, error) {
	var p geo.Policy
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return p, err
	}
	return p, nil
}

// geoFieldError 把 geo 层的字段级拒绝原因包成 API 错误。原因必须逐字段给：
// 一次改十几项配置，只说"不合法"等于让调用方逐字节猜。
func geoFieldError(msg string, f geo.FieldErrors) error {
	return NewApiError("validation_failed", msg).WithDetails(map[string]any{"fields": map[string]string(f)})
}

// cleanGeoPolicy 校验一份域名级区域规则，返回解出来的策略与要入库的字节。
// 返回的是规范化之后重新序列化的 JSON（大写国家码、排序去重、CIDR 补掩码），
// 于是"库里存的""面板显示的""节点解出来的"三段是同一串字节。
//
// 四道关都在碰库之前，且都是拒绝而不是纠正：
//   - 未知字段（拼错的 action 存进库、节点按默认值跑，两边就分叉了）；
//   - 国家不在管理员划的范围内；
//   - 平台总闸关着 —— 域名上"启用了"但主控根本不下发，面板那句已封禁是假的；
//   - 库没就位或这个国家在库里一条网段都没有 —— 编不出前缀，边缘查什么都算"未知"，
//     allow 会把所有人拦掉、deny 会一个人也拦不住。这一条尤其不能放行，因为它看起来一切正常。
func cleanGeoPolicy(raw []byte, scope geo.Scope, country *geo.DB) (geo.Policy, json.RawMessage, error) {
	p, err := decodeGeoPolicyJSON(raw)
	if err != nil {
		return p, nil, NewApiError("validation_failed", "geo_policy 格式不正确: "+err.Error())
	}
	p.Normalize()
	if bad := geo.ValidatePolicy(p, scope.Selectable); !bad.OK() {
		return p, nil, geoFieldError("区域规则不合法", bad)
	}
	if p.Enabled {
		if !scope.Enabled {
			return p, nil, NewApiError("validation_failed", "平台还没开启区域封禁，域名上开不了：请先让管理员在区域封禁范围页开启总闸").
				WithDetails(map[string]any{"fields": map[string]string{"geo_policy.enabled": "平台区域封禁总闸未开"}})
		}
		if !country.Ready() {
			return p, nil, NewApiError("unavailable", "国家级地理库未就位（"+geo.FileIPv4+" / "+geo.FileIPv6+
				"），装不出前缀表就没有判决依据：这条规则现在开了也不会生效").
				WithDetails(map[string]any{"fields": map[string]string{"geo_policy.enabled": "地理库未就位"}})
		}
		missing, scanErr := geoUncataloged(country, p.Countries)
		if scanErr != "" {
			return p, nil, NewApiError("unavailable", "国家级地理库读不出国家目录，无法确认这些国家有没有可下发的网段: "+scanErr)
		}
		if len(missing) > 0 {
			return p, nil, NewApiError("validation_failed", "库里没有这些国家的网段，封了也拦不到任何地址: "+strings.Join(missing, "、")).
				WithDetails(map[string]any{"fields": map[string]string{"geo_policy.countries": "无可用网段: " + strings.Join(missing, "、")}})
		}
	}
	out, err := json.Marshal(p)
	if err != nil {
		return p, nil, err
	}
	return p, json.RawMessage(out), nil
}

// geoUncataloged 挑出 codes 里"库里一条网段都没有"的那些。
//
// 为什么单独立一条检查：Compile 只按清单取段，库里没有的国家会安静地一个段都不出，
// 于是那条规则永远命中不了——面板上"已封禁 BR"和实际拦住 0 个地址成了同一句话。
// 保存时就拒掉，比下发后靠读数反推便宜得多。
func geoUncataloged(d *geo.DB, codes []string) (missing []string, scanErr string) {
	if d == nil || !d.Ready() || len(codes) == 0 {
		return nil, ""
	}
	have := map[string]bool{}
	for _, c := range d.CountryCodes() {
		have[c] = true
	}
	if e := d.CountryCodesErr(); e != "" {
		return nil, e
	}
	for _, c := range codes {
		if !have[strings.ToUpper(strings.TrimSpace(c))] {
			missing = append(missing, c)
		}
	}
	return missing, ""
}

// cleanDomainGeoPolicy 是域名写入路径上的那一道校验：先把平台范围读出来（它决定
// 总闸与可选国家），再走 cleanGeoPolicy。范围读不出来就报错，不降级成"当作没开"：
// 那样一次数据库抖动就能让一条启用中的规则被改写成禁用并落库。
func cleanDomainGeoPolicy(ctx context.Context, db *sql.DB, country *geo.DB, raw json.RawMessage) (geo.Policy, json.RawMessage, error) {
	scope, _, err := loadGeoScope(ctx, db)
	if err != nil {
		return geo.DefaultPolicy(), nil, err
	}
	return cleanGeoPolicy(raw, scope, country)
}

// geoPolicyForResponse 把库里的字节回显成完整策略对象（补齐没写过的字段）。
// 这里不直接抛原始字节，是为了让面板永远拿到一份能照原样 PUT 回来的配置；
// 存量域名的 {} 回显成 {enabled:false, mode:"observe", action:"deny", ...} 才是真话。
func geoPolicyForResponse(raw json.RawMessage) geo.Policy {
	if len(bytes.TrimSpace(raw)) == 0 || string(bytes.TrimSpace(raw)) == "null" {
		return geo.DefaultPolicy()
	}
	p, err := decodeGeoPolicyJSON(raw)
	if err != nil {
		// 解不动只可能是绕过接口写进库的（带未知字段或类型错）。这里不能 500 掉整个域名列表，
		// 但也不能显示默认值假装一切正常：把原因写进 enabled=false 之外的字段，页面会显示"配置无法读取"。
		return geo.Policy{Mode: "invalid: " + err.Error(), Action: geo.ActionDeny, Countries: []string{}, Exceptions: []string{}}
	}
	return p.WithDefaults()
}

// geoCountryCatalog 列出库里有前缀可发的国家码，供管理员划范围时挑。
// 只给"这个库里真有 IP 段"的那些，给一堆选了就下发不出前缀的国家没有意义。
// 库没就位时返回空清单 + 原因，页面据此显示"没地理库"而不是"一个国家都没有"。
func geoCountryCatalog(db *geo.DB) (codes []string, note string) {
	if db == nil || !db.Ready() {
		return nil, "国家级地理库未就位：区域规则无法编译，请先安装 " + strings.Join([]string{geo.FileIPv4, geo.FileIPv6}, " / ")
	}
	var haveV4, haveV6 = db.Available()
	var missing []string
	if !haveV4 {
		missing = append(missing, geo.FileIPv4)
	}
	if !haveV6 {
		missing = append(missing, geo.FileIPv6)
	}
	if len(missing) > 0 {
		note = "缺少：" + strings.Join(missing, "、") + "（另一个家族仍可用）"
	}
	// 目录 = 全量国家码。Compile 只按清单取段，所以这里要的是"库里都有哪些码"，
	// 用一个覆盖全部码的编译结果代价太大（59 万段），改为直接问库要码表。
	return db.CountryCodes(), note
}
