package apiv2

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"

	"cdn/internal/cloudflare"
	"cdn/internal/config"
	"cdn/internal/geo"
	"cdn/internal/master"
)

type domainsHandler struct {
	repo        *DomainRepo
	clusterRepo *ClusterRepo
	jobRepo     *JobRepo
	pusher      *master.Pusher
	nodeRepo    *NodeRepo
	db          *sql.DB
	// country 是国家级地理库（DB-IP Country Lite），区域规则的表由它编译。
	// 两个库文件都没就位时它仍是非 nil（Ready() 为 false）：那时保存域名区域规则
	// 会直接拒绝并说明原因，而不是存下去让节点查成"未知"。
	country *geo.DB
	// acmeDir 是签发证书用的 ACME directory URL（config.json 的 acme_directory），
	// 空串表示 Let's Encrypt 正式环境。
	acmeDir string
}

// domainNameRe 与 internal/config/validator.go 的 domainRe 同规则，独立复制一份而不是导入
// internal/config：apiv2 是全新的存储层，不应该依赖 v1 的业务包。
var domainNameRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
var domainTTLRe = regexp.MustCompile(`^\d+[smhd]$`)

// cacheExtRe 限定单个缓存扩展名的取值。它是边缘渲染守卫（internal/tengine/confguard.go 的
// renderExtRe）的服务端镜像：扩展名最终会逐字拼进站点配置的 location 正则里，
// 所以这里不放行的字符在边缘也不可能出现。平台默认规则（defaultCacheRules）全部落在
// 这个字符集内，见 cache_default_test.go。
var cacheExtRe = regexp.MustCompile(`^[A-Za-z0-9]{1,10}$`)

type domainUpstream struct {
	Address string `json:"address"`
	Weight  int    `json:"weight"`
}

type domainCacheRule struct {
	Extensions []string `json:"extensions"`
	TTL        string   `json:"ttl"`
	Enabled    bool     `json:"enabled"`
}

type domainSSL struct {
	Mode          string  `json:"mode"`
	CertificateID *string `json:"certificate_id"`
	ForceHTTPS    bool    `json:"force_https"`
}

// validateUpstreams 校验并规范化 upstreams（docs/API-v2.md §2.1：至少 1 条，weight 1-100）。
func validateUpstreams(raw json.RawMessage) (json.RawMessage, error) {
	var ups []domainUpstream
	if err := json.Unmarshal(raw, &ups); err != nil {
		return nil, NewApiError("validation_failed", "upstreams 格式不正确")
	}
	if len(ups) == 0 {
		return nil, NewApiError("validation_failed", "upstreams 至少需要 1 条").
			WithDetails(map[string]any{"fields": map[string]string{"upstreams": "至少 1 条"}})
	}
	for i, u := range ups {
		// 用户常把源站写成 http://1.2.3.4/ ：upstream server 不认协议和路径，tengine -t 失败会连累整台节点。
		addr := strings.TrimSpace(u.Address)
		addr = strings.TrimPrefix(strings.TrimPrefix(addr, "http://"), "https://")
		addr = strings.TrimRight(addr, "/")
		if strings.ContainsAny(addr, " \t\r\n;{}/#\"'") {
			return nil, NewApiError("validation_failed", "upstreams address 只能是 IP、域名或 IP:端口").
				WithDetails(map[string]any{"fields": map[string]string{"upstreams[" + itoa(i) + "].address": "格式不正确"}})
		}
		ups[i].Address = addr
		u.Address = addr
		if u.Address == "" {
			return nil, NewApiError("validation_failed", "upstreams 缺少 address").
				WithDetails(map[string]any{"fields": map[string]string{"upstreams[" + itoa(i) + "].address": "必填"}})
		}
		if u.Weight < 1 || u.Weight > 100 {
			return nil, NewApiError("validation_failed", "upstreams weight 必须在 1-100 之间").
				WithDetails(map[string]any{"fields": map[string]string{"upstreams[" + itoa(i) + "].weight": "必须在 1-100 之间"}})
		}
	}
	return json.Marshal(ups)
}

// validateCacheRules 校验并规范化 cache_rules；空数组合法（docs：使用平台默认）。
func validateCacheRules(raw json.RawMessage) (json.RawMessage, error) {
	var rules []domainCacheRule
	if err := json.Unmarshal(raw, &rules); err != nil {
		return nil, NewApiError("validation_failed", "cache_rules 格式不正确")
	}
	for i, rule := range rules {
		if len(rule.Extensions) == 0 {
			return nil, NewApiError("validation_failed", "cache_rules 缺少 extensions").
				WithDetails(map[string]any{"fields": map[string]string{"cache_rules[" + itoa(i) + "].extensions": "必填"}})
		}
		for j, ext := range rule.Extensions {
			// 控制台在客户端做过同样的清洗（DomainsView.vue：去掉前导点并转小写），这里补齐服务端：
			// 直接打 API 的调用方给的是脏值也必须落库成同一个形态。
			ext = strings.ToLower(strings.TrimSpace(ext))
			ext = strings.TrimPrefix(ext, ".")
			// 与 internal/tengine/confguard.go 的 renderExtRe 同规则（两边独立复制，理由见 domainNameRe 上方注释）。
			// 这里是第一道门，边缘那道是兜底：扩展名会被逐字拼进 location ~* \.(...)$ 的正则体，
			// 放 ".*" 过去等于把整站流量降进静态赛道（丢掉 Lua 上传拦截、limit_req 与挑战跳转），
			// 放换行加大括号过去等于在自己的站点里开出新 location——tengine -t 只判语法，
			// 括号配平就 reload 生效。
			if !cacheExtRe.MatchString(ext) {
				return nil, NewApiError("validation_failed", "cache_rules extensions 只能是 1-10 个字母或数字（如 jpg、png、woff2、mp4）").
					WithDetails(map[string]any{"fields": map[string]string{"cache_rules[" + itoa(i) + "].extensions[" + itoa(j) + "]": "只能包含字母和数字，不需要前导点"}})
			}
			rules[i].Extensions[j] = ext
		}
		if !domainTTLRe.MatchString(strings.TrimSpace(rule.TTL)) {
			return nil, NewApiError("validation_failed", "cache_rules ttl 格式不正确（如 30d、7d、1h、60m）").
				WithDetails(map[string]any{"fields": map[string]string{"cache_rules[" + itoa(i) + "].ttl": "格式不正确"}})
		}
	}
	return json.Marshal(rules)
}

// validateSSL 校验并规范化 ssl 子对象（docs/API-v2.md §2.1：manual 模式必须带 certificate_id）。
//
// mode 只有 off / manual 两种：以前还接受 "auto"，但面板从来没有实现自动签发，"auto" 落到
// convertDomainToConfig 会被当成"未启用 HTTPS"（边缘没有 autocert，照发会让模板引用空证书路径，
// tengine -t 失败连累整台节点）——等于一个看起来开了、实际什么都没开的开关。现在自助签发走
// POST /domains/:id/certificate/acme，签完落成 manual，所以 "auto" 从写入接口里删掉；
// 存量 "auto" 在读取时按 off 处理，不做静默降级。
func validateSSL(raw json.RawMessage) (json.RawMessage, error) {
	var s domainSSL
	if err := json.Unmarshal(raw, &s); err != nil {
		return nil, NewApiError("validation_failed", "ssl 格式不正确")
	}
	switch s.Mode {
	case "auto":
		// 升级前存过 "auto" 的行，前端原样回传时不该被拒：它从来就是 off。
		s.Mode = "off"
		fallthrough
	case "off":
	case "manual":
		if s.CertificateID == nil || *s.CertificateID == "" {
			return nil, NewApiError("validation_failed", "ssl.mode 为 manual 时 certificate_id 必填").
				WithDetails(map[string]any{"fields": map[string]string{"ssl.certificate_id": "必填"}})
		}
	default:
		return nil, NewApiError("validation_failed", "ssl.mode 必须是 off/manual 之一")
	}
	// 全部域名强制 HTTPS（边缘模板无条件输出 80 → 301），该字段只读，传什么都存 true。
	s.ForceHTTPS = true
	return json.Marshal(s)
}

// validateTags 校验 tags 是字符串数组。是否存在于 /tags 列表由 Stage 3 tags 资源落地后补充，
// 首版先只做格式校验，不做跨资源存在性检查。
func validateTags(raw json.RawMessage) (json.RawMessage, error) {
	var tags []string
	if err := json.Unmarshal(raw, &tags); err != nil {
		return nil, NewApiError("validation_failed", "tags 必须是字符串数组")
	}
	for _, t := range tags {
		if t == "" {
			return nil, NewApiError("validation_failed", "tags 不能包含空字符串")
		}
	}
	return json.Marshal(tags)
}

// validateJSONObject 只校验 raw 是一个 JSON 对象，原样返回。用于 cc_policy——完整校验其全部
// 子字段是 internal/config/validator.go 里一大段 v1 逻辑的重复，首版先做透传存储，
// 子字段级校验留给后续按需补充。
func validateJSONObject(raw json.RawMessage, field string) (json.RawMessage, error) {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, NewApiError("validation_failed", field+" 必须是 JSON 对象")
	}
	return raw, nil
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

var domainSortColumns = map[string]string{"created_at": "created_at", "domain": "domain"}
var domainCreateFields = []string{"domain", "cluster_id", "origin_scheme", "upstreams", "cache_rules", "ssl", "tags", "defense_cname", "cc_policy", "geo_policy", "enabled", "static_public"}
var domainWritableFields = []string{"cluster_id", "origin_scheme", "upstreams", "cache_rules", "ssl", "tags", "defense_cname", "cc_policy", "geo_policy", "enabled", "static_public"}
var domainReadonlyFields = []string{"id", "verification", "dns", "sync", "version", "created_at", "updated_at"}

type domainVerification struct {
	Status      string  `json:"status"`
	RecordName  string  `json:"record_name"`
	RecordValue string  `json:"record_value"`
	VerifiedAt  *string `json:"verified_at"`
}

type domainDNS struct {
	CNAMETarget       *string `json:"cname_target"`
	OnDefense         bool    `json:"on_defense"`
	DefenseByFailover bool    `json:"defense_by_failover"`
	ActiveTarget      *string `json:"active_target"`
}

type domainSync struct {
	State      string            `json:"state"`
	CFMessage  string            `json:"cf_message"`
	EdgeFailed map[string]string `json:"edge_failed"`
	SyncedAt   *string           `json:"synced_at"`
}

// domainResponse 是 docs/API-v2.md §2.1 定义的对外 JSON 形状。gateway_profile、cname_record_id、
// main_subdomain_record_id、edge_record_ids、cloudflare_proxy_id 不再返回（docs 明确列出的排除项）。
type domainResponse struct {
	ID           string          `json:"id"`
	Domain       string          `json:"domain"`
	ClusterID    *string         `json:"cluster_id"`
	OriginScheme string          `json:"origin_scheme"`
	Upstreams    json.RawMessage `json:"upstreams"`
	CacheRules   json.RawMessage `json:"cache_rules"`
	SSL          json.RawMessage `json:"ssl"`
	Enabled      bool            `json:"enabled"`
	// StaticPublic 回显的是服务端当前状态，不是"前端传了什么"：这个开关关掉之后静态赛道
	// 才会重新挂上逐请求审计，租户必须能从 API 里确证边缘上真实生效的是哪一档。
	StaticPublic bool            `json:"static_public"`
	Tags         json.RawMessage `json:"tags"`
	DefenseCNAME string          `json:"defense_cname"`
	CCPolicy     json.RawMessage `json:"cc_policy"`
	// GeoPolicy 回显的是服务端真实生效的那一份（缺字段补默认值），不是库里原始的字节：
	// 存量域名存的是 {}，照原样抛回去会让面板显示成一个空策略而无法判断"到底是没配还是配了"。
	GeoPolicy geo.Policy `json:"geo_policy"`
	// GeoPush 只在本次写入带了 geo_policy 时出现，回的是这次下发的逐节点结果：
	// domain_config 是域名配置（geo_policy 就在里面，边缘判定读的是它），
	// per_node/fingerprint 是前缀表。规则要生效这两样都得到位——表没补发到位，
	// 新选的国家会被查成"归属未知"然后放行；配置没发下去，边缘还在按上一份规则判。
	GeoPush      map[string]any     `json:"geo_push,omitempty"`
	Verification domainVerification `json:"verification"`
	DNS          domainDNS          `json:"dns"`
	Sync         domainSync         `json:"sync"`
	Version      int                `json:"version"`
	CreatedAt    string             `json:"created_at"`
	UpdatedAt    string             `json:"updated_at"`
}

// renderDomain 把 DB 行渲染成 API 响应。sync.state 目前只在 pending/error 之间取值——
// CF 同步与边缘下发要到 Stage 2b/3 才真正实现，这里如实反映当前能力，不伪造 "synced"。
func renderDomain(d *Domain) domainResponse {
	var clusterID *string
	if d.ClusterID.Valid {
		clusterID = &d.ClusterID.String
	}

	verification := domainVerification{
		Status:      "pending",
		RecordName:  "_cdn-verify." + d.Domain,
		RecordValue: d.VerifyToken,
	}
	if d.VerifiedAt.Valid {
		verification.Status = "verified"
		s := d.VerifiedAt.Time.UTC().Format(rfc3339Milli)
		verification.VerifiedAt = &s
	}

	var cnameTarget *string
	if d.CNAMERecord != "" {
		cnameTarget = &d.CNAMERecord
	}

	syncState := "pending"
	if d.CFMessage != "" {
		syncState = "error"
	}

	return domainResponse{
		ID:           d.ID,
		Domain:       d.Domain,
		ClusterID:    clusterID,
		OriginScheme: d.OriginScheme,
		Upstreams:    rawOrEmptyArray(d.Upstreams),
		CacheRules:   rawOrEmptyArray(d.CacheRules),
		SSL:          rawOrEmptyObject(d.SSLConfig),
		Enabled:      d.Enabled,
		StaticPublic: d.StaticPublic,
		Tags:         rawOrEmptyArray(d.Tags),
		DefenseCNAME: d.DefenseCNAME,
		CCPolicy:     rawOrEmptyObject(d.CCPolicy),
		GeoPolicy:    geoPolicyForResponse(d.GeoPolicy),
		Verification: verification,
		DNS: domainDNS{
			CNAMETarget:       cnameTarget,
			OnDefense:         d.OnDefense,
			DefenseByFailover: d.DefenseByFailover,
			ActiveTarget:      nil,
		},
		Sync: domainSync{
			State:      syncState,
			CFMessage:  d.CFMessage,
			EdgeFailed: map[string]string{},
		},
		Version:   d.Version,
		CreatedAt: d.CreatedAt.UTC().Format(rfc3339Milli),
		UpdatedAt: d.UpdatedAt.UTC().Format(rfc3339Milli),
	}
}

func rawOrEmptyArray(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("[]")
	}
	return raw
}

func rawOrEmptyObject(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("{}")
	}
	return raw
}

func (h *domainsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info := SessionFromContext(r.Context())

	if r.URL.Path == "/api/v2/domains" {
		switch r.Method {
		case http.MethodGet:
			h.list(w, r, info.TenantID)
		case http.MethodPost:
			h.create(w, r, info.TenantID)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, "/api/v2/domains/")
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	if id == "" {
		WriteError(w, NewApiError("not_found", "未找到该资源"))
		return
	}
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			h.get(w, r, info.TenantID, id)
		case http.MethodPatch:
			h.patch(w, r, info.TenantID, id)
		case http.MethodDelete:
			h.delete(w, r, info.TenantID, id)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	switch {
	case parts[1] == "verification" && r.Method == http.MethodGet:
		h.verification(w, r, info.TenantID, id)
	case parts[1] == "verify" && r.Method == http.MethodPost:
		h.verify(w, r, info.TenantID, id)
	case parts[1] == "purge" && r.Method == http.MethodPost:
		h.purge(w, r, info.TenantID, id)
	case parts[1] == "resync" && r.Method == http.MethodPost:
		h.resync(w, r, info.TenantID, id)
	case parts[1] == "switch-to-defense" && r.Method == http.MethodPost:
		h.switchToDefense(w, r, info.TenantID, id)
	case parts[1] == "switch-to-cluster" && r.Method == http.MethodPost:
		h.switchToCluster(w, r, info.TenantID, id)
	case parts[1] == "certificate":
		h.certificate(w, r, info.TenantID, id)
	case parts[1] == "certificate/acme" && r.Method == http.MethodPost:
		h.issueCertificate(w, r, info.TenantID, id)
	default:
		WriteError(w, NewApiError("not_found", "未找到该资源"))
	}
}

func (h *domainsHandler) list(w http.ResponseWriter, r *http.Request, tenantID string) {
	page, pageSize := parsePagination(r)
	orderBy := parseSort(r, domainSortColumns, "created_at")
	var enabledFilter *bool
	if v := r.URL.Query().Get("enabled"); v != "" {
		b := v == "true" || v == "1"
		enabledFilter = &b
	}
	domains, total, err := h.repo.List(r.Context(), tenantID, r.URL.Query().Get("cluster_id"), r.URL.Query().Get("tag"),
		enabledFilter, r.URL.Query().Get("q"), orderBy, page, pageSize)
	if err != nil {
		WriteError(w, err)
		return
	}
	items := make([]domainResponse, 0, len(domains))
	for _, d := range domains {
		items = append(items, renderDomain(d))
	}
	writeList(w, items, total, page, pageSize)
}

type domainWriteRequest struct {
	Domain       *string         `json:"domain"`
	ClusterID    *string         `json:"cluster_id"`
	OriginScheme *string         `json:"origin_scheme"`
	Upstreams    json.RawMessage `json:"upstreams"`
	CacheRules   json.RawMessage `json:"cache_rules"`
	SSL          json.RawMessage `json:"ssl"`
	Tags         json.RawMessage `json:"tags"`
	DefenseCNAME *string         `json:"defense_cname"`
	CCPolicy     json.RawMessage `json:"cc_policy"`
	GeoPolicy    json.RawMessage `json:"geo_policy"`
	Enabled      *bool           `json:"enabled"`
	StaticPublic *bool           `json:"static_public"`
}

func (h *domainsHandler) create(w http.ResponseWriter, r *http.Request, tenantID string) {
	body, _, err := decodeKnownFields(r, domainCreateFields)
	if err != nil {
		WriteError(w, err)
		return
	}
	var req domainWriteRequest
	if err := json.Unmarshal(body, &req); err != nil {
		WriteError(w, NewApiError("invalid_json", "请求体不是合法 JSON"))
		return
	}
	if req.Domain == nil || *req.Domain == "" || !domainNameRe.MatchString(*req.Domain) {
		WriteError(w, NewApiError("validation_failed", "domain 必须是合法域名").
			WithDetails(map[string]any{"fields": map[string]string{"domain": "必须是合法域名"}}))
		return
	}
	if req.Upstreams == nil {
		WriteError(w, NewApiError("validation_failed", "upstreams 为必填字段").
			WithDetails(map[string]any{"fields": map[string]string{"upstreams": "必填"}}))
		return
	}
	upstreams, err := validateUpstreams(req.Upstreams)
	if err != nil {
		WriteError(w, err)
		return
	}

	d := &Domain{
		TenantID:     tenantID,
		Domain:       *req.Domain,
		OriginScheme: "http",
		Upstreams:    upstreams,
		CacheRules:   json.RawMessage("[]"),
		SSLConfig:    json.RawMessage(`{"mode":"off","certificate_id":null,"force_https":true}`),
		CCPolicy:     json.RawMessage("{}"),
		GeoPolicy:    json.RawMessage("{}"),
		Tags:         json.RawMessage("[]"),
		Enabled:      true,
	}
	if req.OriginScheme != nil {
		switch *req.OriginScheme {
		case "http", "https":
			d.OriginScheme = *req.OriginScheme
		default:
			WriteError(w, NewApiError("validation_failed", "origin_scheme 必须是 http 或 https"))
			return
		}
	}
	if req.CacheRules != nil {
		cacheRules, err := validateCacheRules(req.CacheRules)
		if err != nil {
			WriteError(w, err)
			return
		}
		d.CacheRules = cacheRules
	}
	if req.SSL != nil {
		ssl, err := validateSSL(req.SSL)
		if err != nil {
			WriteError(w, err)
			return
		}
		d.SSLConfig = ssl
	}
	if req.Tags != nil {
		tags, err := validateTags(req.Tags)
		if err != nil {
			WriteError(w, err)
			return
		}
		d.Tags = tags
	}
	if req.CCPolicy != nil {
		ccPolicy, err := validateJSONObject(req.CCPolicy, "cc_policy")
		if err != nil {
			WriteError(w, err)
			return
		}
		d.CCPolicy = ccPolicy
	}
	if req.GeoPolicy != nil {
		_, canonical, err := cleanDomainGeoPolicy(r.Context(), h.db, h.country, req.GeoPolicy)
		if err != nil {
			WriteError(w, err)
			return
		}
		d.GeoPolicy = canonical
	}
	if req.DefenseCNAME != nil {
		d.DefenseCNAME = *req.DefenseCNAME
	}
	if req.ClusterID != nil {
		d.ClusterID = sql.NullString{String: *req.ClusterID, Valid: *req.ClusterID != ""}
	}
	if req.Enabled != nil {
		d.Enabled = *req.Enabled
	}
	if req.StaticPublic != nil {
		d.StaticPublic = *req.StaticPublic
	}

	created, err := h.repo.Create(r.Context(), d)
	if err != nil {
		WriteError(w, err)
		return
	}
	resp := renderDomain(created)
	// 只有这次真的带了区域规则才下发：没带就等于这条规则没动，不该顺手推一份配置和 MB 级的表。
	if req.GeoPolicy != nil {
		resp.GeoPush = h.geoPushForDomain(r.Context(), tenantID, created)
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (h *domainsHandler) get(w http.ResponseWriter, r *http.Request, tenantID, id string) {
	d, err := h.repo.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	writeJSON(w, http.StatusOK, renderDomain(d))
}

func (h *domainsHandler) patch(w http.ResponseWriter, r *http.Request, tenantID, id string) {
	existing, err := h.repo.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}

	raw, err := readBody(r)
	if err != nil {
		WriteError(w, err)
		return
	}
	if bad := DisallowedFields(raw, append(domainReadonlyFields, "domain")); len(bad) > 0 {
		WriteError(w, readonlyFieldError(bad))
		return
	}
	if bad := UnknownFields(raw, domainWritableFields); len(bad) > 0 {
		WriteError(w, unknownFieldError(bad))
		return
	}

	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)

	// 以服务端当前行为底，只覆盖白名单里出现过的字段。逐字段手抄一份 existing 是漏字段的
	// 温床：新加一个可写列而忘了抄，PATCH 别的字段就会把它静默重置成零值（对
	// static_public 来说就是"改个标签把静态免检开关关回去了"）。整行拷贝后，能变的
	// 只有下面显式赋值的字段，新增列默认继承当前值；repo 的 UPDATE 也只写白名单列。
	d := *existing
	if raw, ok := fields["cluster_id"]; ok {
		v, err := parseNullableStringField(raw, "cluster_id")
		if err != nil {
			WriteError(w, err)
			return
		}
		d.ClusterID = v
	}
	if raw, ok := fields["origin_scheme"]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil || (s != "http" && s != "https") {
			WriteError(w, NewApiError("validation_failed", "origin_scheme 必须是 http 或 https"))
			return
		}
		d.OriginScheme = s
	}
	if raw, ok := fields["upstreams"]; ok {
		v, err := validateUpstreams(raw)
		if err != nil {
			WriteError(w, err)
			return
		}
		d.Upstreams = v
	}
	if raw, ok := fields["cache_rules"]; ok {
		v, err := validateCacheRules(raw)
		if err != nil {
			WriteError(w, err)
			return
		}
		d.CacheRules = v
	}
	if raw, ok := fields["ssl"]; ok {
		v, err := validateSSL(raw)
		if err != nil {
			WriteError(w, err)
			return
		}
		var ssl domainSSL
		_ = json.Unmarshal(v, &ssl)
		if ssl.Mode == "manual" {
			ok, err := certBelongsTo(r.Context(), h.db, tenantID, id, *ssl.CertificateID)
			if err != nil {
				WriteError(w, err)
				return
			}
			if !ok {
				WriteError(w, NewApiError("validation_failed", "certificate_id 不是该域名已上传的证书").
					WithDetails(map[string]any{"fields": map[string]string{"ssl.certificate_id": "证书不存在"}}))
				return
			}
		}
		d.SSLConfig = v
	}
	if raw, ok := fields["tags"]; ok {
		v, err := validateTags(raw)
		if err != nil {
			WriteError(w, err)
			return
		}
		d.Tags = v
	}
	if raw, ok := fields["cc_policy"]; ok {
		v, err := validateJSONObject(raw, "cc_policy")
		if err != nil {
			WriteError(w, err)
			return
		}
		d.CCPolicy = v
	}
	// geoPol 只在本次 PATCH 真的带了 geo_policy 时才是非 nil：没带就等于这条规则没动，
	// 不该顺手往节点推一份 MB 级的表。
	var geoPol *geo.Policy
	if raw, ok := fields["geo_policy"]; ok {
		pol, canonical, err := cleanDomainGeoPolicy(r.Context(), h.db, h.country, raw)
		if err != nil {
			WriteError(w, err)
			return
		}
		d.GeoPolicy = canonical
		geoPol = &pol
	}
	if raw, ok := fields["defense_cname"]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			WriteError(w, NewApiError("validation_failed", "defense_cname 必须是字符串"))
			return
		}
		d.DefenseCNAME = s
	}
	if raw, ok := fields["enabled"]; ok {
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			WriteError(w, NewApiError("validation_failed", "enabled 必须是布尔值"))
			return
		}
		d.Enabled = b
	}
	if raw, ok := fields["static_public"]; ok {
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			WriteError(w, NewApiError("validation_failed", "static_public 必须是布尔值"))
			return
		}
		d.StaticPublic = b
	}

	updated, err := h.repo.Update(r.Context(), tenantID, id, parseIfMatch(r), &d)
	if err != nil {
		WriteError(w, versionConflictOr(err))
		return
	}
	resp := renderDomain(updated)
	if geoPol != nil {
		resp.GeoPush = h.geoPushForDomain(r.Context(), tenantID, updated)
	}
	writeJSON(w, http.StatusOK, resp)
}

// delete 删除域名。CF 记录与边缘配置清理是异步副作用（docs §3.1），属于 Stage 2b Job 机制范围，
// 这里先只做落库，与 nodes.go/clusters.go 目前的实现深度一致。
func (h *domainsHandler) delete(w http.ResponseWriter, r *http.Request, tenantID, id string) {
	if err := h.repo.Delete(r.Context(), tenantID, id); err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type verificationDetail struct {
	RecordName  string `json:"record_name"`
	RecordType  string `json:"record_type"`
	RecordValue string `json:"record_value"`
	Status      string `json:"status"`
}

func (h *domainsHandler) verification(w http.ResponseWriter, r *http.Request, tenantID, id string) {
	d, err := h.repo.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	status := "pending"
	if d.VerifiedAt.Valid {
		status = "verified"
	}
	writeJSON(w, http.StatusOK, verificationDetail{
		RecordName:  "_cdn-verify." + d.Domain,
		RecordType:  "TXT",
		RecordValue: d.VerifyToken,
		Status:      status,
	})
}

// verify 立即查询 DNS TXT 记录完成所有权验证（docs/API-v2.md §3.1）。已验证过的域名再次调用
// 直接幂等返回当前状态，不重新查 DNS——没有必要,且 MarkVerified 本身也做了 IS NULL 兜底。
// DNS 查询失败（NXDOMAIN 或网络错误）统一按"未查到"处理返回 422 domain_unverified,
// 这里不区分具体失败原因,因为对调用方来说都是"验证还没成功",细分错误意义不大。
func (h *domainsHandler) verify(w http.ResponseWriter, r *http.Request, tenantID, id string) {
	d, err := h.repo.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	if d.VerifiedAt.Valid {
		writeJSON(w, http.StatusOK, renderDomain(d))
		return
	}

	name := "_cdn-verify." + d.Domain
	txts, lookupErr := net.DefaultResolver.LookupTXT(r.Context(), name)
	if lookupErr != nil {
		var dnsErr *net.DNSError
		_ = errors.As(lookupErr, &dnsErr)
		WriteError(w, NewApiError("domain_unverified", "未查询到验证 TXT 记录").
			WithDetails(map[string]any{"found": []string{}}))
		return
	}
	found := false
	for _, v := range txts {
		if v == d.VerifyToken {
			found = true
			break
		}
	}
	if !found {
		WriteError(w, NewApiError("domain_unverified", "TXT 记录内容不匹配").
			WithDetails(map[string]any{"found": txts}))
		return
	}

	updated, err := h.repo.MarkVerified(r.Context(), tenantID, id)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, renderDomain(updated))
}

// purge 对应 docs/API-v2.md §3.1 的 POST /domains/:id/purge：202 Job，并发通知域名所在
// 集群的全部节点清空该域名的边缘缓存（pusher.PurgeCluster）。域名未关联集群时没有节点
// 可以通知，422 cluster_missing。
func (h *domainsHandler) purge(w http.ResponseWriter, r *http.Request, tenantID, id string) {
	d, err := h.repo.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	// 未关联集群的域名会下发到本代理全部节点，所以清缓存也发给全部节点。
	clusterID := ""
	if d.ClusterID.Valid {
		clusterID = d.ClusterID.String
	}

	job, err := h.jobRepo.Create(r.Context(), tenantID, "domain.purge", "", nil)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJobAccepted(w, job)

	go func() {
		ctx := context.Background()
		_ = h.jobRepo.UpdateProgress(ctx, job.ID, 10, "正在清除边缘缓存...")
		results := h.fanout(ctx, tenantID, clusterID, func(n *config.Node) error {
			return h.pusher.PostToNode(n, "/edge/cache/purge", map[string]string{"domain": d.Domain})
		})
		resultJSON, _ := json.Marshal(results)
		failed := 0
		for _, msg := range results {
			if msg != "ok" {
				failed++
			}
		}
		if len(results) > 0 && failed == len(results) {
			_ = h.jobRepo.MarkFailed(ctx, job.ID, "全部节点清缓存失败")
			return
		}
		warning := ""
		if failed > 0 {
			warning = fmt.Sprintf("%d 个节点清缓存失败", failed)
		}
		_ = h.jobRepo.MarkDone(ctx, job.ID, resultJSON, warning)
	}()
}

// domainClusterSubdomain 查出域名所属集群并算出它在 Cloudflare 上对应的 subdomain
// （<cluster name>.<base domain>）。resync/switch-to-defense/switch-to-cluster 与 E 项的
// failover 都需要先拿到这个值才能调用 cf.SyncDomain/cf.PointSwitchTo。
func (h *domainsHandler) domainClusterSubdomain(ctx context.Context, cf *cloudflare.Client, tenantID string, d *Domain) (string, error) {
	sub, _, err := h.domainCluster(ctx, cf, tenantID, d)
	return sub, err
}

// domainCluster 同时返回域名生效的高防 CNAME：域名自己填了用自己的，否则用集群默认值。
func (h *domainsHandler) domainCluster(ctx context.Context, cf *cloudflare.Client, tenantID string, d *Domain) (subdomain, defense string, err error) {
	if !d.ClusterID.Valid || d.ClusterID.String == "" {
		return "", "", NewApiError("cluster_missing", "域名尚未关联集群")
	}
	cluster, err := h.clusterRepo.Get(ctx, tenantID, d.ClusterID.String)
	if err != nil {
		return "", "", notFoundOr(err)
	}
	return cf.ClusterSubdomain(cluster.Name), effectiveDefenseCNAME(d, cluster), nil
}

// resync 对应 docs/API-v2.md §3.1 的 POST /domains/:id/resync：202 Job，重新调用
// cf.SyncDomain 让域名的 CNAME 记录与当前 on_defense 状态保持一致（必要时重新分配记录），
// 落库 CF 返回的记录信息，再把最新域名配置下发到集群全部节点。
func (h *domainsHandler) resync(w http.ResponseWriter, r *http.Request, tenantID, id string) {
	d, err := h.repo.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	cf, err := tenantCF(r.Context(), h.db, tenantID)
	if err != nil {
		WriteError(w, err)
		return
	}
	if !cf.Enabled() {
		WriteError(w, NewApiError("cf_not_configured", "Cloudflare 未配置"))
		return
	}
	clusterSubdomain, defenseCNAME, err := h.domainCluster(r.Context(), cf, tenantID, d)
	if err != nil {
		WriteError(w, err)
		return
	}
	clusterID := d.ClusterID.String

	job, err := h.jobRepo.Create(r.Context(), tenantID, "domain.resync", "", nil)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJobAccepted(w, job)

	go func() {
		ctx := context.Background()
		_ = h.jobRepo.UpdateProgress(ctx, job.ID, 10, "正在重建 DNS 记录...")

		cd, err := convertDomainToConfig(d)
		if err != nil {
			_ = h.jobRepo.MarkFailed(ctx, job.ID, "转换域名配置失败: "+err.Error())
			return
		}
		if err := cf.SyncDomain(cd, clusterSubdomain, defenseCNAME); err != nil {
			_ = h.jobRepo.MarkFailed(ctx, job.ID, "同步 DNS 记录失败: "+err.Error())
			return
		}
		if err := h.repo.UpdateCFState(ctx, tenantID, id, cd.CNAMERecord, cd.CNAMERecordID, cd.MainSubdomainRecordID, cd.CFMessage); err != nil {
			_ = h.jobRepo.MarkFailed(ctx, job.ID, "保存 DNS 记录失败: "+err.Error())
			return
		}

		_ = h.jobRepo.UpdateProgress(ctx, job.ID, 60, "正在下发到边缘节点...")
		payload, err := domainPushPayload(ctx, h.db, d)
		if err != nil {
			_ = h.jobRepo.MarkFailed(ctx, job.ID, "构建下发配置失败: "+err.Error())
			return
		}
		// CF 同步刚写回的记录信息以 cd 为准。
		payload.CNAMERecord, payload.CNAMERecordID, payload.MainSubdomainRecordID, payload.CFMessage =
			cd.CNAMERecord, cd.CNAMERecordID, cd.MainSubdomainRecordID, cd.CFMessage
		results := h.fanout(ctx, tenantID, clusterID, func(n *config.Node) error {
			return h.pusher.PostToNode(n, "/edge/domains", payload)
		})
		resultJSON, _ := json.Marshal(results)
		failed := 0
		for _, msg := range results {
			if msg != "ok" {
				failed++
			}
		}
		var warnings []string
		if failed > 0 {
			warnings = append(warnings, fmt.Sprintf("%d 个节点下发失败", failed))
		}
		// 全部域名强制 HTTPS：没启用证书时 443 落到 default_server（return 444），浏览器报
		// ERR_EMPTY_RESPONSE。下发本身是成功的，但必须告诉用户站点实际不可用。
		if !payload.Domain.SSL.Enabled {
			if cd.SSL.Enabled {
				warnings = append(warnings, "证书读取失败，已按未启用 HTTPS 下发，请重新上传证书")
			} else {
				warnings = append(warnings, "该域名未启用 HTTPS（未上传证书或已关闭），访问会被拒绝")
			}
		}
		_ = h.jobRepo.MarkDone(ctx, job.ID, resultJSON, strings.Join(warnings, "；"))
	}()
}

// switchOneDomain 把单个域名的 CNAME 切到 target（集群 subdomain 或高防 CNAME），
// 供 switchToDefense/switchToCluster 与 clusters.go 的 failover trigger/cancel 共用。
// cf.PointSwitchTo 要求域名已经分配过切换记录（main_subdomain_record_id/cname_record），
// 未分配时（域名从未 resync 过）先兜底调用一次 cf.SyncDomain，不强制要求调用方先手动 resync。
func switchOneDomain(ctx context.Context, cf *cloudflare.Client, domainRepo *DomainRepo, tenantID string, d *Domain, clusterSubdomain, target string, onDefense, byFailover bool) error {
	cd, err := convertDomainToConfig(d)
	if err != nil {
		return err
	}
	if cd.MainSubdomainRecordID == "" || cd.CNAMERecord == "" {
		// 按切换后的状态建记录：高防 CNAME 可能来自集群默认值（d.DefenseCNAME 为空），
		// 按旧状态 + d.DefenseCNAME 去建会报「未配置高防 CNAME」。
		cd.OnDefense = onDefense
		if err := cf.SyncDomain(cd, clusterSubdomain, target); err != nil {
			return err
		}
	}
	if err := cf.PointSwitchTo(cd, target); err != nil {
		return err
	}
	if err := domainRepo.UpdateCFState(ctx, tenantID, d.ID, cd.CNAMERecord, cd.CNAMERecordID, cd.MainSubdomainRecordID, cd.CFMessage); err != nil {
		return err
	}
	return domainRepo.SetDefenseFlags(ctx, tenantID, d.ID, onDefense, byFailover)
}

// switchToDefense 对应 docs/API-v2.md §3.1 的 POST /domains/:id/switch-to-defense：
// 200 同步，把域名的 CNAME 指向已配置的高防 CNAME。
func (h *domainsHandler) switchToDefense(w http.ResponseWriter, r *http.Request, tenantID, id string) {
	d, err := h.repo.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	cf, err := tenantCF(r.Context(), h.db, tenantID)
	if err != nil {
		WriteError(w, err)
		return
	}
	if !cf.Enabled() {
		WriteError(w, NewApiError("cf_not_configured", "Cloudflare 未配置"))
		return
	}
	clusterSubdomain, defenseCNAME, err := h.domainCluster(r.Context(), cf, tenantID, d)
	if err != nil {
		WriteError(w, err)
		return
	}
	if defenseCNAME == "" {
		WriteError(w, NewApiError("defense_cname_missing", "域名和所属集群都未配置高防 CNAME"))
		return
	}
	if err := switchOneDomain(r.Context(), cf, h.repo, tenantID, d, clusterSubdomain, defenseCNAME, true, false); err != nil {
		WriteError(w, NewApiError("upstream_failed", "切换到高防失败: "+err.Error()))
		return
	}
	updated, err := h.repo.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	writeJSON(w, http.StatusOK, renderDomain(updated))
}

// switchToCluster 对应 docs/API-v2.md §3.1 的 POST /domains/:id/switch-to-cluster：
// 200 同步，把域名的 CNAME 切回它所属集群的 subdomain。
func (h *domainsHandler) switchToCluster(w http.ResponseWriter, r *http.Request, tenantID, id string) {
	d, err := h.repo.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	cf, err := tenantCF(r.Context(), h.db, tenantID)
	if err != nil {
		WriteError(w, err)
		return
	}
	if !cf.Enabled() {
		WriteError(w, NewApiError("cf_not_configured", "Cloudflare 未配置"))
		return
	}
	clusterSubdomain, err := h.domainClusterSubdomain(r.Context(), cf, tenantID, d)
	if err != nil {
		WriteError(w, err)
		return
	}
	if err := switchOneDomain(r.Context(), cf, h.repo, tenantID, d, clusterSubdomain, clusterSubdomain, false, false); err != nil {
		WriteError(w, NewApiError("upstream_failed", "切回集群失败: "+err.Error()))
		return
	}
	updated, err := h.repo.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	writeJSON(w, http.StatusOK, renderDomain(updated))
}

// fanout 只对「本代理自己的」已启用节点（按 clusterID 过滤，空则全部）并发执行 fn，
// 返回 节点名 → "ok"/错误信息。v2 节点存在 MySQL 里，不能用 pusher 内部的 v1 节点表，
// 否则会推到别的代理（或 v1 单租户）的节点上。
func (h *domainsHandler) fanout(ctx context.Context, tenantID, clusterID string, fn func(n *config.Node) error) map[string]string {
	nodes, err := h.domainNodes(ctx, tenantID, clusterID)
	if err != nil {
		return map[string]string{"_": "读取节点失败: " + err.Error()}
	}
	return fanoutNodes(nodes, fn)
}

// domainNodes 列出这个域名实际会落到的节点：本代理已启用的那些，按集群收窄
// （clusterID 为空表示全部，与 fanout 一直以来的口径一致）。
func (h *domainsHandler) domainNodes(ctx context.Context, tenantID, clusterID string) ([]*config.Node, error) {
	nodes, err := tenantEdgeNodes(ctx, h.nodeRepo, tenantID)
	if err != nil {
		return nil, err
	}
	var picked []*config.Node
	for _, n := range nodes {
		if clusterID == "" || n.ClusterID == clusterID {
			picked = append(picked, n)
		}
	}
	return picked, nil
}

// geoPushForDomain 在域名区域规则改动后，把这条域名的配置和前缀表一起发到它的节点。
//
// 两样都得发：前缀表决定"这些国家有哪些网段"，域名配置里的 geo_policy 决定"这个域名拦不拦"，
// 边缘判定读的是后者。只补表不发配置，租户把规则改成封禁 JP，边缘还按上一份配置放行。
// 也不能指望调用方随后去 resync：resync 第一步就要过 Cloudflare（没配 CF 直接
// cf_not_configured 返回，DNS 同步失败也走不到下发），区域规则是安全控制，
// 不该被 DNS 那一步的成败绑住。
//
// 顺序是先表后规则：反过来会有一瞬间规则指着表里还没有的国家，边缘查成"未知"然后放行。
// 这里只发域名自己的配置、不动节点级策略——总闸和四层丢包归管理员，租户改自己域名时
// 去覆盖它，等于一个代理能改到别的代理共用的那台节点的四层行为。
func (h *domainsHandler) geoPushForDomain(ctx context.Context, tenantID string, d *Domain) map[string]any {
	if h.pusher == nil {
		return map[string]any{"error": "主控未启用节点推送，区域规则没能下发到节点"}
	}
	nodes, err := h.domainNodes(ctx, tenantID, d.ClusterID.String)
	if err != nil {
		return map[string]any{"error": "读取节点失败: " + err.Error()}
	}
	if len(nodes) == 0 {
		// 一条规则存下来却没有任何节点可发，这句话必须回给调用方：
		// 静默返回空会显示成"改好了"，而它其实哪儿都没到。
		return map[string]any{"skipped": "该域名还没有可下发的边缘节点（未绑定集群，或集群里没有启用的节点）"}
	}
	// 表按"当前全网应该生效的那一份"补：启用时把新国家补进去，关掉最后一条规则时把它撤下来。
	// 指纹相同的补发在 geoEnsureTable 里逐节点跳过，所以这一步正常情况下不产生 MB 级流量。
	out := geoEnsureTable(ctx, h.db, h.pusher, h.country, nodes)
	per, fails := h.pushDomainGeoConfig(ctx, d, nodes)
	out["domain_config"] = per
	if len(fails) > 0 {
		prev, _ := out["failed"].([]string)
		all := append(prev, fails...)
		out["failed"] = all
		out["error"] = strings.Join(all, "; ")
	}
	return out
}

// pushDomainGeoConfig 把域名配置 upsert 到给定节点，走 resync 用的同一个 /edge/domains，
// 但不碰 DNS。带上响应体：边缘整份拒收时原因写在里面（源站不合法、证书读不出来），
// 只回一句"edge returned 400"的话，租户只能对着自己刚保存的那份配置猜。
func (h *domainsHandler) pushDomainGeoConfig(ctx context.Context, d *Domain, nodes []*config.Node) (map[string]string, []string) {
	payload, err := domainPushPayload(ctx, h.db, d)
	if err != nil {
		return nil, []string{"构建域名下发配置失败: " + err.Error()}
	}
	per := make(map[string]string, len(nodes))
	var fails []string
	for _, n := range nodes {
		status, body, err := h.pusher.PostToNodeResp(n, "/edge/domains", payload, geoCfgPushTimeout)
		switch {
		case err != nil:
			per[nodeLabel(n)] = "failed: " + err.Error()
			fails = append(fails, nodeLabel(n)+": 域名配置没发下去——"+err.Error())
		case status >= 400:
			msg := strings.TrimSpace(string(body))
			if msg == "" {
				msg = fmt.Sprintf("边缘返回 %d", status)
			}
			per[nodeLabel(n)] = fmt.Sprintf("rejected(%d): %s", status, msg)
			fails = append(fails, nodeLabel(n)+": 域名配置被拒——"+msg)
		default:
			per[nodeLabel(n)] = "ok"
		}
	}
	return per, fails
}
