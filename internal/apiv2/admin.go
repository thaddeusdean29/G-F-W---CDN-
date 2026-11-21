package apiv2

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

// 平台管理员的代理（租户）/套餐/账号管理，对应 docs/API-v2.md §4 的最小子集。
// 一个代理 = 一个租户：域名、节点、集群全部按 tenant_id 隔离，代理之间互相看不到；
// 管理员只负责开通代理、分配套餐、管理代理的登录账号，不代替代理操作其资源。

// minPasswordLen 与安装向导的管理员密码要求一致。
const minPasswordLen = 8

var adminUserIndexCodes = map[string]string{"tenant_users_email_uq": "conflict"}
var adminPlanIndexCodes = map[string]string{"code": "conflict"}

// classifyOr 把可识别的 MySQL 约束错误翻译成 ApiError，否则原样返回。
func classifyOr(err error, indexCodes map[string]string) error {
	if ae := ClassifyMySQLError(err, indexCodes); ae != nil {
		return ae
	}
	return err
}

func fieldError(field, msg string) *ApiError {
	return NewApiError("validation_failed", msg).
		WithDetails(map[string]any{"fields": map[string]string{field: msg}})
}

func formatNullTime(t sql.NullTime) *string {
	if !t.Valid {
		return nil
	}
	s := t.Time.UTC().Format(rfc3339Milli)
	return &s
}

// parseExpiresAt 接受 RFC3339 时间或 "2006-01-02"（按当天 23:59:59 UTC+8 结束，
// 面板用户都在国内，日期选择器给的是本地日期）。空串/null 表示不过期。
func parseExpiresAt(raw json.RawMessage) (sql.NullTime, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return sql.NullTime{}, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return sql.NullTime{}, fieldError("expires_at", "必须是时间字符串或 null")
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return sql.NullTime{}, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return sql.NullTime{Time: t.UTC(), Valid: true}, nil
	}
	if d, err := time.ParseInLocation("2006-01-02", s, time.FixedZone("UTC+8", 8*3600)); err == nil {
		return sql.NullTime{Time: d.Add(24*time.Hour - time.Second).UTC(), Valid: true}, nil
	}
	return sql.NullTime{}, fieldError("expires_at", "格式应为 2006-01-02 或 RFC3339")
}

func hashPassword(pw string) (string, error) {
	if len(pw) < minPasswordLen {
		return "", fieldError("password", "密码至少 8 位")
	}
	if len(pw) > 72 { // bcrypt 只取前 72 字节，超出部分会被静默忽略
		return "", fieldError("password", "密码最长 72 位")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(h), nil
}

func normalizeLogin(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", fieldError("email", "登录账号必填")
	}
	if len(s) > 255 || strings.ContainsAny(s, " \t\r\n") {
		return "", fieldError("email", "登录账号不能含空白，最长 255 位")
	}
	return s, nil
}

// ---------------------------------------------------------------------------
// 套餐
// ---------------------------------------------------------------------------

type adminPlansHandler struct{ db *sql.DB }

type adminPlan struct {
	ID          int    `json:"id"`
	Code        string `json:"code"`
	Name        string `json:"name"`
	MaxNodes    int    `json:"max_nodes"`
	MaxDomains  int    `json:"max_domains"`
	MaxClusters int    `json:"max_clusters"`
	Tenants     int    `json:"tenants"`
	CreatedAt   string `json:"created_at"`
}

const adminPlanSelect = `
	SELECT p.id, p.code, p.name, p.max_nodes, p.max_domains, p.max_clusters,
	       (SELECT COUNT(*) FROM tenants t WHERE t.plan_id = p.id), p.created_at
	FROM plans p`

func scanAdminPlan(sc interface{ Scan(...any) error }) (*adminPlan, error) {
	var p adminPlan
	var created time.Time
	if err := sc.Scan(&p.ID, &p.Code, &p.Name, &p.MaxNodes, &p.MaxDomains, &p.MaxClusters, &p.Tenants, &created); err != nil {
		return nil, err
	}
	p.CreatedAt = created.UTC().Format(rfc3339Milli)
	return &p, nil
}

func (h *adminPlansHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/v2/admin/plans" {
		switch r.Method {
		case http.MethodGet:
			h.list(w, r)
		case http.MethodPost:
			h.create(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	id, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/api/v2/admin/plans/"))
	if err != nil || id <= 0 {
		WriteError(w, NewApiError("not_found", "未找到该资源"))
		return
	}
	switch r.Method {
	case http.MethodPatch:
		h.patch(w, r, id)
	case http.MethodDelete:
		h.delete(w, r, id)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *adminPlansHandler) list(w http.ResponseWriter, r *http.Request) {
	rows, err := h.db.QueryContext(r.Context(), adminPlanSelect+` ORDER BY p.max_nodes ASC, p.id ASC`)
	if err != nil {
		WriteError(w, err)
		return
	}
	defer rows.Close()
	items := []*adminPlan{}
	for rows.Next() {
		p, err := scanAdminPlan(rows)
		if err != nil {
			WriteError(w, err)
			return
		}
		items = append(items, p)
	}
	if err := rows.Err(); err != nil {
		WriteError(w, err)
		return
	}
	writeList(w, items, len(items), 1, len(items))
}

func (h *adminPlansHandler) get(r *http.Request, id int) (*adminPlan, error) {
	return scanAdminPlan(h.db.QueryRowContext(r.Context(), adminPlanSelect+` WHERE p.id = ?`, id))
}

type planWriteRequest struct {
	Code        *string `json:"code"`
	Name        *string `json:"name"`
	MaxNodes    *int    `json:"max_nodes"`
	MaxDomains  *int    `json:"max_domains"`
	MaxClusters *int    `json:"max_clusters"`
}

func (req *planWriteRequest) validate() error {
	if req.Name != nil && (strings.TrimSpace(*req.Name) == "" || len(*req.Name) > 64) {
		return fieldError("name", "名称必填，最长 64 位")
	}
	for field, v := range map[string]*int{"max_nodes": req.MaxNodes, "max_domains": req.MaxDomains, "max_clusters": req.MaxClusters} {
		if v != nil && *v < 0 {
			return fieldError(field, "不能为负数")
		}
	}
	return nil
}

func (h *adminPlansHandler) create(w http.ResponseWriter, r *http.Request) {
	body, _, err := decodeKnownFields(r, []string{"code", "name", "max_nodes", "max_domains", "max_clusters"})
	if err != nil {
		WriteError(w, err)
		return
	}
	var req planWriteRequest
	if err := json.Unmarshal(body, &req); err != nil {
		WriteError(w, NewApiError("invalid_json", "请求体不是合法 JSON"))
		return
	}
	if req.Code == nil || !validPlanCode(*req.Code) {
		WriteError(w, fieldError("code", "编码必填，1-32 位小写字母、数字、- 或 _"))
		return
	}
	if req.Name == nil || req.MaxNodes == nil || req.MaxDomains == nil || req.MaxClusters == nil {
		WriteError(w, NewApiError("validation_failed", "name、max_nodes、max_domains、max_clusters 为必填字段"))
		return
	}
	if err := req.validate(); err != nil {
		WriteError(w, err)
		return
	}
	res, err := h.db.ExecContext(r.Context(),
		`INSERT INTO plans (code, name, max_nodes, max_domains, max_clusters, features) VALUES (?, ?, ?, ?, ?, '{}')`,
		*req.Code, strings.TrimSpace(*req.Name), *req.MaxNodes, *req.MaxDomains, *req.MaxClusters)
	if err != nil {
		WriteError(w, classifyOr(err, adminPlanIndexCodes))
		return
	}
	id, _ := res.LastInsertId()
	p, err := h.get(r, int(id))
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, p)
}

// patch 改套餐的名称和配额。降低配额不会删除代理已有的资源，只是之后不能再新建（quota_exceeded）。
func (h *adminPlansHandler) patch(w http.ResponseWriter, r *http.Request, id int) {
	raw, err := readBody(r)
	if err != nil {
		WriteError(w, err)
		return
	}
	if bad := DisallowedFields(raw, []string{"id", "code", "tenants", "created_at"}); len(bad) > 0 {
		WriteError(w, readonlyFieldError(bad))
		return
	}
	if bad := UnknownFields(raw, []string{"name", "max_nodes", "max_domains", "max_clusters"}); len(bad) > 0 {
		WriteError(w, unknownFieldError(bad))
		return
	}
	var req planWriteRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		WriteError(w, NewApiError("validation_failed", "字段类型不正确"))
		return
	}
	if err := req.validate(); err != nil {
		WriteError(w, err)
		return
	}
	cur, err := h.get(r, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	if req.Name != nil {
		cur.Name = strings.TrimSpace(*req.Name)
	}
	if req.MaxNodes != nil {
		cur.MaxNodes = *req.MaxNodes
	}
	if req.MaxDomains != nil {
		cur.MaxDomains = *req.MaxDomains
	}
	if req.MaxClusters != nil {
		cur.MaxClusters = *req.MaxClusters
	}
	if _, err := h.db.ExecContext(r.Context(),
		`UPDATE plans SET name = ?, max_nodes = ?, max_domains = ?, max_clusters = ? WHERE id = ?`,
		cur.Name, cur.MaxNodes, cur.MaxDomains, cur.MaxClusters, id); err != nil {
		WriteError(w, classifyOr(err, adminPlanIndexCodes))
		return
	}
	p, err := h.get(r, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (h *adminPlansHandler) delete(w http.ResponseWriter, r *http.Request, id int) {
	p, err := h.get(r, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	if p.Tenants > 0 {
		WriteError(w, NewApiError("in_use", "仍有代理在使用该套餐，无法删除").
			WithDetails(map[string]any{"tenants": p.Tenants}))
		return
	}
	if _, err := h.db.ExecContext(r.Context(), `DELETE FROM plans WHERE id = ?`, id); err != nil {
		WriteError(w, classifyOr(err, nil))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func validPlanCode(s string) bool {
	if len(s) < 1 || len(s) > 32 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// 代理（租户）
// ---------------------------------------------------------------------------

type adminTenantsHandler struct {
	db       *sql.DB
	sessions *SessionStore
}

type adminTenantPlan struct {
	ID          int    `json:"id"`
	Code        string `json:"code"`
	Name        string `json:"name"`
	MaxNodes    int    `json:"max_nodes"`
	MaxDomains  int    `json:"max_domains"`
	MaxClusters int    `json:"max_clusters"`
}

type adminTenant struct {
	ID         string          `json:"id"`
	Name       string          `json:"name"`
	Status     string          `json:"status"`
	Expired    bool            `json:"expired"`
	ExpiresAt  *string         `json:"expires_at"`
	Plan       adminTenantPlan `json:"plan"`
	Usage      meUsage         `json:"usage"`
	OwnerEmail string          `json:"owner_email"`
	CreatedAt  string          `json:"created_at"`
}

const adminTenantSelect = `
	SELECT t.id, t.name, t.status, t.expires_at, t.created_at,
	       p.id, p.code, p.name, p.max_nodes, p.max_domains, p.max_clusters,
	       (SELECT COUNT(*) FROM nodes n WHERE n.tenant_id = t.id),
	       (SELECT COUNT(*) FROM domains d WHERE d.tenant_id = t.id),
	       (SELECT COUNT(*) FROM clusters c WHERE c.tenant_id = t.id),
	       COALESCE((SELECT u.email FROM tenant_users u WHERE u.tenant_id = t.id AND u.role = 'owner'
	                 ORDER BY u.created_at ASC LIMIT 1), '')
	FROM tenants t
	JOIN plans p ON p.id = t.plan_id`

func scanAdminTenant(sc interface{ Scan(...any) error }) (*adminTenant, error) {
	var t adminTenant
	var expires sql.NullTime
	var created time.Time
	if err := sc.Scan(&t.ID, &t.Name, &t.Status, &expires, &created,
		&t.Plan.ID, &t.Plan.Code, &t.Plan.Name, &t.Plan.MaxNodes, &t.Plan.MaxDomains, &t.Plan.MaxClusters,
		&t.Usage.Nodes, &t.Usage.Domains, &t.Usage.Clusters, &t.OwnerEmail); err != nil {
		return nil, err
	}
	t.ExpiresAt = formatNullTime(expires)
	t.Expired = expires.Valid && !expires.Time.After(time.Now())
	t.CreatedAt = created.UTC().Format(rfc3339Milli)
	return &t, nil
}

func (h *adminTenantsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/v2/admin/tenants" {
		switch r.Method {
		case http.MethodGet:
			h.list(w, r)
		case http.MethodPost:
			h.create(w, r)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	rest := strings.TrimPrefix(r.URL.Path, "/api/v2/admin/tenants/")
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	if id == "" {
		WriteError(w, NewApiError("not_found", "未找到该资源"))
		return
	}
	if len(parts) == 1 {
		switch r.Method {
		case http.MethodGet:
			h.getOne(w, r, id)
		case http.MethodPatch:
			h.patch(w, r, id)
		case http.MethodDelete:
			h.delete(w, r, id)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	if parts[1] == "users" {
		switch r.Method {
		case http.MethodGet:
			h.listUsers(w, r, id)
		case http.MethodPost:
			h.createUser(w, r, id)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	WriteError(w, NewApiError("not_found", "未找到该资源"))
}

var adminTenantSortColumns = map[string]string{"created_at": "t.created_at", "name": "t.name", "expires_at": "t.expires_at"}

func (h *adminTenantsHandler) list(w http.ResponseWriter, r *http.Request) {
	page, pageSize := parsePagination(r)
	orderBy := parseSort(r, adminTenantSortColumns, "-created_at")

	where := ""
	var args []any
	if q := strings.TrimSpace(r.URL.Query().Get("q")); q != "" {
		// 按代理名或登录账号模糊搜索；LIKE 通配符转义，防止用户输入 % 扫全表。
		like := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q) + "%"
		where = ` WHERE t.name LIKE ? OR EXISTS (SELECT 1 FROM tenant_users u WHERE u.tenant_id = t.id AND u.email LIKE ?)`
		args = append(args, like, like)
	}

	var total int
	if err := h.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM tenants t`+where, args...).Scan(&total); err != nil {
		WriteError(w, err)
		return
	}
	rows, err := h.db.QueryContext(r.Context(),
		adminTenantSelect+where+` ORDER BY `+orderBy+`, t.id LIMIT ? OFFSET ?`,
		append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		WriteError(w, err)
		return
	}
	defer rows.Close()
	items := []*adminTenant{}
	for rows.Next() {
		t, err := scanAdminTenant(rows)
		if err != nil {
			WriteError(w, err)
			return
		}
		items = append(items, t)
	}
	if err := rows.Err(); err != nil {
		WriteError(w, err)
		return
	}
	writeList(w, items, total, page, pageSize)
}

func (h *adminTenantsHandler) get(r *http.Request, id string) (*adminTenant, error) {
	return scanAdminTenant(h.db.QueryRowContext(r.Context(), adminTenantSelect+` WHERE t.id = ?`, id))
}

func (h *adminTenantsHandler) getOne(w http.ResponseWriter, r *http.Request, id string) {
	t, err := h.get(r, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	writeJSON(w, http.StatusOK, t)
}

func validTenantName(s string) error {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 128 {
		return fieldError("name", "代理名称必填，最长 128 位")
	}
	return nil
}

func (h *adminTenantsHandler) planExists(r *http.Request, planID int) error {
	var n int
	if err := h.db.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM plans WHERE id = ?`, planID).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return fieldError("plan_id", "套餐不存在")
	}
	return nil
}

// create 在一个事务里建代理和它的 owner 登录账号。新代理没有任何域名/节点/集群，
// 和其他代理的数据完全隔离。
func (h *adminTenantsHandler) create(w http.ResponseWriter, r *http.Request) {
	_, fields, err := decodeKnownFields(r, []string{"name", "plan_id", "expires_at", "owner"})
	if err != nil {
		WriteError(w, err)
		return
	}
	var name string
	if err := json.Unmarshal(fields["name"], &name); err != nil {
		WriteError(w, fieldError("name", "代理名称必填"))
		return
	}
	if err := validTenantName(name); err != nil {
		WriteError(w, err)
		return
	}
	var planID int
	if err := json.Unmarshal(fields["plan_id"], &planID); err != nil || planID <= 0 {
		WriteError(w, fieldError("plan_id", "请选择套餐"))
		return
	}
	if err := h.planExists(r, planID); err != nil {
		WriteError(w, err)
		return
	}
	expires, err := parseExpiresAt(fields["expires_at"])
	if err != nil {
		WriteError(w, err)
		return
	}
	var owner struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if raw, ok := fields["owner"]; !ok || json.Unmarshal(raw, &owner) != nil {
		WriteError(w, fieldError("owner", "需要提供 owner.email 与 owner.password"))
		return
	}
	email, err := normalizeLogin(owner.Email)
	if err != nil {
		WriteError(w, err)
		return
	}
	passHash, err := hashPassword(owner.Password)
	if err != nil {
		WriteError(w, err)
		return
	}

	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		WriteError(w, err)
		return
	}
	defer tx.Rollback()
	tenantID := uuid.New().String()
	if _, err := tx.ExecContext(r.Context(),
		`INSERT INTO tenants (id, name, plan_id, status, expires_at) VALUES (?, ?, ?, 'active', ?)`,
		tenantID, strings.TrimSpace(name), planID, expires); err != nil {
		WriteError(w, classifyOr(err, nil))
		return
	}
	if _, err := tx.ExecContext(r.Context(),
		`INSERT INTO tenant_users (id, tenant_id, email, password_hash, role, status) VALUES (?, ?, ?, ?, 'owner', 'active')`,
		uuid.New().String(), tenantID, email, passHash); err != nil {
		WriteError(w, emailConflictOr(err))
		return
	}
	if err := tx.Commit(); err != nil {
		WriteError(w, err)
		return
	}
	t, err := h.get(r, tenantID)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, t)
}

func emailConflictOr(err error) error {
	ae := ClassifyMySQLError(err, adminUserIndexCodes)
	if ae == nil {
		return err
	}
	if ae.Code == "conflict" {
		return NewApiError("conflict", "该登录账号已被使用").
			WithDetails(map[string]any{"fields": map[string]string{"email": "已被使用"}})
	}
	return ae
}

// patch 可改 name / plan_id / status / expires_at。换套餐或降级不会删除已有资源；
// 暂停（suspended）或过期后代理仍能登录查看，但不能再新建资源（quota.go 的 tenant_inactive）。
func (h *adminTenantsHandler) patch(w http.ResponseWriter, r *http.Request, id string) {
	raw, err := readBody(r)
	if err != nil {
		WriteError(w, err)
		return
	}
	if bad := DisallowedFields(raw, []string{"id", "plan", "usage", "owner_email", "expired", "created_at"}); len(bad) > 0 {
		WriteError(w, readonlyFieldError(bad))
		return
	}
	if bad := UnknownFields(raw, []string{"name", "plan_id", "status", "expires_at"}); len(bad) > 0 {
		WriteError(w, unknownFieldError(bad))
		return
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)

	if _, err := h.get(r, id); err != nil {
		WriteError(w, notFoundOr(err))
		return
	}

	sets := []string{}
	args := []any{}
	if v, ok := fields["name"]; ok {
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			WriteError(w, fieldError("name", "必须是字符串"))
			return
		}
		if err := validTenantName(s); err != nil {
			WriteError(w, err)
			return
		}
		sets, args = append(sets, "name = ?"), append(args, strings.TrimSpace(s))
	}
	if v, ok := fields["plan_id"]; ok {
		var planID int
		if err := json.Unmarshal(v, &planID); err != nil || planID <= 0 {
			WriteError(w, fieldError("plan_id", "必须是套餐 ID"))
			return
		}
		if err := h.planExists(r, planID); err != nil {
			WriteError(w, err)
			return
		}
		sets, args = append(sets, "plan_id = ?"), append(args, planID)
	}
	if v, ok := fields["status"]; ok {
		var s string
		if err := json.Unmarshal(v, &s); err != nil || (s != "active" && s != "suspended") {
			WriteError(w, fieldError("status", "只能是 active 或 suspended"))
			return
		}
		sets, args = append(sets, "status = ?"), append(args, s)
	}
	if v, ok := fields["expires_at"]; ok {
		expires, err := parseExpiresAt(v)
		if err != nil {
			WriteError(w, err)
			return
		}
		sets, args = append(sets, "expires_at = ?"), append(args, expires)
	}
	if len(sets) > 0 {
		if _, err := h.db.ExecContext(r.Context(),
			`UPDATE tenants SET `+strings.Join(sets, ", ")+` WHERE id = ?`, append(args, id)...); err != nil {
			WriteError(w, classifyOr(err, nil))
			return
		}
	}
	t, err := h.get(r, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	writeJSON(w, http.StatusOK, t)
}

// delete 只允许删除已经没有域名/节点/集群的代理：这些资源挂着 CF DNS 记录和边缘节点配置，
// 直接级联删库会在 Cloudflare 和边缘上留下孤儿记录。代理的账号、会话、任务等随租户级联删除。
func (h *adminTenantsHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
	t, err := h.get(r, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	if t.Usage.Nodes > 0 || t.Usage.Domains > 0 || t.Usage.Clusters > 0 {
		WriteError(w, NewApiError("in_use", "该代理下仍有域名、节点或集群，请先让代理删除或暂停该代理").
			WithDetails(map[string]any{"nodes": t.Usage.Nodes, "domains": t.Usage.Domains, "clusters": t.Usage.Clusters}))
		return
	}
	if _, err := h.db.ExecContext(r.Context(), `DELETE FROM tenants WHERE id = ?`, id); err != nil {
		WriteError(w, classifyOr(err, nil))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// ---------------------------------------------------------------------------
// 代理的登录账号
// ---------------------------------------------------------------------------

type adminTenantUser struct {
	ID          string  `json:"id"`
	TenantID    string  `json:"tenant_id"`
	Email       string  `json:"email"`
	Role        string  `json:"role"`
	Status      string  `json:"status"`
	LastLoginAt *string `json:"last_login_at"`
	CreatedAt   string  `json:"created_at"`
}

const adminTenantUserSelect = `
	SELECT id, tenant_id, email, role, status, last_login_at, created_at FROM tenant_users`

func scanAdminTenantUser(sc interface{ Scan(...any) error }) (*adminTenantUser, error) {
	var u adminTenantUser
	var last sql.NullTime
	var created time.Time
	if err := sc.Scan(&u.ID, &u.TenantID, &u.Email, &u.Role, &u.Status, &last, &created); err != nil {
		return nil, err
	}
	u.LastLoginAt = formatNullTime(last)
	u.CreatedAt = created.UTC().Format(rfc3339Milli)
	return &u, nil
}

func (h *adminTenantsHandler) listUsers(w http.ResponseWriter, r *http.Request, tenantID string) {
	if _, err := h.get(r, tenantID); err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	rows, err := h.db.QueryContext(r.Context(), adminTenantUserSelect+` WHERE tenant_id = ? ORDER BY created_at ASC`, tenantID)
	if err != nil {
		WriteError(w, err)
		return
	}
	defer rows.Close()
	items := []*adminTenantUser{}
	for rows.Next() {
		u, err := scanAdminTenantUser(rows)
		if err != nil {
			WriteError(w, err)
			return
		}
		items = append(items, u)
	}
	if err := rows.Err(); err != nil {
		WriteError(w, err)
		return
	}
	writeList(w, items, len(items), 1, len(items))
}

func validRole(s string) bool { return s == "owner" || s == "member" || s == "readonly" }

func (h *adminTenantsHandler) createUser(w http.ResponseWriter, r *http.Request, tenantID string) {
	if _, err := h.get(r, tenantID); err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	body, _, err := decodeKnownFields(r, []string{"email", "password", "role"})
	if err != nil {
		WriteError(w, err)
		return
	}
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		WriteError(w, NewApiError("validation_failed", "字段类型不正确"))
		return
	}
	email, err := normalizeLogin(req.Email)
	if err != nil {
		WriteError(w, err)
		return
	}
	if req.Role == "" {
		req.Role = "member"
	}
	if !validRole(req.Role) {
		WriteError(w, fieldError("role", "只能是 owner、member 或 readonly"))
		return
	}
	passHash, err := hashPassword(req.Password)
	if err != nil {
		WriteError(w, err)
		return
	}
	userID := uuid.New().String()
	if _, err := h.db.ExecContext(r.Context(),
		`INSERT INTO tenant_users (id, tenant_id, email, password_hash, role, status) VALUES (?, ?, ?, ?, ?, 'active')`,
		userID, tenantID, email, passHash, req.Role); err != nil {
		WriteError(w, emailConflictOr(err))
		return
	}
	u, err := scanAdminTenantUser(h.db.QueryRowContext(r.Context(), adminTenantUserSelect+` WHERE id = ?`, userID))
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, u)
}

type adminUsersHandler struct {
	db       *sql.DB
	sessions *SessionStore
}

// ServeHTTP 处理 PATCH /api/v2/admin/users/:id {"password"?, "status"?, "role"?}：
// 重置密码或禁用账号后，该账号的所有会话立刻失效。
func (h *adminUsersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v2/admin/users/")
	if id == "" || strings.Contains(id, "/") {
		WriteError(w, NewApiError("not_found", "未找到该资源"))
		return
	}
	if r.Method != http.MethodPatch {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	raw, err := readBody(r)
	if err != nil {
		WriteError(w, err)
		return
	}
	if bad := UnknownFields(raw, []string{"password", "status", "role"}); len(bad) > 0 {
		WriteError(w, unknownFieldError(bad))
		return
	}
	var req struct {
		Password *string `json:"password"`
		Status   *string `json:"status"`
		Role     *string `json:"role"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		WriteError(w, NewApiError("validation_failed", "字段类型不正确"))
		return
	}

	cur, err := scanAdminTenantUser(h.db.QueryRowContext(r.Context(), adminTenantUserSelect+` WHERE id = ?`, id))
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}

	sets := []string{}
	args := []any{}
	revoke := false
	if req.Password != nil {
		passHash, err := hashPassword(*req.Password)
		if err != nil {
			WriteError(w, err)
			return
		}
		sets, args, revoke = append(sets, "password_hash = ?"), append(args, passHash), true
	}
	if req.Status != nil {
		if *req.Status != "active" && *req.Status != "disabled" {
			WriteError(w, fieldError("status", "只能是 active 或 disabled"))
			return
		}
		sets, args = append(sets, "status = ?"), append(args, *req.Status)
		if *req.Status == "disabled" {
			revoke = true
		}
	}
	if req.Role != nil {
		if !validRole(*req.Role) {
			WriteError(w, fieldError("role", "只能是 owner、member 或 readonly"))
			return
		}
		sets, args = append(sets, "role = ?"), append(args, *req.Role)
	}
	if len(sets) > 0 {
		if _, err := h.db.ExecContext(r.Context(),
			`UPDATE tenant_users SET `+strings.Join(sets, ", ")+` WHERE id = ?`, append(args, cur.ID)...); err != nil {
			WriteError(w, classifyOr(err, nil))
			return
		}
	}
	if revoke {
		if err := h.sessions.DeleteAllForTenantUser(r.Context(), cur.ID); err != nil {
			WriteError(w, err)
			return
		}
	}
	u, err := scanAdminTenantUser(h.db.QueryRowContext(r.Context(), adminTenantUserSelect+` WHERE id = ?`, cur.ID))
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	writeJSON(w, http.StatusOK, u)
}
