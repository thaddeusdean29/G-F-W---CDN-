package apiv2

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const (
	loginRateLimitWindow = 10 * time.Minute
	loginRateLimitMax    = 5
)

// clientIP 提取请求方 IP，不含端口。信任 X-Forwarded-For 首段
// （面板通常直接对外监听，若前面加了反代需保证其正确设置该头）。
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// checkLoginRateLimit 返回 true 表示已超限：10 分钟窗口内失败次数达到上限。
func checkLoginRateLimit(ctx context.Context, db *sql.DB, key string) (bool, error) {
	var cnt int
	err := db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM login_attempts WHERE attempt_key = ? AND attempted_at > ?`,
		key, time.Now().UTC().Add(-loginRateLimitWindow)).Scan(&cnt)
	if err != nil {
		return false, err
	}
	return cnt >= loginRateLimitMax, nil
}

func recordLoginFailure(ctx context.Context, db *sql.DB, key string) error {
	_, err := db.ExecContext(ctx, `INSERT INTO login_attempts (attempt_key) VALUES (?)`, key)
	return err
}

type tenantAuthHandler struct {
	db       *sql.DB
	sessions *SessionStore
}

type meResponse struct {
	User      meUser   `json:"user"`
	Tenant    meTenant `json:"tenant"`
	Plan      mePlan   `json:"plan"`
	Usage     meUsage  `json:"usage"`
	CSRFToken string   `json:"csrf_token"`
}

type meUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Role  string `json:"role"`
}

type meTenant struct {
	ID        string  `json:"id"`
	Name      string  `json:"name"`
	Status    string  `json:"status"`
	ExpiresAt *string `json:"expires_at"`
}

type mePlan struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	MaxNodes    int    `json:"max_nodes"`
	MaxDomains  int    `json:"max_domains"`
	MaxClusters int    `json:"max_clusters"`
}

type meUsage struct {
	Nodes    int `json:"nodes"`
	Domains  int `json:"domains"`
	Clusters int `json:"clusters"`
}

// getTenantPlan 查询租户当前套餐。被 buildMe 和 dashboard.go 的看板接口共用——
// 两处都需要展示同一份 plan 信息,抽出来避免 SQL 重复漂移。
func getTenantPlan(ctx context.Context, db *sql.DB, tenantID string) (mePlan, error) {
	var p mePlan
	err := db.QueryRowContext(ctx, `
		SELECT p.code, p.name, p.max_nodes, p.max_domains, p.max_clusters
		FROM tenants t
		JOIN plans p ON p.id = t.plan_id
		WHERE t.id = ?`, tenantID).
		Scan(&p.Code, &p.Name, &p.MaxNodes, &p.MaxDomains, &p.MaxClusters)
	if err != nil {
		return mePlan{}, err
	}
	return p, nil
}

// countUsage 统计租户当前节点/域名/集群数量。被 buildMe 和 dashboard.go 的看板接口共用。
func countUsage(ctx context.Context, db *sql.DB, tenantID string) (meUsage, error) {
	var u meUsage
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM nodes WHERE tenant_id = ?`, tenantID).Scan(&u.Nodes); err != nil {
		return meUsage{}, err
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM domains WHERE tenant_id = ?`, tenantID).Scan(&u.Domains); err != nil {
		return meUsage{}, err
	}
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM clusters WHERE tenant_id = ?`, tenantID).Scan(&u.Clusters); err != nil {
		return meUsage{}, err
	}
	return u, nil
}

func (h *tenantAuthHandler) buildMe(ctx context.Context, tenantUserID, csrfToken string) (*meResponse, error) {
	var (
		email      string
		role       string
		tenantID   string
		tName      string
		tStatus    string
		tExpiresAt sql.NullTime
	)
	err := h.db.QueryRowContext(ctx, `
		SELECT tu.email, tu.role, t.id, t.name, t.status, t.expires_at
		FROM tenant_users tu
		JOIN tenants t ON t.id = tu.tenant_id
		WHERE tu.id = ?`, tenantUserID).
		Scan(&email, &role, &tenantID, &tName, &tStatus, &tExpiresAt)
	if err != nil {
		return nil, err
	}

	plan, err := getTenantPlan(ctx, h.db, tenantID)
	if err != nil {
		return nil, err
	}
	usage, err := countUsage(ctx, h.db, tenantID)
	if err != nil {
		return nil, err
	}

	var expiresAt *string
	if tExpiresAt.Valid {
		s := tExpiresAt.Time.UTC().Format(time.RFC3339)
		expiresAt = &s
	}

	return &meResponse{
		User:      meUser{ID: tenantUserID, Email: email, Role: role},
		Tenant:    meTenant{ID: tenantID, Name: tName, Status: tStatus, ExpiresAt: expiresAt},
		Plan:      plan,
		Usage:     usage,
		CSRFToken: csrfToken,
	}, nil
}

func (h *tenantAuthHandler) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)
	limited, err := checkLoginRateLimit(r.Context(), h.db, ip)
	if err != nil {
		WriteError(w, err)
		return
	}
	if limited {
		w.Header().Set("Retry-After", "600")
		WriteError(w, NewApiError("rate_limited", "登录失败次数过多，请稍后重试"))
		return
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, NewApiError("invalid_json", "请求体不是合法 JSON"))
		return
	}

	var tenantUserID, tenantID, passwordHash, status string
	err = h.db.QueryRowContext(r.Context(), `
		SELECT id, tenant_id, password_hash, status FROM tenant_users WHERE email = ?`, req.Email).
		Scan(&tenantUserID, &tenantID, &passwordHash, &status)
	if errors.Is(err, sql.ErrNoRows) {
		_ = recordLoginFailure(r.Context(), h.db, ip)
		WriteError(w, NewApiError("invalid_credentials", "账号或密码错误"))
		return
	}
	if err != nil {
		WriteError(w, err)
		return
	}
	if status != "active" || bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)) != nil {
		_ = recordLoginFailure(r.Context(), h.db, ip)
		WriteError(w, NewApiError("invalid_credentials", "账号或密码错误"))
		return
	}

	token, csrfToken, err := h.sessions.CreateTenantSession(r.Context(), tenantUserID, tenantID, ip, r.UserAgent())
	if err != nil {
		WriteError(w, err)
		return
	}
	setSessionCookie(w, r, TenantSessionCookie, token)

	me, err := h.buildMe(r.Context(), tenantUserID, csrfToken)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, me)
}

func (h *tenantAuthHandler) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if c, err := r.Cookie(TenantSessionCookie); err == nil {
		_ = h.sessions.Delete(r.Context(), c.Value)
	}
	clearSessionCookie(w, r, TenantSessionCookie)
	w.WriteHeader(http.StatusNoContent)
}

func (h *tenantAuthHandler) meOrPatch(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.me(w, r)
	case http.MethodPatch:
		h.patchMe(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *tenantAuthHandler) me(w http.ResponseWriter, r *http.Request) {
	info := SessionFromContext(r.Context())
	me, err := h.buildMe(r.Context(), info.TenantUserID, info.CSRFToken)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, me)
}

// patchMe 目前只支持 docs/API-v2.md §1 描述的改密码操作：{"password":{"old","new"}}。
func (h *tenantAuthHandler) patchMe(w http.ResponseWriter, r *http.Request) {
	info := SessionFromContext(r.Context())

	var req struct {
		Password *struct {
			Old string `json:"old"`
			New string `json:"new"`
		} `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, NewApiError("invalid_json", "请求体不是合法 JSON"))
		return
	}
	if req.Password == nil || req.Password.New == "" {
		WriteError(w, NewApiError("validation_failed", "缺少 password 字段").
			WithDetails(map[string]any{"fields": map[string]string{"password": "必填"}}))
		return
	}

	var currentHash string
	if err := h.db.QueryRowContext(r.Context(), `SELECT password_hash FROM tenant_users WHERE id = ?`, info.TenantUserID).
		Scan(&currentHash); err != nil {
		WriteError(w, err)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.Password.Old)) != nil {
		WriteError(w, NewApiError("validation_failed", "原密码不正确").
			WithDetails(map[string]any{"fields": map[string]string{"password.old": "不正确"}}))
		return
	}

	newHash, err := bcrypt.GenerateFromPassword([]byte(req.Password.New), bcrypt.DefaultCost)
	if err != nil {
		WriteError(w, err)
		return
	}
	if _, err := h.db.ExecContext(r.Context(), `UPDATE tenant_users SET password_hash = ? WHERE id = ?`,
		string(newHash), info.TenantUserID); err != nil {
		WriteError(w, err)
		return
	}

	// 改密码后其他会话全部失效（docs/API-v2.md §1）；当前会话也一并失效，
	// 这里立刻发一个新的以保持前端不被登出。
	if err := h.sessions.DeleteAllForTenantUser(r.Context(), info.TenantUserID); err != nil {
		WriteError(w, err)
		return
	}
	token, csrfToken, err := h.sessions.CreateTenantSession(r.Context(), info.TenantUserID, info.TenantID, clientIP(r), r.UserAgent())
	if err != nil {
		WriteError(w, err)
		return
	}
	setSessionCookie(w, r, TenantSessionCookie, token)

	me, err := h.buildMe(r.Context(), info.TenantUserID, csrfToken)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, me)
}
