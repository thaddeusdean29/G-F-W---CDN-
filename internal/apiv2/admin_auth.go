package apiv2

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"

	"golang.org/x/crypto/bcrypt"
)

type adminAuthHandler struct {
	db       *sql.DB
	sessions *SessionStore
}

type adminMeResponse struct {
	Admin     adminMeUser `json:"admin"`
	CSRFToken string      `json:"csrf_token"`
}

type adminMeUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

func (h *adminAuthHandler) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	ip := clientIP(r)
	key := "admin:" + ip
	limited, err := checkLoginRateLimit(r.Context(), h.db, key)
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
		Username string `json:"username"`
		Password string `json:"password"`
		// TOTP 二次验证暂未实现（admin_users.totp_secret_enc 目前始终为空），先接收占位不做校验。
		TOTP string `json:"totp"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteError(w, NewApiError("invalid_json", "请求体不是合法 JSON"))
		return
	}

	var adminID, passwordHash, status string
	err = h.db.QueryRowContext(r.Context(), `
		SELECT id, password_hash, status FROM admin_users WHERE username = ?`, req.Username).
		Scan(&adminID, &passwordHash, &status)
	if errors.Is(err, sql.ErrNoRows) {
		_ = recordLoginFailure(r.Context(), h.db, key)
		WriteError(w, NewApiError("invalid_credentials", "账号或密码错误"))
		return
	}
	if err != nil {
		WriteError(w, err)
		return
	}
	if status != "active" || bcrypt.CompareHashAndPassword([]byte(passwordHash), []byte(req.Password)) != nil {
		_ = recordLoginFailure(r.Context(), h.db, key)
		WriteError(w, NewApiError("invalid_credentials", "账号或密码错误"))
		return
	}

	token, csrfToken, err := h.sessions.CreateAdminSession(r.Context(), adminID, ip, r.UserAgent())
	if err != nil {
		WriteError(w, err)
		return
	}
	setSessionCookie(w, r, AdminSessionCookie, token)
	writeJSON(w, http.StatusOK, adminMeResponse{
		Admin:     adminMeUser{ID: adminID, Username: req.Username},
		CSRFToken: csrfToken,
	})
}

func (h *adminAuthHandler) logout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if c, err := r.Cookie(AdminSessionCookie); err == nil {
		_ = h.sessions.Delete(r.Context(), c.Value)
	}
	clearSessionCookie(w, r, AdminSessionCookie)
	w.WriteHeader(http.StatusNoContent)
}

func (h *adminAuthHandler) meOrPatch(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.me(w, r)
	case http.MethodPatch:
		h.patchMe(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *adminAuthHandler) me(w http.ResponseWriter, r *http.Request) {
	info := SessionFromContext(r.Context())
	var username string
	if err := h.db.QueryRowContext(r.Context(), `SELECT username FROM admin_users WHERE id = ?`, info.AdminUserID).
		Scan(&username); err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, adminMeResponse{
		Admin:     adminMeUser{ID: info.AdminUserID, Username: username},
		CSRFToken: info.CSRFToken,
	})
}

// patchMe 是平台管理员自助改密码，请求体与租户侧 patchMe 同形：{"password":{"old","new"}}。
// 必须一次事务里改两处：安装向导会用同一登录名、同一密码额外建一条 tenant_users owner
// （setup/bootstrap.go:72-74），只动 admin_users 的话后台密码变了、代理登录入口还能用旧密码进来。
// 会话失效范围跟着这条副本走，与 ResetPassword CLI 的判据保持一致。
func (h *adminAuthHandler) patchMe(w http.ResponseWriter, r *http.Request) {
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

	var username, currentHash string
	err := h.db.QueryRowContext(r.Context(),
		`SELECT username, password_hash FROM admin_users WHERE id = ?`, info.AdminUserID).
		Scan(&username, &currentHash)
	if err != nil {
		WriteError(w, err)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(req.Password.Old)) != nil {
		WriteError(w, NewApiError("validation_failed", "原密码不正确").
			WithDetails(map[string]any{"fields": map[string]string{"password.old": "不正确"}}))
		return
	}
	// 长度上限交给 hashPassword，它同时管住 bcrypt 静默截断的 72 字节。
	newHash, err := hashPassword(req.Password.New)
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
	if _, err := tx.ExecContext(r.Context(), `UPDATE admin_users SET password_hash = ? WHERE id = ?`,
		newHash, info.AdminUserID); err != nil {
		WriteError(w, err)
		return
	}
	if _, err := tx.ExecContext(r.Context(), `UPDATE tenant_users SET password_hash = ? WHERE email = ?`,
		newHash, username); err != nil {
		WriteError(w, err)
		return
	}
	if _, err := tx.ExecContext(r.Context(), `
		DELETE FROM sessions
		WHERE admin_user_id = ?
		   OR tenant_user_id IN (SELECT id FROM tenant_users WHERE email = ?)`,
		info.AdminUserID, username); err != nil {
		WriteError(w, err)
		return
	}
	if err := tx.Commit(); err != nil {
		WriteError(w, err)
		return
	}

	// 上面的删除把当前会话也一起清掉了，这里立刻重建一个，免得改完密码就被踢下线。
	token, csrfToken, err := h.sessions.CreateAdminSession(r.Context(), info.AdminUserID, clientIP(r), r.UserAgent())
	if err != nil {
		WriteError(w, err)
		return
	}
	setSessionCookie(w, r, AdminSessionCookie, token)
	writeJSON(w, http.StatusOK, adminMeResponse{
		Admin:     adminMeUser{ID: info.AdminUserID, Username: username},
		CSRFToken: csrfToken,
	})
}
