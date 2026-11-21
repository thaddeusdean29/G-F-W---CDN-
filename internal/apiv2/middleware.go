package apiv2

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
)

type contextKey int

const sessionContextKey contextKey = 0

func withSession(ctx context.Context, info *SessionInfo) context.Context {
	return context.WithValue(ctx, sessionContextKey, info)
}

// SessionFromContext 返回当前请求的会话身份；未登录时为 nil。
func SessionFromContext(ctx context.Context) *SessionInfo {
	info, _ := ctx.Value(sessionContextKey).(*SessionInfo)
	return info
}

// RequireTenantSession 校验 cdn_session cookie，把身份放进 context 后交给 next。
// 未登录、会话过期或该会话属于管理员身份时统一返回 401 unauthenticated——不区分
// "没带 cookie" 和 "带的是管理员 cookie"，避免给攻击者提供探测信息。
func RequireTenantSession(store *SessionStore) func(http.Handler) http.Handler {
	return requireSession(store, TenantSessionCookie, PrincipalTenant)
}

// RequireAdminSession 是 RequireTenantSession 的管理员对应版本。
func RequireAdminSession(store *SessionStore) func(http.Handler) http.Handler {
	return requireSession(store, AdminSessionCookie, PrincipalAdmin)
}

func requireSession(store *SessionStore, cookieName string, want PrincipalType) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(cookieName)
			if err != nil {
				WriteError(w, NewApiError("unauthenticated", "未登录"))
				return
			}
			info, err := store.Lookup(r.Context(), cookie.Value)
			if err != nil {
				WriteError(w, err)
				return
			}
			if info == nil || info.Principal != want {
				WriteError(w, NewApiError("unauthenticated", "未登录"))
				return
			}
			next.ServeHTTP(w, r.WithContext(withSession(r.Context(), info)))
		})
	}
}

// RequireCSRF 对非 GET/HEAD/OPTIONS 请求校验 X-CSRF-Token 头。必须放在
// RequireTenantSession / RequireAdminSession 之后，依赖 context 里已有的 SessionInfo。
func RequireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet, http.MethodHead, http.MethodOptions:
			next.ServeHTTP(w, r)
			return
		}
		info := SessionFromContext(r.Context())
		if info == nil || !CheckCSRF(info, r) {
			WriteError(w, NewApiError("csrf_invalid", "CSRF 校验失败"))
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requestIsHTTPS 判断浏览器看到的是不是 HTTPS。面板常被直接用 http://IP:8080 访问，
// 这时给 cookie 加 Secure 浏览器会直接丢弃，表现为「登录成功却提示未登录」。
// X-Forwarded-Proto 只用来决定是否加 Secure（只会更严格），不参与任何鉴权。
func requestIsHTTPS(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0]), "https")
}

func setSessionCookie(w http.ResponseWriter, r *http.Request, name, value string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   requestIsHTTPS(r),
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
