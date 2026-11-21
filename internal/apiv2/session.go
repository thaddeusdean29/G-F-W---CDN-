package apiv2

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"time"
)

const (
	TenantSessionCookie = "cdn_session"
	AdminSessionCookie  = "cdn_admin_session"
	sessionTTL          = 24 * time.Hour
	// renewThreshold：剩余有效期低于此值时才写库续期（滑动续期），
	// 避免每次请求都 UPDATE sessions。
	renewThreshold = 12 * time.Hour
)

type PrincipalType string

const (
	PrincipalTenant PrincipalType = "tenant"
	PrincipalAdmin  PrincipalType = "admin"
)

// SessionInfo 是校验通过后的会话身份，通过 context 传给 handler。
type SessionInfo struct {
	Principal    PrincipalType
	AdminUserID  string
	TenantUserID string
	TenantID     string
	CSRFToken    string
}

// SessionStore 是 sessions 表的数据访问层。会话存数据库而不是内存，
// 这样多台主控可以共享登录状态，重启也不会让用户掉线。
type SessionStore struct {
	db *sql.DB
}

func NewSessionStore(db *sql.DB) *SessionStore {
	return &SessionStore{db: db}
}

func newToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// hashToken 只把 token 的哈希存进数据库：DB 泄露不能直接拿去当会话使用。
func hashToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func nullableStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// CreateTenantSession 为租户用户创建新会话，返回 cookie 值与 CSRF token。
func (s *SessionStore) CreateTenantSession(ctx context.Context, tenantUserID, tenantID, ip, userAgent string) (token, csrfToken string, err error) {
	return s.create(ctx, PrincipalTenant, "", tenantUserID, tenantID, ip, userAgent)
}

// CreateAdminSession 为管理员创建新会话。
func (s *SessionStore) CreateAdminSession(ctx context.Context, adminUserID, ip, userAgent string) (token, csrfToken string, err error) {
	return s.create(ctx, PrincipalAdmin, adminUserID, "", "", ip, userAgent)
}

func (s *SessionStore) create(ctx context.Context, principal PrincipalType, adminUserID, tenantUserID, tenantID, ip, userAgent string) (string, string, error) {
	token, err := newToken()
	if err != nil {
		return "", "", err
	}
	csrfToken, err := newToken()
	if err != nil {
		return "", "", err
	}
	_, err = s.db.ExecContext(ctx, `
		INSERT INTO sessions (token_hash, principal_type, admin_user_id, tenant_user_id, tenant_id, csrf_token, ip, user_agent, expires_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		hashToken(token), string(principal), nullableStr(adminUserID), nullableStr(tenantUserID), nullableStr(tenantID),
		csrfToken, ip, userAgent, time.Now().UTC().Add(sessionTTL))
	if err != nil {
		return "", "", err
	}
	return token, csrfToken, nil
}

// Lookup 校验 cookie 值对应的会话是否有效，并在剩余有效期低于阈值时滑动续期。
// 会话不存在或已过期返回 (nil, nil)——调用方应视为未登录，不是内部错误。
func (s *SessionStore) Lookup(ctx context.Context, token string) (*SessionInfo, error) {
	th := hashToken(token)
	var (
		principal    string
		adminUserID  sql.NullString
		tenantUserID sql.NullString
		tenantID     sql.NullString
		csrfToken    string
		expiresAt    time.Time
	)
	err := s.db.QueryRowContext(ctx, `
		SELECT principal_type, admin_user_id, tenant_user_id, tenant_id, csrf_token, expires_at
		FROM sessions WHERE token_hash = ?`, th).
		Scan(&principal, &adminUserID, &tenantUserID, &tenantID, &csrfToken, &expiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	if now.After(expiresAt) {
		return nil, nil
	}
	if expiresAt.Sub(now) < renewThreshold {
		if _, err := s.db.ExecContext(ctx, `UPDATE sessions SET expires_at = ? WHERE token_hash = ?`,
			now.Add(sessionTTL), th); err != nil {
			return nil, err
		}
	}
	return &SessionInfo{
		Principal:    PrincipalType(principal),
		AdminUserID:  adminUserID.String,
		TenantUserID: tenantUserID.String,
		TenantID:     tenantID.String,
		CSRFToken:    csrfToken,
	}, nil
}

// Delete 删除单个会话（登出）。
func (s *SessionStore) Delete(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash = ?`, hashToken(token))
	return err
}

// DeleteAllForTenantUser 使某租户用户的全部会话失效（改密码后按 docs/API-v2.md §1 要求）。
func (s *SessionStore) DeleteAllForTenantUser(ctx context.Context, tenantUserID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE tenant_user_id = ?`, tenantUserID)
	return err
}

// DeleteAllForAdminUser 使某管理员的全部会话失效。
func (s *SessionStore) DeleteAllForAdminUser(ctx context.Context, adminUserID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE admin_user_id = ?`, adminUserID)
	return err
}

// CheckCSRF 用恒定时间比较校验请求头 X-CSRF-Token，防止时序攻击探测 token 内容。
func CheckCSRF(info *SessionInfo, r *http.Request) bool {
	header := r.Header.Get("X-CSRF-Token")
	if header == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(header), []byte(info.CSRFToken)) == 1
}
