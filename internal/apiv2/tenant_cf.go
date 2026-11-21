package apiv2

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"cdn/internal/cloudflare"
	"cdn/internal/secure"
)

// tenantCFHandler 实现 GET/PUT/DELETE /api/v2/cf-credentials 与 POST /api/v2/cf-credentials/test。
// 每个代理（租户）各存一份 Cloudflare token/zone/根域名，按 tenant_id 隔离，互相不可见；
// token 加密落库（secure.Encrypt），响应里只给 api_token_set/api_token_hint，绝不回显明文。
type tenantCFHandler struct {
	db *sql.DB
}

var cfCredentialFields = []string{"api_token", "zone_id", "base_domain", "enabled"}

var (
	zoneIDPattern     = regexp.MustCompile(`^[a-f0-9]{32}$`)
	baseDomainPattern = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)
)

type tenantCFRow struct {
	token      string
	zoneID     string
	baseDomain string
	enabled    bool
	verifiedAt sql.NullTime
	lastError  sql.NullString
	updatedAt  time.Time
}

func loadTenantCF(ctx context.Context, db *sql.DB, tenantID string) (*tenantCFRow, error) {
	var enc []byte
	row := &tenantCFRow{}
	err := db.QueryRowContext(ctx, `SELECT api_token_enc, zone_id, base_domain, enabled, verified_at, last_error, updated_at
		FROM tenant_cf_credentials WHERE tenant_id = ?`, tenantID).
		Scan(&enc, &row.zoneID, &row.baseDomain, &row.enabled, &row.verifiedAt, &row.lastError, &row.updatedAt)
	if err != nil {
		return nil, err
	}
	plain, err := secure.Decrypt(enc)
	if err != nil {
		return nil, err
	}
	row.token = string(plain)
	return row, nil
}

// tenantCF 返回该代理自己的 Cloudflare 客户端。未配置或已停用时返回一个 Enabled()==false
// 的空客户端，调用方按原有逻辑报 cf_not_configured。绝不回落到 config.json 里的全局凭据，
// 否则代理 A 的域名会被写进平台（或别的代理）的 zone。
func tenantCF(ctx context.Context, db *sql.DB, tenantID string) (*cloudflare.Client, error) {
	row, err := loadTenantCF(ctx, db, tenantID)
	if errors.Is(err, sql.ErrNoRows) {
		return cloudflare.NewClient("", "", ""), nil
	}
	if err != nil {
		return nil, err
	}
	if !row.enabled {
		return cloudflare.NewClient("", "", ""), nil
	}
	return cloudflare.NewClient(row.token, row.zoneID, row.baseDomain), nil
}

func renderTenantCF(row *tenantCFRow) map[string]any {
	out := map[string]any{
		"configured":  row != nil,
		"zone_id":     "",
		"base_domain": "",
		"enabled":     false,
		"verified_at": nil,
		"last_error":  "",
	}
	token := ""
	if row != nil {
		token = row.token
		out["zone_id"] = row.zoneID
		out["base_domain"] = row.baseDomain
		out["enabled"] = row.enabled
		if row.verifiedAt.Valid {
			out["verified_at"] = row.verifiedAt.Time
		}
		out["last_error"] = row.lastError.String
		out["updated_at"] = row.updatedAt
	}
	for k, v := range SecretFields("api_token", token) {
		out[k] = v
	}
	return out
}

func (h *tenantCFHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tenantID := SessionFromContext(r.Context()).TenantID
	if r.URL.Path == "/api/v2/cf-credentials/test" {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		h.test(w, r, tenantID)
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.get(w, r, tenantID)
	case http.MethodPut, http.MethodPatch:
		h.put(w, r, tenantID)
	case http.MethodDelete:
		if _, err := h.db.ExecContext(r.Context(), `DELETE FROM tenant_cf_credentials WHERE tenant_id = ?`, tenantID); err != nil {
			WriteError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *tenantCFHandler) get(w http.ResponseWriter, r *http.Request, tenantID string) {
	row, err := loadTenantCF(r.Context(), h.db, tenantID)
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusOK, renderTenantCF(nil))
		return
	}
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, renderTenantCF(row))
}

// put 保存凭据。api_token 走三态语义：不传=保留原值，传字符串=替换；不允许 null 清除
// （要清空整份凭据用 DELETE）。保存前会用新凭据实际调一次 Cloudflare 验证 zone，
// 验证失败直接 422 不落库，避免存进一份不能用的 token。
func (h *tenantCFHandler) put(w http.ResponseWriter, r *http.Request, tenantID string) {
	body, fields, err := decodeKnownFields(r, cfCredentialFields)
	if err != nil {
		WriteError(w, err)
		return
	}
	var req struct {
		ZoneID     *string `json:"zone_id"`
		BaseDomain *string `json:"base_domain"`
		Enabled    *bool   `json:"enabled"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		WriteError(w, NewApiError("invalid_json", "请求体不是合法 JSON"))
		return
	}
	intent, token, err := ParseSecretField(fields, "api_token", false)
	if err != nil {
		WriteError(w, err)
		return
	}

	existing, err := loadTenantCF(r.Context(), h.db, tenantID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		WriteError(w, err)
		return
	}
	next := tenantCFRow{enabled: true}
	if existing != nil {
		next = *existing
	}
	if intent == SecretReplace {
		next.token = strings.TrimSpace(token)
	}
	if req.ZoneID != nil {
		next.zoneID = strings.ToLower(strings.TrimSpace(*req.ZoneID))
	}
	if req.BaseDomain != nil {
		next.baseDomain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(*req.BaseDomain)), ".")
	}
	if req.Enabled != nil {
		next.enabled = *req.Enabled
	}

	bad := map[string]string{}
	if next.token == "" {
		bad["api_token"] = "必填"
	}
	if !zoneIDPattern.MatchString(next.zoneID) {
		bad["zone_id"] = "应为 32 位十六进制 Zone ID"
	}
	if !baseDomainPattern.MatchString(next.baseDomain) {
		bad["base_domain"] = "应为合法根域名，如 example.com"
	}
	if len(bad) > 0 {
		WriteError(w, NewApiError("validation_failed", "Cloudflare 配置不完整").WithDetails(map[string]any{"fields": bad}))
		return
	}

	if err := verifyCF(next.token, next.zoneID, next.baseDomain); err != nil {
		WriteError(w, NewApiError("upstream_failed", "Cloudflare 验证失败: "+err.Error()))
		return
	}

	enc, err := secure.Encrypt([]byte(next.token))
	if err != nil {
		WriteError(w, err)
		return
	}
	_, err = h.db.ExecContext(r.Context(), `INSERT INTO tenant_cf_credentials
		(tenant_id, api_token_enc, zone_id, base_domain, enabled, verified_at, last_error)
		VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP(6), NULL)
		ON DUPLICATE KEY UPDATE api_token_enc = VALUES(api_token_enc), zone_id = VALUES(zone_id),
			base_domain = VALUES(base_domain), enabled = VALUES(enabled),
			verified_at = VALUES(verified_at), last_error = NULL`,
		tenantID, enc, next.zoneID, next.baseDomain, next.enabled)
	if err != nil {
		WriteError(w, err)
		return
	}
	if next.enabled {
		go backfillTenantNodeDNS(h.db, tenantID)
	}
	h.get(w, r, tenantID)
}

// test 用已保存的凭据重新验证一次，把结果记到 verified_at / last_error。
func (h *tenantCFHandler) test(w http.ResponseWriter, r *http.Request, tenantID string) {
	row, err := loadTenantCF(r.Context(), h.db, tenantID)
	if errors.Is(err, sql.ErrNoRows) {
		WriteError(w, NewApiError("cf_not_configured", "Cloudflare 未配置"))
		return
	}
	if err != nil {
		WriteError(w, err)
		return
	}
	if verr := verifyCF(row.token, row.zoneID, row.baseDomain); verr != nil {
		msg := verr.Error()
		if len(msg) > 1000 {
			msg = msg[:1000]
		}
		_, _ = h.db.ExecContext(r.Context(), `UPDATE tenant_cf_credentials SET last_error = ? WHERE tenant_id = ?`, msg, tenantID)
		writeJSON(w, http.StatusOK, map[string]any{"ok": false, "error": msg})
		return
	}
	_, _ = h.db.ExecContext(r.Context(), `UPDATE tenant_cf_credentials SET verified_at = CURRENT_TIMESTAMP(6), last_error = NULL WHERE tenant_id = ?`, tenantID)
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// verifyCF 确认 token 能读这个 zone，并且 base_domain 就是该 zone 或其子域名。
// 错误信息里不带 token。
func verifyCF(token, zoneID, baseDomain string) error {
	zoneName, err := cloudflare.NewClient(token, zoneID, baseDomain).VerifyZone()
	if err != nil {
		return err
	}
	zoneName = strings.ToLower(zoneName)
	if baseDomain != zoneName && !strings.HasSuffix(baseDomain, "."+zoneName) {
		return errors.New("根域名 " + baseDomain + " 不属于该 Zone（" + zoneName + "）")
	}
	return nil
}
