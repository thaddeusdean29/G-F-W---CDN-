package apiv2

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"cdn/internal/master"
	"cdn/internal/secure"

	"github.com/google/uuid"
)

// 证书上传：POST /api/v2/domains/{id}/certificate {cert_pem, key_pem, force_https?}
// 私钥用 secure.Encrypt 落库（key_pem_enc），任何接口都不返回私钥；GET 只返回证书元数据。
// 下发到边缘时由 domainPushPayload 解密后随域名配置一起推送，边缘写到 /etc/ssl/cdnpanel/<domain>/。

type certificateResponse struct {
	ID        string   `json:"id"`
	DomainID  string   `json:"domain_id"`
	Source    string   `json:"source"`
	Issuer    string   `json:"issuer"`
	Subject   string   `json:"subject"`
	DNSNames  []string `json:"dns_names"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	InUse     bool     `json:"in_use"`
	CreatedAt string   `json:"created_at"`
}

// edgeCertPaths 与模板 / 边缘 handler 的约定一致：必须位于 /etc/ssl/cdnpanel/ 下。
func edgeCertPaths(domain string) (string, string) {
	base := "/etc/ssl/cdnpanel/" + domain + "/"
	return base + "cert.pem", base + "key.pem"
}

func (h *domainsHandler) certificate(w http.ResponseWriter, r *http.Request, tenantID, id string) {
	d, err := h.repo.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.getCertificate(w, r, tenantID, d)
	case http.MethodPost:
		h.uploadCertificate(w, r, tenantID, d)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func currentCertID(d *Domain) string {
	var ssl domainSSL
	if len(d.SSLConfig) == 0 || json.Unmarshal(d.SSLConfig, &ssl) != nil || ssl.CertificateID == nil {
		return ""
	}
	return *ssl.CertificateID
}

// getCertificate 返回域名当前的证书元数据。ssl_config 引用的证书优先；引用缺失（例如 HTTPS 被
// 「关闭」保存过、或 ssl_config 被旧逻辑覆盖）但库里仍有该域名的证书时，返回最近一张并标记
// in_use=false——否则前端显示「未上传」，用户以为上传失败，实际是证书在库里但没启用。
func (h *domainsHandler) getCertificate(w http.ResponseWriter, r *http.Request, tenantID string, d *Domain) {
	resp, err := h.lookupCertificate(r.Context(), tenantID, d)
	if err != nil {
		WriteError(w, err)
		return
	}
	if resp == nil {
		writeJSON(w, http.StatusOK, map[string]any{"certificate": nil})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"certificate": resp})
}

func (h *domainsHandler) lookupCertificate(ctx context.Context, tenantID string, d *Domain) (*certificateResponse, error) {
	var ssl domainSSL
	_ = json.Unmarshal(d.SSLConfig, &ssl)
	certID := currentCertID(d)
	var (
		id, source, certPEM, issuer    string
		notBefore, notAfter, createdAt time.Time
	)
	scan := func(row *sql.Row) error {
		return row.Scan(&id, &source, &certPEM, &issuer, &notBefore, &notAfter, &createdAt)
	}
	err := sql.ErrNoRows
	if certID != "" {
		err = scan(h.db.QueryRowContext(ctx,
			`SELECT id, source, cert_pem, issuer, not_before, not_after, created_at FROM certificates
			 WHERE tenant_id = ? AND domain_id = ? AND id = ?`, tenantID, d.ID, certID))
	}
	if errors.Is(err, sql.ErrNoRows) {
		err = scan(h.db.QueryRowContext(ctx,
			`SELECT id, source, cert_pem, issuer, not_before, not_after, created_at FROM certificates
			 WHERE tenant_id = ? AND domain_id = ? ORDER BY created_at DESC LIMIT 1`, tenantID, d.ID))
	}
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	resp := &certificateResponse{
		ID: id, DomainID: d.ID, Source: source, Issuer: issuer, DNSNames: []string{},
		NotBefore: notBefore.UTC().Format(rfc3339Milli), NotAfter: notAfter.UTC().Format(rfc3339Milli),
		InUse:     ssl.Mode == "manual" && id == certID,
		CreatedAt: createdAt.UTC().Format(rfc3339Milli),
	}
	if leaf := parseLeaf(certPEM); leaf != nil {
		resp.Subject = leaf.Subject.CommonName
		resp.DNSNames = append(resp.DNSNames, leaf.DNSNames...)
	}
	return resp, nil
}

// certBelongsTo 校验 certificate_id 属于该租户的该域名。PATCH ssl.mode=manual 只能引用本域名
// 已上传的证书，不能填任意 ID（填错会让下发时静默降级为不启用 HTTPS）。
func certBelongsTo(ctx context.Context, db *sql.DB, tenantID, domainID, certID string) (bool, error) {
	var one int
	err := db.QueryRowContext(ctx,
		`SELECT 1 FROM certificates WHERE tenant_id = ? AND domain_id = ? AND id = ?`, tenantID, domainID, certID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

func parseLeaf(certPEM string) *x509.Certificate {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return nil
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return leaf
}

func certFieldError(field, msg string) error {
	return NewApiError("validation_failed", msg).
		WithDetails(map[string]any{"fields": map[string]string{field: msg}})
}

// storedCert 是「存一张证书并让它对该域名生效」的入参。上传证书和 ACME 自助签发共用这段尾巴：
// 两条路只有证书来源不同，落库形态（私钥加密、ssl_config 切成 manual、旧证书清掉）必须一致，
// 否则会出现「上传的证书能下发、签发的不能下发」这种只在生产看到的差别。
type storedCert struct {
	TenantID   string
	DomainID   string
	DomainName string
	Source     string // certificates.source 的 CHECK 只允许 upload / acme
	CertPEM    string
	KeyPEM     string
}

// storeCertificate 校验证书与私钥配对、覆盖该域名、未过期，然后加密私钥落库并把域名的
// ssl_config 切到 manual + 新证书 ID。返回新证书 ID 与解析出的叶子证书。
//
// 校验失败复用 certFieldError（400 + details.fields），调用方直接 WriteError 就是文档承诺的形状。
func storeCertificate(ctx context.Context, db *sql.DB, in storedCert) (string, *x509.Certificate, error) {
	pair, err := tls.X509KeyPair([]byte(in.CertPEM), []byte(in.KeyPEM))
	if err != nil {
		return "", nil, certFieldError("cert_pem", "证书与私钥不匹配或格式错误: "+err.Error())
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return "", nil, certFieldError("cert_pem", "证书解析失败")
	}
	now := time.Now()
	if now.After(leaf.NotAfter) {
		return "", nil, certFieldError("cert_pem", "证书已过期（"+leaf.NotAfter.Format("2006-01-02")+"）")
	}
	if err := leaf.VerifyHostname(in.DomainName); err != nil {
		return "", nil, certFieldError("cert_pem", "证书不包含域名 "+in.DomainName)
	}
	keyEnc, err := secure.Encrypt([]byte(in.KeyPEM))
	if err != nil {
		return "", nil, err
	}
	issuer := leaf.Issuer.CommonName
	if issuer == "" && len(leaf.Issuer.Organization) > 0 {
		issuer = leaf.Issuer.Organization[0]
	}
	if len(issuer) > 255 {
		issuer = issuer[:255]
	}

	certID := uuid.New().String()
	// 全部域名强制 HTTPS（边缘模板无条件输出 80 → 301），force_https 只读，一律存 true。
	ssl := domainSSL{Mode: "manual", CertificateID: &certID, ForceHTTPS: true}
	sslJSON, _ := json.Marshal(ssl)

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return "", nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx,
		`INSERT INTO certificates (id, tenant_id, domain_id, source, cert_pem, key_pem_enc, issuer, not_before, not_after)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		certID, in.TenantID, in.DomainID, in.Source, in.CertPEM, keyEnc, issuer, leaf.NotBefore.UTC(), leaf.NotAfter.UTC()); err != nil {
		return "", nil, err
	}
	// 旧证书不再被引用，直接清掉（私钥密文不留存）。
	if _, err := tx.ExecContext(ctx,
		`DELETE FROM certificates WHERE tenant_id = ? AND domain_id = ? AND id <> ?`, in.TenantID, in.DomainID, certID); err != nil {
		return "", nil, err
	}
	res, err := tx.ExecContext(ctx,
		`UPDATE domains SET ssl_config = ?, version = version + 1 WHERE tenant_id = ? AND id = ?`,
		sslJSON, in.TenantID, in.DomainID)
	if err != nil {
		return "", nil, err
	}
	if n, err := res.RowsAffected(); err != nil || n == 0 {
		return "", nil, notFoundOr(sql.ErrNoRows)
	}
	if err := tx.Commit(); err != nil {
		return "", nil, err
	}
	return certID, leaf, nil
}

// renderCertificate 把一张已入库证书元数据化成对外形状（签发成功后作业结果里也用它）。
func renderCertificate(certID, source string, leaf *x509.Certificate, d *Domain, createdAt time.Time) certificateResponse {
	return certificateResponse{
		ID:        certID,
		DomainID:  d.ID,
		Source:    source,
		Issuer:    leaf.Issuer.CommonName,
		Subject:   leaf.Subject.CommonName,
		DNSNames:  append([]string{}, leaf.DNSNames...),
		NotBefore: leaf.NotBefore.UTC().Format(rfc3339Milli),
		NotAfter:  leaf.NotAfter.UTC().Format(rfc3339Milli),
		InUse:     true,
		CreatedAt: createdAt.UTC().Format(rfc3339Milli),
	}
}

func (h *domainsHandler) uploadCertificate(w http.ResponseWriter, r *http.Request, tenantID string, d *Domain) {
	raw, _, err := decodeKnownFields(r, []string{"cert_pem", "key_pem", "force_https"})
	if err != nil {
		WriteError(w, err)
		return
	}
	var req struct {
		CertPEM    string `json:"cert_pem"`
		KeyPEM     string `json:"key_pem"`
		ForceHTTPS *bool  `json:"force_https"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		WriteError(w, NewApiError("validation_failed", "cert_pem / key_pem 必须是字符串"))
		return
	}
	req.CertPEM = strings.TrimSpace(req.CertPEM) + "\n"
	req.KeyPEM = strings.TrimSpace(req.KeyPEM) + "\n"

	certID, leaf, err := storeCertificate(r.Context(), h.db, storedCert{
		TenantID: tenantID, DomainID: d.ID, DomainName: d.Domain, Source: "upload",
		CertPEM: req.CertPEM, KeyPEM: req.KeyPEM,
	})
	if err != nil {
		WriteError(w, err)
		return
	}
	updated, err := h.repo.Get(r.Context(), tenantID, d.ID)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"domain":      renderDomain(updated),
		"certificate": renderCertificate(certID, "upload", leaf, d, time.Now()),
	})
}

// loadCertPair 读出（租户隔离的）证书与解密后的私钥。
func loadCertPair(ctx context.Context, db *sql.DB, tenantID, domainID, certID string) (string, string, error) {
	var certPEM string
	var keyEnc []byte
	if err := db.QueryRowContext(ctx,
		`SELECT cert_pem, key_pem_enc FROM certificates WHERE tenant_id = ? AND domain_id = ? AND id = ?`,
		tenantID, domainID, certID).Scan(&certPEM, &keyEnc); err != nil {
		return "", "", err
	}
	key, err := secure.Decrypt(keyEnc)
	if err != nil {
		return "", "", fmt.Errorf("decrypt key: %w", err)
	}
	return certPEM, string(key), nil
}

// domainPushPayload 把 v2 域名转成边缘下发 payload。manual 模式带上证书内容；
// 证书缺失/解密失败时降级为不启用 HTTPS——否则边缘模板会引用不存在的证书文件，
// tengine -t 失败会连累整台节点所有站点的 443。
func domainPushPayload(ctx context.Context, db *sql.DB, d *Domain) (*master.DomainPushPayload, error) {
	cd, err := convertDomainToConfig(d)
	if err != nil {
		return nil, err
	}
	// 域名没有自己的缓存规则：用本代理在「缓存」页保存的默认规则（没保存过就是平台默认）。
	if usesDefaultCache(d) {
		rules, err := tenantCacheRules(ctx, db, d.TenantID)
		if err != nil {
			log.Printf("[apiv2] domain %s: load tenant cache rules failed, using platform default: %v", d.Domain, err)
		} else {
			cd.CacheRules = rules
		}
	}
	p := &master.DomainPushPayload{Domain: *cd}
	if cd.SSL.Enabled && cd.SSL.Mode == "manual" {
		certPEM, keyPEM, err := loadCertPair(ctx, db, d.TenantID, d.ID, currentCertID(d))
		if err != nil {
			log.Printf("[apiv2] domain %s: load certificate failed, pushing without HTTPS: %v", d.Domain, err)
			p.Domain.SSL = disabledSSL()
		} else {
			p.CertPEM, p.KeyPEM = certPEM, keyPEM
		}
	}
	return p, nil
}
