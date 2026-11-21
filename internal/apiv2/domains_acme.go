package apiv2

import (
	"context"
	"crypto/ecdsa"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"cdn/internal/acme"
	"cdn/internal/cloudflare"
	"cdn/internal/config"
	"cdn/internal/secure"
)

// 自助申请 Let's Encrypt 证书：POST /api/v2/domains/{id}/certificate/acme → 202 Job。
//
// 验证方式是 dns-01，用本代理在「设置 → Cloudflare」里保存的那份凭据写 TXT 校验记录。
// 不要求源站可达、也不要求边缘做任何事（边缘本来就没有 autocert 实现），所以域名哪怕
// 还挂着橙云、哪怕还没切到本集群，只要 DNS 权威在这个 zone 里就能签。
//
// 前置条件全部在发起请求时就判掉，不塞进一个还要用户去盯的异步任务里：
//  1. 域名已完成所有权验证（_cdn-verify 那条 TXT）；
//  2. 本代理配置并启用了 Cloudflare 凭据；
//  3. 域名属于那个 Zone——面板只能改自己 zone 的记录，别人的 zone 写不进去。
//
// 签完按 source='acme' 入库、ssl_config 切到 manual，并立刻下发到该域名所在集群的节点
// （不下发的话要等一次 resync 才有 HTTPS）。到期不自动续：面板只做签发，界面显示剩余
// 天数，用户在到期前重新点一次。

const (
	acmeJobType = "domain.acme"
	// 一次签发的总预算：下单、等 CA 查 DNS、签发、下发。CF 写记录是秒级，但 CA 侧的
	// 解析缓存、重试和限流退避都得留出时间。
	acmeBudget = 8 * time.Minute
	// 单个授权等待校验结果的上限（CA 查不到 TXT 时会长时间停在 processing）。
	acmeAuthzWait = 4 * time.Minute
	// 作业失败文案的长度上限：jobs.message 是 VARCHAR(2048)，CA 的 problem document
	// 偶尔带一大段，超了会被数据库截断成半句话，不如自己截。
	acmeMessageMax = 1800
)

// issueCertificate 是签发端点：只做同步可判的前置检查，然后开作业立刻回 202。
// 签发要等 CA，同步等待会把请求挂几分钟，面板的 WriteTimeout 和用户的耐心都撑不住。
func (h *domainsHandler) issueCertificate(w http.ResponseWriter, r *http.Request, tenantID, id string) {
	d, err := h.repo.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	if !d.VerifiedAt.Valid {
		WriteError(w, NewApiError("domain_unverified", "域名尚未完成所有权验证，不能申请证书"))
		return
	}
	cf, err := tenantCF(r.Context(), h.db, tenantID)
	if err != nil {
		WriteError(w, err)
		return
	}
	if !cf.Enabled() {
		WriteError(w, NewApiError("cf_not_configured",
			"未配置（或已停用）Cloudflare 凭证：自助申请要用它在域名所在 Zone 写一条 DNS 校验记录"))
		return
	}
	if !cf.InZone(d.Domain) {
		WriteError(w, NewApiError("acme_unsupported",
			"域名 "+d.Domain+" 不在已配置的 Cloudflare Zone（"+cf.BaseDomain+"）里，面板写不进校验记录；请改用上传证书"))
		return
	}
	running, err := acmeJobRunning(r.Context(), h.db, tenantID, d.ID)
	if err != nil {
		WriteError(w, err)
		return
	}
	if running {
		WriteError(w, NewApiError("conflict", "该域名的证书申请还在进行中"))
		return
	}

	params, _ := json.Marshal(map[string]string{"domain_id": d.ID, "domain": d.Domain})
	job, err := h.jobRepo.Create(r.Context(), tenantID, acmeJobType, "", params)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJobAccepted(w, job)
	go h.runAcme(job.ID, tenantID, d, cf)
}

// runAcme 在请求之外跑完整签发流程。
//
// 收尾（标记失败、删 TXT）一律另起 context：作业预算耗尽时 ctx 已经过期，
// 拿它去写库只会让 job 永远停在 running，前端一直转圈。
func (h *domainsHandler) runAcme(jobID, tenantID string, d *Domain, cf *cloudflare.Client) {
	ctx, cancel := context.WithTimeout(context.Background(), acmeBudget)
	defer cancel()

	if err := h.issueAcme(ctx, jobID, tenantID, d, cf); err != nil {
		msg := acmeMessage(err)
		log.Printf("[apiv2] acme issue failed tenant=%s domain=%s job=%s: %s", tenantID, d.Domain, jobID, msg)
		tail, tailCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer tailCancel()
		_ = h.jobRepo.MarkFailed(tail, jobID, msg)
	}
}

func (h *domainsHandler) issueAcme(ctx context.Context, jobID, tenantID string, d *Domain, cf *cloudflare.Client) error {
	dir := h.acmeDirectory()
	_ = h.jobRepo.UpdateProgress(ctx, jobID, 5, "正在准备 ACME 账号...")
	acct, err := loadAcmeAccount(ctx, h.db, tenantID, dir)
	if err != nil {
		return err
	}
	cl, err := acme.NewClient(ctx, dir, acct.key)
	if err != nil {
		return err
	}
	if acct.accountURL != "" {
		cl.SetAccountURL(acct.accountURL)
	}
	if err := cl.EnsureAccount(ctx); err != nil {
		return err
	}
	if cl.AccountURL() != acct.accountURL {
		if err := saveAcmeAccountURL(ctx, h.db, tenantID, cl.AccountURL(), dir); err != nil {
			return err
		}
	}

	_ = h.jobRepo.UpdateProgress(ctx, jobID, 20, "正在向 CA 下单...")
	order, err := cl.OrderDomains(ctx, []string{d.Domain})
	if err != nil {
		return err
	}
	pending, _, ok, err := cl.AuthzPending(ctx, order)
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("CA 把这次下单判为无效（%s），请稍后再试或改用上传证书", order.URL())
	}

	// 校验记录用完就必须清掉：留在 zone 里的旧 TXT 没有作用，还会让下一次申请面对
	// 同名多条记录（CA 对这种情况的处理并不统一）。
	// cloudflare 客户端自带每请求 15 秒超时、不吃调用方 context，所以作业超时也不会把这段带走。
	var txtNames []string
	defer func() {
		for _, name := range txtNames {
			if err := cf.DeleteTXTRecords(name); err != nil {
				log.Printf("[apiv2] acme cleanup TXT %s failed: %v", name, err)
			}
		}
	}()

	_ = h.jobRepo.UpdateProgress(ctx, jobID, 35, "正在写入 DNS 校验记录...")
	for _, a := range pending {
		domain, name, value, err := cl.DNS01Record(ctx, a.URL)
		if err != nil {
			return err
		}
		if domain == "" {
			domain = d.Domain
		}
		if !cf.InZone(name) {
			return fmt.Errorf("校验记录 %s 不在 Zone（%s）里", name, cf.BaseDomain)
		}
		if _, err := cf.SetTXTRecord(name, value); err != nil {
			return fmt.Errorf("写入 DNS 校验记录失败: %w", err)
		}
		txtNames = append(txtNames, name)
		if err := cl.Accept(ctx, a.URL); err != nil {
			return err
		}
	}

	_ = h.jobRepo.UpdateProgress(ctx, jobID, 50, "等待 CA 校验域名...")
	for _, a := range pending {
		if err := cl.WaitAuthz(ctx, a.URL, acmeAuthzWait); err != nil {
			return err
		}
	}

	_ = h.jobRepo.UpdateProgress(ctx, jobID, 70, "正在签发证书...")
	certPEM, keyPEM, err := cl.Finalize(ctx, order)
	if err != nil {
		return err
	}

	_ = h.jobRepo.UpdateProgress(ctx, jobID, 82, "正在保存并下发证书...")
	certID, leaf, err := storeCertificate(ctx, h.db, storedCert{
		TenantID: tenantID, DomainID: d.ID, DomainName: d.Domain, Source: "acme",
		CertPEM: certPEM, KeyPEM: keyPEM,
	})
	if err != nil {
		return err
	}
	updated, err := h.repo.Get(ctx, tenantID, d.ID)
	if err != nil {
		return err
	}
	payload, err := domainPushPayload(ctx, h.db, updated)
	if err != nil {
		return err
	}
	clusterID := ""
	if d.ClusterID.Valid {
		clusterID = d.ClusterID.String
	}
	results := h.fanout(ctx, tenantID, clusterID, func(n *config.Node) error {
		return h.pusher.PostToNode(n, "/edge/domains", payload)
	})
	resultJSON, _ := json.Marshal(map[string]any{
		"certificate": renderCertificate(certID, "acme", leaf, d, time.Now()),
		"nodes":       results,
	})
	var warnings []string
	failed := 0
	for _, msg := range results {
		if msg != "ok" {
			failed++
		}
	}
	if failed > 0 {
		warnings = append(warnings, fmt.Sprintf("%d 个节点下发失败，证书已在面板入库，可稍后对该域名重新下发", failed))
	}
	if len(results) == 0 {
		warnings = append(warnings, "本代理还没有可用节点，证书已入库，接入节点后自动带上")
	}
	return h.jobRepo.MarkDone(ctx, jobID, resultJSON, strings.Join(warnings, "；"))
}

// acmeDirectory 返回本次签发用的 CA directory URL（空串按 Let's Encrypt 正式环境）。
func (h *domainsHandler) acmeDirectory() string {
	if h.acmeDir == "" {
		return acme.ProductionDirectory
	}
	return h.acmeDir
}

// acmeJobRunning 判断该域名是否已有一个还在跑的签发作业。params 里存了 domain_id，
// 所以按域名精确判——不同域名并发申请互不影响（CA 的限流也是按注册域名算的）。
func acmeJobRunning(ctx context.Context, db *sql.DB, tenantID, domainID string) (bool, error) {
	var n int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM jobs WHERE tenant_id = ? AND type = ?
		AND status IN ('pending', 'running')
		AND JSON_UNQUOTE(JSON_EXTRACT(params, '$.domain_id')) = ?`,
		tenantID, acmeJobType, domainID).Scan(&n)
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// acmeAccount 是一个代理自己的 ACME 账号。私钥只在内存里存在，库里是 secure.Encrypt 后的 DER。
type acmeAccount struct {
	key        *ecdsa.PrivateKey
	thumbprint string
	// accountURL 为该空串表示还没在这家 CA 注册过；directory 变了必须丢掉（账号属于别家 CA）。
	accountURL string
	directory  string
}

// loadAcmeAccount 取出本代理的 ACME 账号，没有就用新生成的私钥建一条。
//
// 两个代理用户同时点申请时两边都读到「没有」，插入会撞主键——那不是故障，是并发：
// 撞了就重新读一次，用先落库的那把私钥。否则同一时刻会产生两个不同账号，
// 之后的 accountURL 归属就不清楚了。
func loadAcmeAccount(ctx context.Context, db *sql.DB, tenantID, directory string) (*acmeAccount, error) {
	a, err := readAcmeAccount(ctx, db, tenantID, directory)
	if err == nil {
		return a, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	key, err := acme.NewAccountKey()
	if err != nil {
		return nil, err
	}
	tp, err := acme.AccountThumbprint(key)
	if err != nil {
		return nil, err
	}
	der, err := acme.FormatAccountKey(key)
	if err != nil {
		return nil, err
	}
	enc, err := secure.Encrypt(der)
	if err != nil {
		return nil, err
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO acme_accounts (tenant_id, key_enc, thumbprint, account_url, directory)
		VALUES (?, ?, ?, '', ?)`, tenantID, enc, tp, directory); err != nil {
		other, rerr := readAcmeAccount(ctx, db, tenantID, directory)
		if rerr == nil {
			return other, nil
		}
		return nil, err
	}
	return readAcmeAccount(ctx, db, tenantID, directory)
}

func readAcmeAccount(ctx context.Context, db *sql.DB, tenantID, directory string) (*acmeAccount, error) {
	var keyEnc []byte
	var url, dir string
	err := db.QueryRowContext(ctx, `SELECT key_enc, account_url, directory FROM acme_accounts WHERE tenant_id = ?`, tenantID).
		Scan(&keyEnc, &url, &dir)
	if err != nil {
		return nil, err
	}
	plain, err := secure.Decrypt(keyEnc)
	if err != nil {
		return nil, fmt.Errorf("解密 ACME 账号私钥失败: %w", err)
	}
	key, err := acme.ParseAccountKey(plain)
	if err != nil {
		return nil, err
	}
	tp, err := acme.AccountThumbprint(key)
	if err != nil {
		return nil, err
	}
	if dir != directory {
		// 换了 CA 目录（正式 ↔ 测试，或换服务商）：旧账号 URL 是新 CA 不认识的地址。
		// 私钥可以照用，账号到新 CA 那边重新注册一次。
		url = ""
	}
	return &acmeAccount{key: key, thumbprint: tp, accountURL: url, directory: directory}, nil
}

func saveAcmeAccountURL(ctx context.Context, db *sql.DB, tenantID, accountURL, directory string) error {
	_, err := db.ExecContext(ctx, `UPDATE acme_accounts SET account_url = ?, directory = ? WHERE tenant_id = ?`,
		accountURL, directory, tenantID)
	return err
}

// acmeMessage 把错误压成一句能存进 jobs.message 的中文文案。CA/CF 的原文要留着，
// 用户看得懂的"申请失败"和能定位问题的"urn:acme:error:caa + domain"差别就在这半句上。
func acmeMessage(err error) string {
	msg := err.Error()
	if len(msg) > acmeMessageMax {
		msg = msg[:acmeMessageMax] + "…"
	}
	return msg
}
