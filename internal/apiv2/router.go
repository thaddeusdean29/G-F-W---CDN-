// Package apiv2 实现 docs/API-v2.md 定义的多租户 MySQL 存储接口，与
// internal/api（v1，JSON 文件存储、单管理员）完全并存、互不依赖。
package apiv2

import (
	"database/sql"
	"net/http"

	"cdn/internal/cloudflare"
	"cdn/internal/geo"
	"cdn/internal/geoip"
	"cdn/internal/master"
)

// NewRouter 构造 /api/v2 的路由。pusher 用于节点部署完成后的 onboard、install-xdp 等
// 需要与边缘节点通信的 Job（Stage 2b）；Stage 2 阶段的纯 CRUD handler 不依赖它。
// cf 用于域名 purge/resync/switch-* 与集群 failover 里的 DNS 记录操作。
// locator 是城市级 IP 归属地库，两个库文件都没就位时它仍是非 nil（Ready() 为 false），
// 流量页据此告诉运维"地理库未就位"，而不是让归属地列静默空白。
// country 是国家级地理库（区域封禁的前缀表由它编译）。它可以是 nil：那时区域规则
// 在保存那一层就被拒绝，而不是存进库让节点查成"未知"。
// acmeDir 是签发证书用的 ACME directory URL，空串表示 Let's Encrypt 正式环境。
func NewRouter(db *sql.DB, pusher *master.Pusher, cf *cloudflare.Client, locator *geoip.Locator, country *geo.DB, acmeDir string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/healthz", healthzHandler(db))
	// 平台名称等品牌信息，登录页未登录也要显示，所以公开只读。
	mux.HandleFunc("/api/v2/branding", brandingHandler(db))
	mux.HandleFunc(faviconPath, faviconHandler(db))

	sessions := NewSessionStore(db)

	tenantAuth := &tenantAuthHandler{db: db, sessions: sessions}
	mux.HandleFunc("/api/v2/auth/login", tenantAuth.login)
	mux.HandleFunc("/api/v2/auth/logout", tenantAuth.logout)
	mux.Handle("/api/v2/auth/me",
		RequireTenantSession(sessions)(RequireCSRF(http.HandlerFunc(tenantAuth.meOrPatch))))

	adminAuth := &adminAuthHandler{db: db, sessions: sessions}
	mux.HandleFunc("/api/v2/admin/auth/login", adminAuth.login)
	mux.HandleFunc("/api/v2/admin/auth/logout", adminAuth.logout)
	// me 现在两种方法：GET 拿身份，PATCH 改密码。PATCH 是写操作，所以必须过 RequireCSRF
	// （RequireCSRF 放行 GET/HEAD/OPTIONS，加在它身上不影响原来的 GET 调用方）。
	mux.Handle("/api/v2/admin/auth/me",
		RequireAdminSession(sessions)(RequireCSRF(http.HandlerFunc(adminAuth.meOrPatch))))

	// 平台管理员：开通/管理代理（租户）、套餐、代理登录账号。只认 cdn_admin_session，
	// 代理的 cdn_session 进不来；代理之间的数据由各资源接口按 tenant_id 隔离。
	adminWrite := func(h http.Handler) http.Handler {
		return RequireAdminSession(sessions)(RequireCSRF(h))
	}
	adminTenants := &adminTenantsHandler{db: db, sessions: sessions}
	adminPlans := &adminPlansHandler{db: db}
	mux.Handle("/api/v2/admin/tenants", adminWrite(adminTenants))
	mux.Handle("/api/v2/admin/tenants/", adminWrite(adminTenants))
	mux.Handle("/api/v2/admin/plans", adminWrite(adminPlans))
	mux.Handle("/api/v2/admin/plans/", adminWrite(adminPlans))
	mux.Handle("/api/v2/admin/users/", adminWrite(&adminUsersHandler{db: db, sessions: sessions}))
	mux.Handle("/api/v2/admin/settings", adminWrite(&adminSettingsHandler{db: db}))
	mux.Handle("/api/v2/admin/settings/favicon", adminWrite(&adminFaviconHandler{db: db}))
	mux.Handle("/api/v2/admin/homepage", adminWrite(&adminHomepageHandler{db: db}))
	mux.Handle("/api/v2/admin/faq", adminWrite(&adminFAQHandler{db: db}))

	nodeRepo := NewNodeRepo(db)
	// WAF 托管规则包：平台级，只有管理员能维护；激活即向全网启用节点下发密文包。
	// 放在 nodeRepo 之后建，是因为逐节点下发与"哪个节点真吃到了这份包"都要按节点表取数。
	adminWaf := &adminWafHandler{db: db, pusher: pusher, nodes: nodeRepo}
	mux.Handle("/api/v2/admin/waf/packages", adminWrite(adminWaf))
	mux.Handle("/api/v2/admin/waf/packages/", adminWrite(adminWaf))
	mux.Handle("/api/v2/admin/waf/nodes", adminWrite(adminWaf))
	// 区域封禁的平台侧范围：能力总闸、租户可选国家、整节点四层丢包。
	// 前两项决定所有租户能配什么，最后一项直接作用在网卡上，所以只归平台管理员。
	adminGeo := &adminGeoHandler{db: db, pusher: pusher, nodes: nodeRepo, country: country}
	mux.Handle("/api/v2/admin/geo", adminWrite(adminGeo))
	mux.Handle("/api/v2/admin/geo/", adminWrite(adminGeo))
	jobRepo := NewJobRepo(db)
	domainRepo := NewDomainRepo(db)
	clusterRepo := NewClusterRepo(db)
	clusters := &clustersHandler{repo: clusterRepo, nodeRepo: nodeRepo, domainRepo: domainRepo, db: db}
	nodeJobs := &nodeJobsHandler{nodeRepo: nodeRepo, jobRepo: jobRepo, domainRepo: domainRepo, pusher: pusher, db: db, country: country}
	nodes := &nodesHandler{repo: nodeRepo, db: db, jobs: nodeJobs}
	domains := &domainsHandler{repo: domainRepo, clusterRepo: clusterRepo, jobRepo: jobRepo, pusher: pusher, nodeRepo: nodeRepo, db: db, country: country, acmeDir: acmeDir}
	jobs := &jobsHandler{repo: jobRepo}
	dashboard := &dashboardHandler{db: db, nodeRepo: nodeRepo, clusterRepo: clusterRepo, domainRepo: domainRepo}
	tenantWrite := func(h http.Handler) http.Handler {
		return RequireTenantSession(sessions)(RequireCSRF(h))
	}
	mux.Handle("/api/v2/clusters", tenantWrite(clusters))
	mux.Handle("/api/v2/clusters/", tenantWrite(clusters))
	// nodeJobs 处理 /nodes/deploy 与 /nodes/{id}/install-xdp、/nodes/{id}/onboard——
	// 这几个子路径要比 nodesHandler 的 "/api/v2/nodes/" 更精确匹配，ServeMux 按最长
	// 路径前缀优先，所以必须显式注册 "/api/v2/nodes/deploy" 这个精确路径（否则会被
	// "/api/v2/nodes/" 吞掉,nodesHandler 会把 "deploy" 当成节点 ID 去查询）。
	// "/{id}/install-xdp"、"/{id}/onboard" 前缀不固定,交给 nodesHandler 识别后转发。
	mux.Handle("/api/v2/nodes/deploy", tenantWrite(nodeJobs))
	mux.Handle("/api/v2/nodes", tenantWrite(nodes))
	mux.Handle("/api/v2/nodes/", tenantWrite(&nodeRouter{nodes: nodes, jobs: nodeJobs}))
	mux.Handle("/api/v2/domains", tenantWrite(domains))
	mux.Handle("/api/v2/domains/", tenantWrite(domains))
	mux.Handle("/api/v2/jobs", tenantWrite(jobs))
	mux.Handle("/api/v2/jobs/", tenantWrite(jobs))
	mux.Handle("/api/v2/dashboard", tenantWrite(dashboard))

	// 每个代理各自的 Cloudflare 凭证 / 防御配置 / 标签；数据只来自本代理的节点与域名。
	tenantCFH := &tenantCFHandler{db: db}
	mux.Handle("/api/v2/cf-credentials", tenantWrite(tenantCFH))
	mux.Handle("/api/v2/cf-credentials/test", tenantWrite(tenantCFH))
	mux.Handle("/api/v2/security/", tenantWrite(&securityHandler{db: db, nodeRepo: nodeRepo, domainRepo: domainRepo, pusher: pusher, geo: locator, country: country}))
	tags := &tagsHandler{db: db}
	mux.Handle("/api/v2/tags", tenantWrite(tags))
	mux.Handle("/api/v2/tags/", tenantWrite(tags))
	// 全局 cf 已不再用于代理接口（每个代理只用自己的凭证，不回落到 config.json）。
	_ = cf
	// 升级前装好的节点没有集群灰云 A 记录，启动时补建一次。
	go backfillAllNodeDNS(db)
	// 带宽 / 在线率监控：连续超限自动切高防 CNAME，稳定后自动切回（cluster_monitor.go）。
	startClusterMonitor(db, clusterRepo, nodeRepo, domainRepo)
	// 部署级 CC 挑战签名密钥：不存在就生成，并定期重推给全部节点（cc_challenge_key.go）。
	startCCChallengeKeySync(db, pusher)

	edgeSecret := &edgeRegisterSecretHandler{db: db}
	mux.Handle("/api/v2/edge-register", tenantWrite(edgeSecret))
	mux.Handle("/api/v2/edge-register/rotate", tenantWrite(edgeSecret))
	// 边缘节点调用，不走会话：注册靠租户注册密钥，心跳靠节点 token（见 edge_register.go）。
	edge := &EdgeHandler{db: db, nodes: nodeRepo, onboard: nodeJobs, pusher: pusher}
	mux.HandleFunc("/api/v2/edge/register", edge.ServeRegister)
	mux.HandleFunc("/api/v2/edge/heartbeat", edge.ServeHeartbeat)
	mux.HandleFunc("/api/v2/edge/report", edge.ServeReport)

	return mux
}

// nodeRouter 在 "/api/v2/nodes/" 前缀下区分"普通节点 CRUD"（/nodes/{id}）与
// "节点 Job 子资源"（/nodes/{id}/install-xdp、/nodes/{id}/onboard）。放在这里而不是
// nodesHandler 内部，是为了不让 nodesHandler 依赖 *master.Pusher——CRUD 和部署/编排
// 是两类不同的依赖，拆成两个 handler 更清楚。
type nodeRouter struct {
	nodes *nodesHandler
	jobs  *nodeJobsHandler
}

func (h *nodeRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	rest := r.URL.Path[len("/api/v2/nodes/"):]
	if idx := lastSlash(rest); idx >= 0 {
		switch rest[idx+1:] {
		case "install-xdp", "onboard":
			h.jobs.ServeHTTP(w, r)
			return
		}
	}
	h.nodes.ServeHTTP(w, r)
}

func lastSlash(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '/' {
			return i
		}
	}
	return -1
}

func healthzHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := db.PingContext(r.Context()); err != nil {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"error"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}
}
