package apiv2

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"cdn/configs"
	"cdn/internal/config"
	"cdn/internal/deploy"
	"cdn/internal/geo"
	"cdn/internal/master"
	"cdn/internal/secure"
	"cdn/internal/xdp"
)

// nodeJobsHandler 处理三个走 Job 的节点副作用接口（docs/API-v2.md §3.3）：
// POST /nodes/deploy、POST /nodes/:id/install-xdp、POST /nodes/:id/onboard。
// 与 nodesHandler（纯 CRUD）分开是因为这三个接口需要 *master.Pusher 与边缘节点通信，
// CRUD 不需要这个依赖。
type nodeJobsHandler struct {
	nodeRepo   *NodeRepo
	jobRepo    *JobRepo
	domainRepo *DomainRepo
	pusher     *master.Pusher
	db         *sql.DB
	// country 是国家级地理库：新节点接入时要按它编译当前应该生效的前缀表。
	country *geo.DB
}

func (h *nodeJobsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/v2/nodes/deploy" {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		h.deploy(w, r)
		return
	}

	rest := strings.TrimPrefix(r.URL.Path, "/api/v2/nodes/")
	idx := lastSlash(rest)
	if idx < 0 {
		WriteError(w, NewApiError("not_found", "未找到该资源"))
		return
	}
	id, action := rest[:idx], rest[idx+1:]
	if id == "" {
		WriteError(w, NewApiError("not_found", "未找到该资源"))
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	info := SessionFromContext(r.Context())
	switch action {
	case "install-xdp":
		h.installXDP(w, r, info.TenantID, id)
	case "onboard":
		h.onboard(w, r, info.TenantID, id)
	default:
		WriteError(w, NewApiError("not_found", "未找到该资源"))
	}
}

var nodeDeployFields = []string{"host", "port", "user", "password", "private_key", "name", "cluster_id", "edge_port", "xdp_iface"}

type nodeDeployRequest struct {
	Host       string     `json:"host"`
	Port       portString `json:"port"`
	User       string     `json:"user"`
	Password   string     `json:"password"`
	PrivateKey string     `json:"private_key"`
	Name       string     `json:"name"`
	ClusterID  string     `json:"cluster_id"`
	EdgePort   portString `json:"edge_port"`
	XDPIface   string     `json:"xdp_iface"`
}

// portString 同时接受 JSON 数字和字符串（控制台 el-input-number 发的是数字，
// 旧脚本/curl 常写成字符串），统一成十进制字符串，并校验 1-65535。
type portString string

func (p *portString) UnmarshalJSON(b []byte) error {
	s := strings.TrimSpace(string(b))
	if s == "null" || s == `""` {
		*p = ""
		return nil
	}
	s = strings.Trim(s, `"`)
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > 65535 {
		return fmt.Errorf("端口必须是 1-65535 的整数")
	}
	*p = portString(strconv.Itoa(n))
	return nil
}

// deploy 对应 docs/API-v2.md §3.3 的 POST /nodes/deploy：SSH 一键部署边缘节点。
// SSH 密码/私钥只在这次请求处理和后台 goroutine 里使用一次，绝不写进 job.params 或任何表
// （对应文档"SSH 凭据只在内存里用一次，不落库"的约束）。
func (h *nodeJobsHandler) deploy(w http.ResponseWriter, r *http.Request) {
	info := SessionFromContext(r.Context())
	tenantID := info.TenantID

	body, _, err := decodeKnownFields(r, nodeDeployFields)
	if err != nil {
		WriteError(w, err)
		return
	}
	var req nodeDeployRequest
	if err := json.Unmarshal(body, &req); err != nil {
		var ute *json.UnmarshalTypeError
		if errors.As(err, &ute) || strings.Contains(err.Error(), "端口") {
			WriteError(w, NewApiError("validation_failed", "端口必须是 1-65535 的整数").
				WithDetails(map[string]any{"fields": map[string]string{"port": "1-65535", "edge_port": "1-65535"}}))
			return
		}
		WriteError(w, NewApiError("invalid_json", "请求体不是合法 JSON"))
		return
	}
	if req.Host == "" {
		WriteError(w, NewApiError("validation_failed", "host 为必填字段").
			WithDetails(map[string]any{"fields": map[string]string{"host": "必填"}}))
		return
	}
	if req.Password == "" && req.PrivateKey == "" {
		WriteError(w, NewApiError("validation_failed", "password 或 private_key 必须提供一个").
			WithDetails(map[string]any{"fields": map[string]string{"password": "必填(或 private_key)"}}))
		return
	}
	if req.Port == "" {
		req.Port = "22"
	}
	if req.User == "" {
		req.User = "root"
	}
	if req.EdgePort == "" {
		req.EdgePort = "9090"
	}
	if req.Name == "" {
		req.Name = req.Host
	}

	// 集群不属于本代理就在 SSH 安装之前拒绝，免得装完才因外键失败、白装一台。
	if err := clusterExists(r.Context(), h.db, tenantID, req.ClusterID); err != nil {
		WriteError(w, err)
		return
	}

	exe, _ := os.Executable()
	edgeBinary := filepath.Join(filepath.Dir(exe), "cdnedge")
	if _, err := os.Stat(edgeBinary); err != nil {
		WriteError(w, NewApiError("internal_error", "未找到 cdnedge 二进制文件，请把它放到面板程序同目录: "+edgeBinary))
		return
	}

	// 先测试 SSH 连通性（快速失败），成功后才建 job、才返回 202。
	sshClient, err := deploy.Connect(req.Host, string(req.Port), req.User, req.Password, req.PrivateKey)
	if err != nil {
		WriteError(w, NewApiError("upstream_failed", "SSH 连接失败: "+err.Error()))
		return
	}

	// job.params 绝不能包含 password/private_key（docs/API-v2.md §3.3 的安全约束）。
	params, _ := json.Marshal(map[string]string{
		"host": req.Host, "port": string(req.Port), "user": req.User, "name": req.Name,
		"cluster_id": req.ClusterID, "edge_port": string(req.EdgePort), "xdp_iface": req.XDPIface,
	})
	job, err := h.jobRepo.Create(r.Context(), tenantID, "node.deploy", "", params)
	if err != nil {
		sshClient.Close()
		WriteError(w, err)
		return
	}
	writeJobAccepted(w, job)

	// 节点 ID 由主控先分配并随部署写到节点上，cdnedge 带 --master 启动后直接用它心跳、上报统计，
	// 不需要注册密钥，主控也不必回连节点拉取状态。
	nodeID := uuid.New().String()
	link := &deploy.MasterLink{NodeID: nodeID, MasterURL: panelURL(r)}

	go func() {
		defer sshClient.Close()
		ctx := context.Background()

		xdpIface := req.XDPIface
		if xdpIface == "" {
			if iface, err := deploy.DetectMainIface(sshClient); err == nil {
				xdpIface = iface
			}
		}
		_ = h.jobRepo.UpdateProgress(ctx, job.ID, 10, "开始部署边缘节点...")

		// 进度回调：把 SSH 部署的每一步写进 jobs 表，用递增的粗粒度进度值（部署脚本本身
		// 不上报百分比，只上报步骤文案），10 起步、90 封顶，最后 MarkDone 时补到 100。
		progress := 10
		step := func(_, message string) {
			if progress < 90 {
				progress += 10
			}
			_ = h.jobRepo.UpdateProgress(ctx, job.ID, progress, message)
			log.Printf("[apiv2 Deploy %s] %s", req.Host, message)
		}

		result, err := deploy.DeployEdge(sshClient, edgeBinary, xdp.Source, configs.TengineConf, string(req.EdgePort), xdpIface, link, step)
		if err != nil {
			_ = h.jobRepo.MarkFailed(ctx, job.ID, "部署失败: "+err.Error())
			log.Printf("[apiv2 Deploy] %s failed: %v", req.Host, err)
			return
		}

		// SSH 部署成功拿到 token 之后才创建节点：nodes.token_enc 是 NOT NULL 列，
		// 配额检查（NodeRepo.Create 里的 checkPlanQuota）也就天然发生在部署成功之后，
		// 不需要应用层预占配额。
		tokenEnc, err := secure.Encrypt([]byte(result.Token))
		if err != nil {
			_ = h.jobRepo.MarkFailed(ctx, job.ID, "加密节点 token 失败: "+err.Error())
			return
		}
		n := &Node{
			TenantID: tenantID,
			Name:     req.Name,
			Address:  fmt.Sprintf("https://%s:%s", req.Host, req.EdgePort),
			IP:       sql.NullString{String: req.Host, Valid: true},
			TokenEnc: tokenEnc,
			Enabled:  true,
		}
		if req.ClusterID != "" {
			n.ClusterID = sql.NullString{String: req.ClusterID, Valid: true}
		}

		// 这台机器以前装过（面板里已有同 IP 节点）就当重装：删掉旧被控记录再建新的。
		// SSH 登录成功已经证明控制这台机器，所以旧节点属于别的租户也允许顶替。
		created, replaced, err := h.nodeRepo.CreateReplacingIP(ctx, nodeID, n, ReplaceOpts{AllowCrossTenant: true})
		if err != nil {
			msg := "节点保存失败: " + err.Error()
			var ae *ApiError
			if errors.As(err, &ae) {
				msg = ae.Message
			}
			_ = h.jobRepo.MarkFailed(ctx, job.ID, msg)
			return
		}
		h.pusher.InvalidateClient(created.ID)
		if replaced != nil {
			h.pusher.InvalidateClient(replaced.ID)
			log.Printf("[apiv2 Deploy] node %s reinstalled, replaced old node %s (tenant %s)", req.Host, replaced.ID, replaced.TenantID)
		}
		// 集群子域名的灰云 A 记录（指向本节点 IP），与补发配置并行。
		go syncReplacedNodeDNS(h.db, h.nodeRepo, created, replaced)

		// 部署完成后补发配置：域名，以及代理保存过的 CC / XDP 阈值 / 封禁阶梯（pushTenantDefense）。
		var onboardRes map[string]string
		if cn, err := toConfigNode(created); err == nil {
			onboardRes = h.onboardNode(ctx, tenantID, cn)
		} else {
			onboardRes = map[string]string{"reachable": "解密节点 token 失败: " + err.Error()}
		}

		resultMap := map[string]any{
			"node_id": created.ID,
			"onboard": onboardRes,
		}
		if replaced != nil {
			// 只回旧节点 ID；旧节点属于别的租户时不回名称等信息，免得泄露他人数据。
			resultMap["replaced_node_id"] = replaced.ID
		}
		resultJSON, _ := json.Marshal(resultMap)
		_ = h.jobRepo.MarkDone(ctx, job.ID, resultJSON, result.XDPWarning)
		log.Printf("[apiv2 Deploy] node %s deployed (id=%s)", req.Host, created.ID)
	}()
}

// installXDP 对应 docs/API-v2.md §3.3 的 POST /nodes/:id/install-xdp：在已注册节点上
// 补装 XDP。同步版本在 internal/api/nodes.go，这里只是把它包一层 Job。
func (h *nodeJobsHandler) installXDP(w http.ResponseWriter, r *http.Request, tenantID, id string) {
	n, err := h.nodeRepo.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	job, err := h.jobRepo.Create(r.Context(), tenantID, "node.install_xdp", id, nil)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJobAccepted(w, job)

	go func() {
		ctx := context.Background()
		cn, err := toConfigNode(n)
		if err != nil {
			_ = h.jobRepo.MarkFailed(ctx, job.ID, "解密节点 token 失败: "+err.Error())
			return
		}
		_ = h.jobRepo.UpdateProgress(ctx, job.ID, 10, "正在安装 XDP...")
		start, err := h.pusher.InstallXdp(cn)
		if err != nil {
			_ = h.jobRepo.MarkFailed(ctx, job.ID, "安装 XDP 失败: "+err.Error())
			return
		}
		if s, _ := start["status"].(string); s == "already_loaded" {
			result, _ := json.Marshal(start)
			_ = h.jobRepo.MarkDone(ctx, job.ID, result, "")
			return
		}
		h.waitInstallXdp(ctx, job.ID, cn)
	}()
}

// installXdpPollInterval / installXdpTimeout 控制补装 XDP 的轮询节奏。边缘 /edge/install-xdp
// 只是启动后台安装（apt + clang 编译 + 挂载，慢机器要几分钟）就返回 202，必须轮询到终态。
// 以前只查一次状态就 MarkDone，任务永远显示「完成」，编译/挂载失败的原因从不上报，
// 用户以为 XDP 已开，机器在洪水下照样被打崩。
var (
	installXdpPollInterval = 3 * time.Second
	installXdpTimeout      = 15 * time.Minute
)

// installXdpDetailsMax 限制写进 job.message 的编译输出长度（三轮 clang 输出可能上百 KB）。
const installXdpDetailsMax = 4000

func (h *nodeJobsHandler) waitInstallXdp(ctx context.Context, jobID string, cn *config.Node) {
	deadline := time.Now().Add(installXdpTimeout)
	lastProgress := ""
	pct := 10
	consecutiveErr := 0
	for time.Now().Before(deadline) {
		time.Sleep(installXdpPollInterval)
		st, err := h.pusher.GetInstallXdpStatus(cn)
		if err != nil {
			// 安装期间 apt 可能让机器短暂卡顿，单次查询失败不算失败。
			consecutiveErr++
			if consecutiveErr >= 10 {
				_ = h.jobRepo.MarkFailed(ctx, jobID, "查询 XDP 安装状态失败: "+err.Error())
				return
			}
			continue
		}
		consecutiveErr = 0
		status, _ := st["status"].(string)
		switch status {
		case "success":
			result, _ := json.Marshal(st)
			_ = h.jobRepo.MarkDone(ctx, jobID, result, "")
			return
		case "failed":
			msg, _ := st["error"].(string)
			if msg == "" {
				msg = "未知错误"
			}
			if d, _ := st["details"].(string); d != "" {
				msg += ": " + tailString(d, installXdpDetailsMax)
			}
			_ = h.jobRepo.MarkFailed(ctx, jobID, "安装 XDP 失败: "+msg)
			return
		case "idle":
			// 节点在安装中途重启（systemd 拉起的新进程状态是 idle）：安装结果已不可知。
			_ = h.jobRepo.MarkFailed(ctx, jobID, "安装 XDP 中断：节点进程已重启，请重试")
			return
		}
		if p, _ := st["progress"].(string); p != "" && p != lastProgress {
			lastProgress = p
			if pct < 90 {
				pct += 10
			}
			_ = h.jobRepo.UpdateProgress(ctx, jobID, pct, p)
		}
	}
	_ = h.jobRepo.MarkFailed(ctx, jobID, "安装 XDP 超时（15 分钟仍未完成），请在节点上查看 journalctl -u cdnedge")
}

// tailString 保留 s 末尾最多 n 字节（按 rune 边界截断），编译错误的关键信息通常在最后。
func tailString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	s = s[len(s)-n:]
	for i := 0; i < len(s) && i < 4; i++ {
		if utf8.RuneStart(s[i]) {
			return "…" + s[i:]
		}
	}
	return "…" + s
}

// onboard 对应 docs/API-v2.md §3.3 的 POST /nodes/:id/onboard：手动补发全部配置。
func (h *nodeJobsHandler) onboard(w http.ResponseWriter, r *http.Request, tenantID, id string) {
	n, err := h.nodeRepo.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	job, err := h.jobRepo.Create(r.Context(), tenantID, "node.onboard", id, nil)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJobAccepted(w, job)

	go func() {
		ctx := context.Background()
		cn, err := toConfigNode(n)
		if err != nil {
			_ = h.jobRepo.MarkFailed(ctx, job.ID, "解密节点 token 失败: "+err.Error())
			return
		}
		res := h.onboardNode(ctx, tenantID, cn)
		result, _ := json.Marshal(res)
		_ = h.jobRepo.MarkDone(ctx, job.ID, result, "")
	}()
}

// toConfigNode 把 apiv2.Node 转成 master.Pusher 需要的 v1 *config.Node（解密 token）。
func toConfigNode(n *Node) (*config.Node, error) {
	plaintext, err := secure.Decrypt(n.TokenEnc)
	if err != nil {
		return nil, err
	}
	cn := &config.Node{
		ID:              n.ID,
		Name:            n.Name,
		Address:         n.Address,
		Token:           string(plaintext),
		CertFingerprint: n.CertFingerprint,
		Enabled:         n.Enabled,
	}
	if n.IP.Valid {
		cn.IP = n.IP.String
	}
	if n.ClusterID.Valid {
		cn.ClusterID = n.ClusterID.String
	}
	return cn, nil
}

// onboardNode 参照 v1 internal/api/node_onboard.go 的 nodeOnboarder.Onboard，为 v2 节点
// 重新实现"补发全部配置"：域名、CC 挑战密钥，以及该代理在 tenant_settings 里保存的
// CC / XDP 阈值与封禁阶梯（未保存过的项标注 skipped，边缘沿用自带默认值）。
// CC 挑战密钥由 cc_challenge_key.go 在启动时生成（不存在时），这里只读。

func (h *nodeJobsHandler) onboardNode(ctx context.Context, tenantID string, n *config.Node) map[string]string {
	res := make(map[string]string, 5)

	// 就绪判断看节点有没有主动发来心跳（边缘 → 主控），不再由主控回连 /edge/status 探测。
	// 注册/部署完成后 cdnedge 立即开始每 3 秒心跳一次，最多等 60 秒。
	ready := false
	var cur *Node
	for i := 0; i < 20; i++ {
		var err error
		cur, err = h.nodeRepo.GetByID(ctx, n.ID)
		if err == nil && cur.LastHeartbeatAt.Valid && time.Since(cur.LastHeartbeatAt.Time) < nodeOnlineThreshold {
			ready = true
			break
		}
		time.Sleep(3 * time.Second)
	}
	if !ready {
		res["reachable"] = "节点未上报心跳（请确认 cdnedge 以 --master 启动且能访问主控）"
		return res
	}

	// 用等待期间刷出来的那行覆盖快照：一键部署时 n 是点下「部署」那一刻的，那时边缘还没
	// 装、地址/token/证书指纹全是空的或旧的；注册成功后这三项才被边缘写回库。不覆盖的话
	// 主控会拿着空指纹去推送，被自己的钉扎检查拒掉，报出一条看起来毫无关系的「未登记
	// 证书指纹」，而恢复办法（等注册）其实已经做完了。
	if fresh, err := toConfigNode(cur); err == nil {
		*n = *fresh
	} else {
		res["token"] = "解密节点 token 失败: " + err.Error()
		return res
	}

	domains, err := h.listAllDomains(ctx, tenantID)
	if err != nil {
		res["domains"] = err.Error()
	} else if len(domains) == 0 {
		res["domains"] = "skipped: no domains for tenant"
	} else if cnt, err := h.pusher.SyncNodePayloads(n, domains); err != nil {
		res["domains"] = err.Error()
	} else {
		res["domains"] = fmt.Sprintf("ok (%d)", cnt)
	}

	// CC 挑战签名密钥是部署级的（v1 主控启动时生成在 ccChallengeSecretFile），所有节点共用；
	// 这里只读不生成，缺失时如实标注。
	if b, err := os.ReadFile(ccChallengeSecretFile); err != nil {
		res["cc_key"] = "skipped: " + err.Error()
	} else if secret := strings.TrimSpace(string(b)); secret == "" {
		res["cc_key"] = "skipped: empty secret"
	} else if err := h.pusher.PostToNode(n, "/edge/cc/challenge-key", map[string]string{"secret": secret}); err != nil {
		res["cc_key"] = err.Error()
	} else {
		res["cc_key"] = "ok"
	}

	if h.db != nil {
		pushTenantDefense(ctx, h.db, h.pusher, h.country, tenantID, n, res)
	}
	return res
}

// listAllDomains 取出该租户的全部域名并转换成下发 payload（manual 证书一并解密带上），
// 供 pusher.SyncNodePayloads 复用（它内部按集群过滤，这里不用重复过滤）。
func (h *nodeJobsHandler) listAllDomains(ctx context.Context, tenantID string) ([]*master.DomainPushPayload, error) {
	var out []*master.DomainPushPayload
	page := 1
	for {
		rows, total, err := h.domainRepo.List(ctx, tenantID, "", "", nil, "", "created_at ASC", page, maxPageSize)
		if err != nil {
			return nil, err
		}
		for _, d := range rows {
			p, err := domainPushPayload(ctx, h.db, d)
			if err != nil {
				return nil, fmt.Errorf("domain %s: %w", d.Domain, err)
			}
			out = append(out, p)
		}
		if len(rows) == 0 || page*maxPageSize >= total {
			break
		}
		page++
	}
	return out, nil
}

// defaultCacheRules 是平台默认缓存规则，与 v1 internal/api/cache.go 的默认值一致。
// 每次返回新切片，调用方可以随意修改。
func defaultCacheRules() []config.CacheRule {
	return []config.CacheRule{
		{Extensions: []string{"js", "css", "woff", "woff2", "ttf", "otf", "eot"}, TTL: "30d", Enabled: true},
		{Extensions: []string{"png", "jpg", "jpeg", "gif", "ico", "svg", "webp", "avif", "bmp"}, TTL: "7d", Enabled: true},
		{Extensions: []string{"mp4", "webm", "mp3", "ogg", "m4a", "flac"}, TTL: "30d", Enabled: true},
		{Extensions: []string{"zip", "rar", "7z", "gz", "pdf", "apk", "exe", "dmg", "iso"}, TTL: "7d", Enabled: true},
	}
}

func disabledSSL() config.SSLConfig {
	return config.SSLConfig{Enabled: false, Mode: "disabled"}
}

// convertDomainToConfig 把 apiv2.Domain 的 JSON 列转成 v1 config.Domain 具体字段，
// 只填 pusher.SyncNode/buildDomainPayload 需要的部分。GatewayProfile 在 v2 还没有对应的
// 写入接口（Stage 3/4），这里用随机皮肤兜底，而不是留零值（零值会让边缘发出空 Server 头）。
func convertDomainToConfig(d *Domain) (*config.Domain, error) {
	cd := &config.Domain{
		ID:                    d.ID,
		Domain:                d.Domain,
		OriginScheme:          d.OriginScheme,
		Enabled:               d.Enabled,
		StaticPublic:          d.StaticPublic,
		GatewayProfile:        config.GetRandomProfile(),
		DefenseCNAME:          d.DefenseCNAME,
		OnDefense:             d.OnDefense,
		DefenseByFailover:     d.DefenseByFailover,
		CFMessage:             d.CFMessage,
		CNAMERecord:           d.CNAMERecord,
		CNAMERecordID:         d.CNAMERecordID,
		MainSubdomainRecordID: d.MainSubdomainRecordID,
		CloudflareProxyID:     d.CloudflareProxyID,
	}
	if d.ClusterID.Valid {
		cd.ClusterID = d.ClusterID.String
	}
	if len(d.Upstreams) > 0 {
		if err := json.Unmarshal(d.Upstreams, &cd.Upstreams); err != nil {
			return nil, fmt.Errorf("upstreams: %w", err)
		}
	}
	if len(d.CacheRules) > 0 {
		if err := json.Unmarshal(d.CacheRules, &cd.CacheRules); err != nil {
			return nil, fmt.Errorf("cache_rules: %w", err)
		}
	}
	// docs/API-v2.md：cache_rules 空数组 = 使用默认规则。下发时 domainPushPayload 会再换成
	// 本代理在「缓存」页保存的默认规则；这里先填平台默认，保证任何路径都不会下发空规则。
	//以前这里原样下发空规则，模板里
	// 一个缓存 location 都不生成，所有请求走 location /（proxy_cache off），边缘缓存恒为 0。
	// 要关闭缓存应保留规则并把 enabled 设为 false，而不是清空。
	if len(cd.CacheRules) == 0 {
		cd.CacheRules = defaultCacheRules()
	}
	if len(d.SSLConfig) > 0 {
		var ssl domainSSL
		if err := json.Unmarshal(d.SSLConfig, &ssl); err != nil {
			return nil, fmt.Errorf("ssl: %w", err)
		}
		// 只有 manual（已上传证书）才启用 HTTPS。边缘没有 autocert 实现，"auto" 若照发
		// Enabled:true 会让模板引用空证书路径，tengine -t 失败连累整台节点，所以按未启用处理。
		switch {
		case ssl.Mode == "manual" && ssl.CertificateID != nil && *ssl.CertificateID != "":
			certFile, keyFile := edgeCertPaths(d.Domain)
			cd.SSL = config.SSLConfig{Enabled: true, Mode: "manual", CertFile: certFile, KeyFile: keyFile}
		default:
			cd.SSL = disabledSSL()
		}
	}
	if len(d.CCPolicy) > 0 {
		if err := json.Unmarshal(d.CCPolicy, &cd.CCPolicy); err != nil {
			return nil, fmt.Errorf("cc_policy: %w", err)
		}
	}
	if len(d.GeoPolicy) > 0 {
		if err := json.Unmarshal(d.GeoPolicy, &cd.GeoPolicy); err != nil {
			return nil, fmt.Errorf("geo_policy: %w", err)
		}
	}
	if len(d.EdgeRecordIDs) > 0 {
		if err := json.Unmarshal(d.EdgeRecordIDs, &cd.EdgeRecordIDs); err != nil {
			return nil, fmt.Errorf("edge_record_ids: %w", err)
		}
	}
	return cd, nil
}
