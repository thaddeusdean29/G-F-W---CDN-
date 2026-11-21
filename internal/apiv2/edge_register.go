package apiv2

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"cdn/internal/master"
	"cdn/internal/secure"
)

// ---------------------------------------------------------------------------
// 面板侧：GET /api/v2/edge-register、POST /api/v2/edge-register/rotate（docs/API-v2.md §3.4）
// ---------------------------------------------------------------------------

// edgeRegisterSecretHandler 管理租户的边缘自动注册密钥。每个租户一把，库里只存 sha256
// （tenants.register_secret_hash），明文只在轮换响应里出现一次——和 v1 把密钥明文落在
// /etc/cdnpanel/edge_register.secret 不同，v2 主控可能多实例、多租户，不能靠本机文件。
type edgeRegisterSecretHandler struct {
	db *sql.DB
}

func (h *edgeRegisterSecretHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info := SessionFromContext(r.Context())
	switch {
	case r.URL.Path == "/api/v2/edge-register" && r.Method == http.MethodGet:
		h.get(w, r, info.TenantID)
	case r.URL.Path == "/api/v2/edge-register/rotate" && r.Method == http.MethodPost:
		h.rotate(w, r, info.TenantID)
	case r.URL.Path == "/api/v2/edge-register" || r.URL.Path == "/api/v2/edge-register/rotate":
		w.WriteHeader(http.StatusMethodNotAllowed)
	default:
		WriteError(w, NewApiError("not_found", "未找到该资源"))
	}
}

// secretPlaceholder 出现在 GET 返回的安装命令里：明文从未存库，只能提示用户替换。
const secretPlaceholder = "<注册密钥>"

func (h *edgeRegisterSecretHandler) get(w http.ResponseWriter, r *http.Request, tenantID string) {
	var hash []byte
	err := h.db.QueryRowContext(r.Context(), `SELECT register_secret_hash FROM tenants WHERE id = ?`, tenantID).Scan(&hash)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	// 库里只有哈希，给不出明文末 4 位；secret_hint 用哈希前 8 位，
	// 运维可以在边缘上 sha256sum /etc/cdnpanel/edge_register.secret 对照是不是同一把。
	hint := ""
	if len(hash) > 0 {
		hint = "sha256:" + hex.EncodeToString(hash)[:8]
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"secret_set":      len(hash) > 0,
		"secret_hint":     hint,
		"install_command": installCommand(panelURL(r), secretPlaceholder),
	})
}

func (h *edgeRegisterSecretHandler) rotate(w http.ResponseWriter, r *http.Request, tenantID string) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		WriteError(w, err)
		return
	}
	secret := hex.EncodeToString(buf)
	sum := sha256.Sum256([]byte(secret))
	res, err := h.db.ExecContext(r.Context(), `UPDATE tenants SET register_secret_hash = ? WHERE id = ?`, sum[:], tenantID)
	if err != nil {
		WriteError(w, err)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		WriteError(w, NewApiError("not_found", "未找到该资源"))
		return
	}
	// 旧密钥立即失效；已注册节点靠各自的节点 token 心跳，不受影响。
	writeJSON(w, http.StatusOK, map[string]any{
		"secret":          secret,
		"install_command": installCommand(panelURL(r), secret),
	})
}

// panelURL 从请求推出边缘该回连的主控地址（反代后以 X-Forwarded-* 为准）。
func panelURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	if p := r.Header.Get("X-Forwarded-Proto"); p == "http" || p == "https" {
		scheme = p
	}
	host := r.Host
	if fh := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Host"), ",")[0]); fh != "" {
		host = fh
	}
	return scheme + "://" + host
}

// installCommand 生成边缘安装命令：install.sh 需要在项目源码目录下执行（它就地编译 cdnedge），
// MASTER_URL/REGISTER_SECRET 让 cdnedge 带 --master 启动并自动注册到本租户。
// 要加入指定集群时在前面再加 CLUSTER_ID=<集群ID>。
func installCommand(panel, secret string) string {
	return "MODE=edge MASTER_URL=" + panel + " REGISTER_SECRET=" + secret + " bash install.sh"
}

// ---------------------------------------------------------------------------
// 边缘侧：POST /api/v2/edge/register、POST /api/v2/edge/heartbeat（docs/API-v2.md §5）
// v1 的 /api/edge/register、/api/edge/heartbeat 在密钥/节点不属于 v1 时也转到这里，
// 已部署的 cdnedge 二进制不用改。
// ---------------------------------------------------------------------------

// EdgeHandler 处理边缘节点的自动注册与心跳。没有会话：注册靠租户注册密钥，心跳靠节点 token。
type EdgeHandler struct {
	db      *sql.DB
	nodes   *NodeRepo
	onboard *nodeJobsHandler
	pusher  *master.Pusher
}

// NewEdgeHandler 供 v1 路由（internal/api）在 v1 找不到对应密钥/节点时回落到 v2。
func NewEdgeHandler(db *sql.DB, pusher *master.Pusher) *EdgeHandler {
	nodeRepo := NewNodeRepo(db)
	return &EdgeHandler{
		db:     db,
		nodes:  nodeRepo,
		pusher: pusher,
		onboard: &nodeJobsHandler{
			nodeRepo: nodeRepo, jobRepo: NewJobRepo(db), domainRepo: NewDomainRepo(db), pusher: pusher, db: db,
		},
	}
}

type edgeRegisterRequest struct {
	NodeID          string `json:"node_id"`
	Token           string `json:"token"`
	Listen          string `json:"listen"`
	LocalIPs        string `json:"local_ips"`
	CertFingerprint string `json:"cert_fingerprint"`
	ClusterID       string `json:"cluster_id"`
	RegisterSecret  string `json:"register_secret"`
}

// RegisterSecretKnown 报告该密钥是否属于某个 v2 租户，供 v1 路由决定是否转给 v2。
func (h *EdgeHandler) RegisterSecretKnown(ctx context.Context, secret string) bool {
	if secret == "" {
		return false
	}
	sum := sha256.Sum256([]byte(secret))
	var id string
	return h.db.QueryRowContext(ctx, `SELECT id FROM tenants WHERE register_secret_hash = ?`, sum[:]).Scan(&id) == nil
}

// NodeKnown 报告 node_id 是否是 v2 节点，供 v1 心跳路由决定是否转给 v2。
func (h *EdgeHandler) NodeKnown(ctx context.Context, id string) bool {
	_, err := h.nodes.GetByID(ctx, id)
	return err == nil
}

// ServeRegister 处理 POST /api/v2/edge/register。成功时返回 {"status":"ok"}——cdnedge
// 只认这个形状；密钥错、集群不对、node_id 非法返回 400/403，cdnedge 收到后不再重试。
func (h *EdgeHandler) ServeRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req edgeRegisterRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 64<<10)).Decode(&req); err != nil {
		WriteError(w, NewApiError("invalid_json", "请求体不是合法 JSON"))
		return
	}
	ctx := r.Context()

	// fail closed：密钥为空或匹配不到任何租户一律 403。按哈希查找本身就是常量时间比较
	// 的等价物（攻击者无法从响应时间逐字节猜出哈希原像）。
	if req.RegisterSecret == "" {
		WriteError(w, NewApiError("forbidden", "注册密钥无效"))
		return
	}
	sum := sha256.Sum256([]byte(req.RegisterSecret))
	var (
		tenantID  string
		status    string
		expiresAt sql.NullTime
	)
	err := h.db.QueryRowContext(ctx, `SELECT id, status, expires_at FROM tenants WHERE register_secret_hash = ?`, sum[:]).
		Scan(&tenantID, &status, &expiresAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			log.Printf("[apiv2 EdgeRegister] rejected registration from %s: bad register secret", r.RemoteAddr)
			WriteError(w, NewApiError("forbidden", "注册密钥无效"))
			return
		}
		WriteError(w, err)
		return
	}
	if status != "active" || (expiresAt.Valid && expiresAt.Time.Before(time.Now().UTC())) {
		WriteError(w, NewApiError("tenant_inactive", "租户已停用或到期"))
		return
	}
	if !validEdgeNodeID(req.NodeID) {
		WriteError(w, NewApiError("validation_failed", "node_id 不合法").
			WithDetails(map[string]any{"fields": map[string]string{"node_id": "8-64 位字母、数字或 -"}}))
		return
	}
	if req.Token == "" {
		WriteError(w, NewApiError("validation_failed", "token 为必填字段").
			WithDetails(map[string]any{"fields": map[string]string{"token": "必填"}}))
		return
	}

	var clusterID sql.NullString
	if req.ClusterID != "" {
		var cid string
		err := h.db.QueryRowContext(ctx, `SELECT id FROM clusters WHERE tenant_id = ? AND id = ?`, tenantID, req.ClusterID).Scan(&cid)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				// 拒绝而不是忽略：静默丢掉集群的话节点会以「无集群」身份上线，拿到全部无集群域名。
				WriteError(w, NewApiError("validation_failed", "集群 "+req.ClusterID+" 不存在").
					WithDetails(map[string]any{"fields": map[string]string{"cluster_id": "不存在"}}))
				return
			}
			WriteError(w, err)
			return
		}
		clusterID = sql.NullString{String: cid, Valid: true}
	}

	ip := edgeNodeIP(req.Listen, req.LocalIPs, r.RemoteAddr)
	port := "9090"
	if _, p, err := net.SplitHostPort(req.Listen); err == nil && p != "" {
		port = p
	}
	address := "https://" + net.JoinHostPort(ip, port)
	tokenEnc, err := secure.Encrypt([]byte(req.Token))
	if err != nil {
		WriteError(w, err)
		return
	}
	nullIP := sql.NullString{String: ip, Valid: ip != ""}

	existing, err := h.nodes.GetByID(ctx, req.NodeID)
	var saved, replaced *Node
	switch {
	case errors.Is(err, sql.ErrNoRows):
		// 新 node_id 但 IP 已有节点 = 这台机器卸载后重装了（uninstall.sh 删了 node_id 文件），
		// 按「删掉旧被控再装」处理。跨租户顶替只在注册请求确实从这个 IP 发出时才允许：
		// listen / local_ips 是边缘自己报的，可以伪造，RemoteAddr 不行（不信任 X-Forwarded-For）。
		remoteHost, _, _ := net.SplitHostPort(r.RemoteAddr)
		sameHost := ip != "" && net.ParseIP(remoteHost) != nil && net.ParseIP(remoteHost).String() == ip
		saved, replaced, err = h.nodes.CreateReplacingIP(ctx, req.NodeID, &Node{
			TenantID:        tenantID,
			ClusterID:       clusterID,
			Name:            "edge-" + req.NodeID[:8],
			Address:         address,
			TokenEnc:        tokenEnc,
			IP:              nullIP,
			CertFingerprint: req.CertFingerprint,
			Enabled:         true,
		}, ReplaceOpts{AllowCrossTenant: sameHost, KeepName: true})
		if err != nil {
			WriteError(w, err)
			return
		}
		if replaced != nil {
			h.pusher.InvalidateClient(replaced.ID)
			log.Printf("[apiv2 EdgeRegister] node %s (%s) reinstalled for tenant %s, replaced old node %s (tenant %s)",
				saved.ID, ip, tenantID, replaced.ID, replaced.TenantID)
		} else {
			log.Printf("[apiv2 EdgeRegister] new node %s (%s) registered for tenant %s", saved.ID, ip, tenantID)
		}
	case err != nil:
		WriteError(w, err)
		return
	case existing.TenantID != tenantID:
		// 同一个 node_id 已属于别的租户：不能凭另一个租户的密钥把节点"抢"过来。
		WriteError(w, NewApiError("forbidden", "该节点已注册到其他租户"))
		return
	default:
		saved, err = h.nodes.ApplyEdgeReport(ctx, tenantID, existing.ID, address, tokenEnc, req.CertFingerprint, nullIP, clusterID)
		if err != nil {
			WriteError(w, err)
			return
		}
	}

	// token / 证书指纹可能变了，丢掉缓存的 TLS client。
	h.pusher.InvalidateClient(saved.ID)
	// 灰云 A 记录：新节点、重装，或 IP 变了都要同步；记录已在且 IP 没变就不打 CF。
	switch {
	case existing == nil || replaced != nil:
		go syncReplacedNodeDNS(h.db, h.nodes, saved, replaced)
	case saved.IP != existing.IP || saved.ClusterID != existing.ClusterID:
		go syncNodeDNS(h.db, h.nodes, saved, existing.CFRecordID)
	case saved.CFRecordID == "":
		go syncNodeDNS(h.db, h.nodes, saved, "")
	}
	// 边缘每次启动都会重新注册且配置全在内存，所以每次注册都补发域名（面板上停用的节点不补发）。
	if saved.Enabled {
		if cn, err := toConfigNode(saved); err == nil {
			go func(tenantID string) {
				res := h.onboard.onboardNode(context.Background(), tenantID, cn)
				log.Printf("[apiv2 EdgeRegister] onboard node %s: %v", cn.ID, res)
			}(tenantID)
		}
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "node_id": saved.ID})
}

type edgeHeartbeatRequest struct {
	NodeID string         `json:"node_id"`
	Token  string         `json:"token"`
	Status map[string]any `json:"status"`
}

// ServeHeartbeat 处理 POST /api/v2/edge/heartbeat：校验节点 token 后写 last_heartbeat_at / last_status。
func (h *EdgeHandler) ServeHeartbeat(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var req edgeHeartbeatRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 256<<10)).Decode(&req); err != nil {
		WriteError(w, NewApiError("invalid_json", "请求体不是合法 JSON"))
		return
	}
	n, err := h.nodes.GetByID(r.Context(), req.NodeID)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	plain, err := secure.Decrypt(n.TokenEnc)
	if err != nil {
		WriteError(w, err)
		return
	}
	// 不校验 token 的话，任何人知道 node_id 就能伪造面板上的节点状态。
	if req.Token == "" || subtle.ConstantTimeCompare([]byte(req.Token), plain) != 1 {
		WriteError(w, NewApiError("forbidden", "节点 token 无效"))
		return
	}
	if err := h.nodes.TouchHeartbeat(r.Context(), n.ID, mapEdgeStatus(req.Status)); err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// mapEdgeStatus 把边缘 /edge/status 的原始结构（internal/edgeapi/handler.go status()）
// 转成 nodes.last_status 存的 §2.3 形状：{cpu_percent, mem_percent, connections, version, xdp}。
// 只存这几个字段，避免把 xdp_stats 之类的大对象每 3 秒写一次库。
func mapEdgeStatus(raw map[string]any) []byte {
	st := nodeStatus{}
	if raw == nil {
		b, _ := json.Marshal(st)
		return b
	}
	if sys, ok := raw["system"].(map[string]any); ok {
		st.CPUPercent, _ = sys["cpu_percent"].(float64)
		st.MemPercent, _ = sys["mem_percent"].(float64)
		if c, ok := sys["connections"].(float64); ok {
			st.Connections = int(c)
		}
	}
	if v, ok := raw["version"].(string); ok {
		st.Version = v
	}
	if x, ok := raw["xdp"].(bool); ok {
		st.XDP = &nodeXDPStatus{Installed: x, Attached: x}
		// native / generic：generic(SKB) 模式每包都要先分配 skb，洪水下 CPU 先于带宽打满，
		// 面板要能标出来。旧版边缘不报这个字段，留空。
		if x {
			st.XDP.Mode, _ = raw["xdp_mode"].(string)
			st.XDP.Iface, _ = raw["xdp_iface"].(string)
		}
		// armed 是边缘自己按「挂着 ∧ 内核 enabled ∧ 最近一次写参数成功」算出来的，
		// 主控不重算，避免两边判据漂移。旧版边缘不发这个键 → 保持 nil（无从判断），
		// 不能写成 false，否则正常防护的旧节点会被显示成故障。
		if a, ok := raw["xdp_armed"].(bool); ok {
			st.XDP.Armed = &a
		}
		st.XDP.Enabled, _ = raw["xdp_enabled"].(bool)
		st.XDP.ConfigError, _ = raw["xdp_config_error"].(string)
		if f, ok := raw["xdp_cpu_syn"].(float64); ok {
			st.XDP.CPUSYNLimit = uint32(f)
		}
		if f, ok := raw["xdp_rx_queues"].(float64); ok {
			st.XDP.RXQueues = int(f)
		}
	}
	b, _ := json.Marshal(st)
	return b
}

// validEdgeNodeID 与 v1 validNodeID 相同：node_id 成为主键并出现在 URL 里。
func validEdgeNodeID(id string) bool {
	if len(id) < 8 || len(id) > 64 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// edgeNodeIP 推出节点对外 IP：listen 里的具体地址 > local_ips 第一个非回环 > 请求来源 IP。
func edgeNodeIP(listen, localIPs, remoteAddr string) string {
	usable := func(s string) bool {
		ip := net.ParseIP(s)
		return ip != nil && !ip.IsLoopback() && !ip.IsUnspecified()
	}
	if host, _, err := net.SplitHostPort(listen); err == nil && usable(host) {
		return net.ParseIP(host).String()
	}
	for _, s := range strings.Split(localIPs, ",") {
		if s = strings.TrimSpace(s); usable(s) {
			return net.ParseIP(s).String()
		}
	}
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil && net.ParseIP(host) != nil {
		return net.ParseIP(host).String()
	}
	return ""
}
