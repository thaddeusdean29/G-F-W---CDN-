package apiv2

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"cdn/internal/secure"
)

type nodesHandler struct {
	repo *NodeRepo
	db   *sql.DB
	// jobs 用于节点换集群后补发域名（各集群下发的域名不同）；为 nil 时跳过（测试）。
	jobs *nodeJobsHandler
}

// afterNodeChange 在节点落库后异步同步灰云 A 记录，集群变了再补发一次配置。
func (h *nodesHandler) afterNodeChange(n *Node, oldRecordID string, clusterChanged bool) {
	if h.db == nil {
		return
	}
	go func() {
		syncNodeDNS(h.db, h.repo, n, oldRecordID)
		if !clusterChanged || !n.Enabled || h.jobs == nil {
			return
		}
		if cn, err := toConfigNode(n); err == nil {
			res := h.jobs.onboardNode(context.Background(), n.TenantID, cn)
			log.Printf("[apiv2 Nodes] node %s cluster changed, re-onboard: %v", n.ID, res)
		}
	}()
}

// nodeXDPStatus 是 status.xdp 子对象（docs/API-v2.md §2.3），原样来自心跳上报的 last_status JSON。
//
// Installed/Attached 只说明「程序挂在网卡上」，不代表防护在生效：enabled 被关掉、
// 或最近一次写 xdp_config 失败（.o 与二进制字段对不上）时，程序照样挂着但一个包都不判。
// 面板要按 Armed 判断 L4 是否在拦包，并把 ConfigError 原样显示出来。
// Armed 用指针：旧版边缘不发这个键，nil 表示「无从判断」，不能和 false（判断过、结论是未生效）
// 混成一个值——后者会让正常跑的旧边缘节点显示成故障。
type nodeXDPStatus struct {
	Installed   bool   `json:"installed"`
	Attached    bool   `json:"attached"`
	Armed       *bool  `json:"armed,omitempty"`
	Enabled     bool   `json:"enabled"`
	Mode        string `json:"mode"`
	Iface       string `json:"iface,omitempty"`
	ConfigError string `json:"config_error,omitempty"`
	// 不带 omitempty：0 是「总量闸门关闭」这个有效结论，和旧边缘根本没上报（键缺失）
	// 必须能区分开，否则面板没法告诉运维「这台没开闸门」和「这台没上报闸门值」的差别。
	CPUSYNLimit uint32 `json:"cpu_syn_limit"`
	RXQueues    int    `json:"rx_queues"`
}

// nodeStatus 对应 §2.3 的 status 字段。CPUPercent/MemPercent/Connections/Version/XDP 直接来自
// last_status JSON 列（心跳上报原样落库）；Online/LastHeartbeatAt 由 last_heartbeat_at 列现算，
// 不信任 last_status 里可能带的同名字段（心跳payload本身不应该也不会包含这两个,但以防万一)。
type nodeStatus struct {
	Online          bool    `json:"online"`
	LastHeartbeatAt *string `json:"last_heartbeat_at"`
	CPUPercent      float64 `json:"cpu_percent"`
	MemPercent      float64 `json:"mem_percent"`
	Connections     int     `json:"connections"`
	Version         string  `json:"version"`
	// PackageVersion：面板准备下发的这份 cdnedge 的构建标识（同目录那个文件里真读出来的）。
	// VersionState：Version 与 PackageVersion 比出来的结论（match|outdated|unknown）。
	// 两个都由主控现算、都带 omitempty：mapEdgeStatus 存 last_status 时它们恒为空，不会
	// 把算出来的结论当成上报数据落进库；前端因此不用自己复制判据。
	PackageVersion string         `json:"package_version,omitempty"`
	VersionState   string         `json:"version_state,omitempty"`
	XDP            *nodeXDPStatus `json:"xdp,omitempty"`
}

func buildNodeStatus(n *Node) nodeStatus {
	var st nodeStatus
	if len(n.LastStatus) > 0 {
		_ = json.Unmarshal(n.LastStatus, &st)
	}
	st.Online = n.LastHeartbeatAt.Valid && time.Since(n.LastHeartbeatAt.Time) < nodeOnlineThreshold
	st.LastHeartbeatAt = nil
	if n.LastHeartbeatAt.Valid {
		s := n.LastHeartbeatAt.Time.UTC().Format(rfc3339Milli)
		st.LastHeartbeatAt = &s
	}
	// 版本结论在主控算：判据只有一份（见 node_version.go），面板只按值渲染。
	// 每个节点都算一次会走缓存，同一次列表里最多扫一次磁盘。
	st.PackageVersion = edgePackageVersion()
	st.VersionState = resolveVersionState(st.Version, st.PackageVersion)
	return st
}

// nodeResponse 是 docs/API-v2.md §2.3 定义的对外 JSON 形状。token 是仅写字段，
// 响应里只暴露 token_set/token_hint（末 4 位），永不回显完整 token。
type nodeResponse struct {
	ID              string  `json:"id"`
	Name            string  `json:"name"`
	Address         string  `json:"address"`
	TokenSet        bool    `json:"token_set"`
	TokenHint       *string `json:"token_hint,omitempty"`
	IP              string  `json:"ip"`
	CertFingerprint string  `json:"cert_fingerprint"`
	// TLSPinned：主控→边缘这条控制面通道有没有做证书钉扎，规则只有一条 —— 登记了指纹才钉。
	// 让主控把结论算好交出去，面板就不用再复制一份"什么算钉住了"的判断（两份定义迟早分叉）。
	// 这个字段同时也是"这台节点还能不能被主控管理"的答案：无指纹时主控一律拒绝推送。
	TLSPinned bool       `json:"tls_pinned"`
	ClusterID *string    `json:"cluster_id"`
	Enabled   bool       `json:"enabled"`
	Status    nodeStatus `json:"status"`
	Version   int        `json:"version"`
	AddedAt   string     `json:"added_at"`
	// DNSPaused：带宽打满，已被暂时从集群 DNS 摘除（恢复后自动加回）。
	DNSPaused   bool    `json:"dns_paused"`
	DNSPausedAt *string `json:"dns_paused_at"`
}

// renderNode 把 DB 行渲染成 API 响应。需要解密 token_enc 来计算 token_hint（末4位）——
// 解密失败说明数据被篡改或加密密钥不匹配，属于未预期的内部错误，直接把 err 原样返回给
// WriteError（它会把非 *ApiError 统一映射成 500 internal_error，不泄露细节）。
func renderNode(n *Node) (nodeResponse, error) {
	plaintext, err := secure.Decrypt(n.TokenEnc)
	if err != nil {
		return nodeResponse{}, err
	}
	secretMeta := SecretFields("token", string(plaintext))

	var clusterID *string
	if n.ClusterID.Valid {
		clusterID = &n.ClusterID.String
	}
	ip := ""
	if n.IP.Valid {
		ip = n.IP.String
	}

	resp := nodeResponse{
		ID:              n.ID,
		Name:            n.Name,
		Address:         n.Address,
		TokenSet:        secretMeta["token_set"].(bool),
		IP:              ip,
		CertFingerprint: n.CertFingerprint,
		TLSPinned:       n.CertFingerprint != "",
		ClusterID:       clusterID,
		Enabled:         n.Enabled,
		Status:          buildNodeStatus(n),
		Version:         n.Version,
		AddedAt:         n.AddedAt.UTC().Format(rfc3339Milli),
	}
	if hint, ok := secretMeta["token_hint"].(string); ok {
		resp.TokenHint = &hint
	}
	if n.DNSPausedAt.Valid {
		s := n.DNSPausedAt.Time.UTC().Format(rfc3339Milli)
		resp.DNSPaused, resp.DNSPausedAt = true, &s
	}
	return resp, nil
}

var nodeSortColumns = map[string]string{"added_at": "added_at", "name": "name"}
var nodeCreateFields = []string{"name", "address", "token", "ip", "cert_fingerprint", "cluster_id", "enabled"}
var nodeWritableFields = []string{"name", "address", "token", "ip", "cert_fingerprint", "cluster_id", "enabled"}
var nodeReadonlyFields = []string{"id", "status", "version", "added_at"}

func (h *nodesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info := SessionFromContext(r.Context())

	if r.URL.Path == "/api/v2/nodes" {
		switch r.Method {
		case http.MethodGet:
			h.list(w, r, info.TenantID)
		case http.MethodPost:
			h.create(w, r, info.TenantID)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/v2/nodes/")
	if id == "" || strings.Contains(id, "/") {
		WriteError(w, NewApiError("not_found", "未找到该资源"))
		return
	}
	switch r.Method {
	case http.MethodGet:
		h.get(w, r, info.TenantID, id)
	case http.MethodPatch:
		h.patch(w, r, info.TenantID, id)
	case http.MethodDelete:
		h.delete(w, r, info.TenantID, id)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// writeNodeList 是 list 的公共实现，供 nodesHandler.list（GET /nodes?cluster_id=&online=）
// 和 listClusterNodes（GET /clusters/:id/nodes，docs §3.2 说与前者等价）复用。
func writeNodeList(w http.ResponseWriter, r *http.Request, repo *NodeRepo, tenantID, clusterID string) {
	page, pageSize := parsePagination(r)
	orderBy := parseSort(r, nodeSortColumns, "-added_at")
	var onlineFilter *bool
	if v := r.URL.Query().Get("online"); v != "" {
		b := v == "true" || v == "1"
		onlineFilter = &b
	}
	nodes, total, err := repo.List(r.Context(), tenantID, clusterID, onlineFilter, orderBy, page, pageSize)
	if err != nil {
		WriteError(w, err)
		return
	}
	items := make([]nodeResponse, 0, len(nodes))
	for _, n := range nodes {
		resp, err := renderNode(n)
		if err != nil {
			WriteError(w, err)
			return
		}
		items = append(items, resp)
	}
	writeList(w, items, total, page, pageSize)
}

// listClusterNodes 供 clusters.go 的 GET /clusters/:id/nodes 调用（clusterID 已在那里校验存在）。
func listClusterNodes(w http.ResponseWriter, r *http.Request, tenantID, clusterID string, repo *NodeRepo) {
	writeNodeList(w, r, repo, tenantID, clusterID)
}

func (h *nodesHandler) list(w http.ResponseWriter, r *http.Request, tenantID string) {
	writeNodeList(w, r, h.repo, tenantID, r.URL.Query().Get("cluster_id"))
}

type nodeWriteRequest struct {
	Name            *string `json:"name"`
	Address         *string `json:"address"`
	IP              *string `json:"ip"`
	CertFingerprint *string `json:"cert_fingerprint"`
	ClusterID       *string `json:"cluster_id"`
	Enabled         *bool   `json:"enabled"`
}

func (h *nodesHandler) create(w http.ResponseWriter, r *http.Request, tenantID string) {
	body, fields, err := decodeKnownFields(r, nodeCreateFields)
	if err != nil {
		WriteError(w, err)
		return
	}
	var req nodeWriteRequest
	if err := json.Unmarshal(body, &req); err != nil {
		WriteError(w, NewApiError("invalid_json", "请求体不是合法 JSON"))
		return
	}
	if req.Name == nil || *req.Name == "" {
		WriteError(w, NewApiError("validation_failed", "name 为必填字段").
			WithDetails(map[string]any{"fields": map[string]string{"name": "必填"}}))
		return
	}
	if req.Address == nil || *req.Address == "" {
		WriteError(w, NewApiError("validation_failed", "address 为必填字段").
			WithDetails(map[string]any{"fields": map[string]string{"address": "必填"}}))
		return
	}
	intent, tokenPlain, err := ParseSecretField(fields, "token", false)
	if err != nil {
		WriteError(w, err)
		return
	}
	if intent != SecretReplace {
		WriteError(w, NewApiError("validation_failed", "token 为必填字段").
			WithDetails(map[string]any{"fields": map[string]string{"token": "必填"}}))
		return
	}
	tokenEnc, err := secure.Encrypt([]byte(tokenPlain))
	if err != nil {
		WriteError(w, err)
		return
	}

	n := &Node{TenantID: tenantID, Name: *req.Name, Address: *req.Address, TokenEnc: tokenEnc, Enabled: true}
	if req.IP != nil {
		n.IP = sql.NullString{String: *req.IP, Valid: *req.IP != ""}
	}
	if req.CertFingerprint != nil {
		n.CertFingerprint = *req.CertFingerprint
	}
	if req.ClusterID != nil {
		n.ClusterID = sql.NullString{String: *req.ClusterID, Valid: *req.ClusterID != ""}
	}
	if req.Enabled != nil {
		n.Enabled = *req.Enabled
	}

	if n.ClusterID.Valid {
		if err := clusterExists(r.Context(), h.db, tenantID, n.ClusterID.String); err != nil {
			WriteError(w, err)
			return
		}
	}

	created, err := h.repo.Create(r.Context(), n)
	if err != nil {
		WriteError(w, err)
		return
	}
	h.afterNodeChange(created, "", false)
	resp, err := renderNode(created)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

func (h *nodesHandler) get(w http.ResponseWriter, r *http.Request, tenantID, id string) {
	n, err := h.repo.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	resp, err := renderNode(n)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// parseNullableStringField 解析一个允许显式 null 的字符串字段：null → 清空该列，
// 非空字符串 → 设置，用于 ip/cluster_id 这类可以解绑的可写字段。
func parseNullableStringField(raw json.RawMessage, field string) (sql.NullString, error) {
	if string(raw) == "null" {
		return sql.NullString{}, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return sql.NullString{}, NewApiError("validation_failed", field+" 必须是字符串")
	}
	return sql.NullString{String: s, Valid: s != ""}, nil
}

func (h *nodesHandler) patch(w http.ResponseWriter, r *http.Request, tenantID, id string) {
	existing, err := h.repo.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}

	raw, err := readBody(r)
	if err != nil {
		WriteError(w, err)
		return
	}
	if bad := DisallowedFields(raw, nodeReadonlyFields); len(bad) > 0 {
		WriteError(w, readonlyFieldError(bad))
		return
	}
	if bad := UnknownFields(raw, nodeWritableFields); len(bad) > 0 {
		WriteError(w, unknownFieldError(bad))
		return
	}

	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)

	n := &Node{
		ClusterID: existing.ClusterID, Name: existing.Name, Address: existing.Address,
		IP: existing.IP, CertFingerprint: existing.CertFingerprint, Enabled: existing.Enabled,
	}
	if raw, ok := fields["name"]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil || s == "" {
			WriteError(w, NewApiError("validation_failed", "name 必须是非空字符串"))
			return
		}
		n.Name = s
	}
	if raw, ok := fields["address"]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil || s == "" {
			WriteError(w, NewApiError("validation_failed", "address 必须是非空字符串"))
			return
		}
		n.Address = s
	}
	if raw, ok := fields["ip"]; ok {
		v, err := parseNullableStringField(raw, "ip")
		if err != nil {
			WriteError(w, err)
			return
		}
		n.IP = v
	}
	if raw, ok := fields["cert_fingerprint"]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			WriteError(w, NewApiError("validation_failed", "cert_fingerprint 必须是字符串"))
			return
		}
		n.CertFingerprint = s
	}
	if raw, ok := fields["cluster_id"]; ok {
		v, err := parseNullableStringField(raw, "cluster_id")
		if err != nil {
			WriteError(w, err)
			return
		}
		n.ClusterID = v
	}
	if raw, ok := fields["enabled"]; ok {
		var b bool
		if err := json.Unmarshal(raw, &b); err != nil {
			WriteError(w, NewApiError("validation_failed", "enabled 必须是布尔值"))
			return
		}
		n.Enabled = b
	}
	intent, tokenPlain, err := ParseSecretField(fields, "token", false)
	if err != nil {
		WriteError(w, err)
		return
	}
	if intent == SecretReplace {
		tokenEnc, err := secure.Encrypt([]byte(tokenPlain))
		if err != nil {
			WriteError(w, err)
			return
		}
		n.TokenEnc = tokenEnc
	}

	clusterChanged := n.ClusterID != existing.ClusterID
	if clusterChanged && n.ClusterID.Valid {
		if err := clusterExists(r.Context(), h.db, tenantID, n.ClusterID.String); err != nil {
			WriteError(w, err)
			return
		}
	}

	updated, err := h.repo.Update(r.Context(), tenantID, id, parseIfMatch(r), n)
	if err != nil {
		WriteError(w, versionConflictOr(err))
		return
	}
	// 连接三要素（地址 / token / 证书指纹）任何一项变了，都要丢掉缓存的 HTTP client：
	// Pusher 按节点 ID 缓存 client，而钉扎结论是建 client 那一刻定下来的。不丢掉的话，
	// 运维照报错提示把新指纹填进来、点重试，撞上的还是旧指纹 —— 那句提示就成了假承诺。
	if updated.Address != existing.Address || updated.CertFingerprint != existing.CertFingerprint || intent == SecretReplace {
		if h.jobs != nil && h.jobs.pusher != nil {
			h.jobs.pusher.InvalidateClient(id)
		}
	}
	// 换集群就不再沿用旧集群的「带宽摘除」状态，在新集群里照常建记录。
	if clusterChanged && updated.DNSPausedAt.Valid {
		if err := h.repo.ResumeDNS(r.Context(), tenantID, id, ""); err != nil {
			log.Printf("[apiv2 Nodes] clear dns pause of node %s: %v", id, err)
		} else {
			updated.DNSPausedAt = sql.NullTime{}
		}
	}
	// 集群 / IP / 启用状态变了要换记录；还没有记录的（老节点、CF 是后来才配的）顺便补建。
	if clusterChanged || n.IP != existing.IP || n.Enabled != existing.Enabled || existing.CFRecordID == "" {
		oldRecord := existing.CFRecordID
		if !clusterChanged && n.IP == existing.IP && n.Enabled == existing.Enabled {
			oldRecord = "" // 只是补建，不删
		}
		h.afterNodeChange(updated, oldRecord, clusterChanged)
	}
	resp, err := renderNode(updated)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// delete 删除节点。通知边缘清空站点配置（docs §3.3）是异步副作用，属于 Stage 2b Job 机制的范围，
// 这里先只做落库，与 clusters.go 目前的实现深度一致。
func (h *nodesHandler) delete(w http.ResponseWriter, r *http.Request, tenantID, id string) {
	existing, err := h.repo.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	if err := h.repo.Delete(r.Context(), tenantID, id); err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	if existing.CFRecordID != "" && h.db != nil {
		go deleteNodeDNS(h.db, tenantID, id, existing.CFRecordID)
	}
	w.WriteHeader(http.StatusNoContent)
}
