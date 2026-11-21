package apiv2

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"cdn/internal/cloudflare"
)

type clustersHandler struct {
	repo       *ClusterRepo
	nodeRepo   *NodeRepo
	domainRepo *DomainRepo
	db         *sql.DB
}

// clusterResponse 是 docs/API-v2.md §2.2 定义的对外 JSON 形状,与 clusters 表的列名不是一一对应
// （role/failover 是包装过的字段，见 cluster_mapping.go）。
type clusterResponse struct {
	ID           string           `json:"id"`
	Name         string           `json:"name"`
	Subdomain    string           `json:"subdomain"`
	Description  string           `json:"description"`
	DefenseCNAME string           `json:"defense_cname"`
	Failover     clusterFailover  `json:"failover"`
	Bandwidth    clusterBandwidth `json:"bandwidth"`
	Role         string           `json:"role"`
	Health       clusterHealth    `json:"health"`
	Version      int              `json:"version"`
	CreatedAt    string           `json:"created_at"`
}

var clusterWritableFields = []string{"description", "defense_cname", "failover", "bandwidth", "role"}
var clusterCreateFields = []string{"name", "description", "defense_cname", "failover", "bandwidth", "role"}
var clusterReadonlyFields = []string{"id", "subdomain", "health", "version", "created_at"}

func renderCluster(c *Cluster, baseDomain string) clusterResponse {
	var targetID *string
	if c.FailoverTargetID.Valid {
		targetID = &c.FailoverTargetID.String
	}
	var checkedAt *string
	if c.LastCheckTime.Valid {
		s := c.LastCheckTime.Time.UTC().Format(rfc3339Milli)
		checkedAt = &s
	}
	subdomain := ""
	if baseDomain != "" {
		subdomain = c.Name + "." + baseDomain
	}
	health := clusterHealth{Status: c.Status, OnlineNodes: c.OnlineNodes, TotalNodes: c.TotalNodes, CheckedAt: checkedAt,
		AutoSwitched: c.AutoFailoverActive}
	monitor.fillHealth(c.ID, &health)
	return clusterResponse{
		ID:           c.ID,
		Name:         c.Name,
		Subdomain:    subdomain,
		Description:  c.Description,
		DefenseCNAME: c.DefenseCNAME,
		Failover: clusterFailover{
			Auto:            c.IsAutoFailover,
			Threshold:       c.FailoverThreshold,
			TargetClusterID: targetID,
		},
		Bandwidth: clusterBandwidth{LimitMbps: c.BWLimitMbps, DangerPercent: c.BWDangerPercent},
		Role:      flagsToRole(c.IsPrimary, c.IsBackup),
		Health:    health,
		Version:   c.Version,
		CreatedAt: c.CreatedAt.UTC().Format(rfc3339Milli),
	}
}

var clusterSortColumns = map[string]string{"created_at": "created_at", "name": "name"}

func (h *clustersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info := SessionFromContext(r.Context())

	if r.URL.Path == "/api/v2/clusters" {
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

	rest := strings.TrimPrefix(r.URL.Path, "/api/v2/clusters/")
	parts := strings.SplitN(rest, "/", 2)
	id := parts[0]
	if id == "" {
		WriteError(w, NewApiError("not_found", "未找到该资源"))
		return
	}
	if len(parts) == 1 {
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
		return
	}
	if parts[1] == "nodes" && r.Method == http.MethodGet {
		h.listNodes(w, r, info.TenantID, id)
		return
	}
	if parts[1] == "failover" && r.Method == http.MethodPost {
		h.failover(w, r, info.TenantID, id)
		return
	}
	WriteError(w, NewApiError("not_found", "未找到该资源"))
}

func (h *clustersHandler) list(w http.ResponseWriter, r *http.Request, tenantID string) {
	page, pageSize := parsePagination(r)
	orderBy := parseSort(r, clusterSortColumns, "-created_at")
	clusters, total, err := h.repo.List(r.Context(), tenantID, orderBy, page, pageSize)
	if err != nil {
		WriteError(w, err)
		return
	}
	h.withNodeCounts(r.Context(), tenantID, clusters...)
	base := h.baseDomain(r.Context(), tenantID)
	items := make([]clusterResponse, 0, len(clusters))
	for _, c := range clusters {
		items = append(items, renderCluster(c, base))
	}
	writeList(w, items, total, page, pageSize)
}

// baseDomain 取自该代理自己的 Cloudflare 配置（tenant_cf_credentials.base_domain）。
// 未配置时为空串，subdomain 字段照常留空。
func (h *clustersHandler) baseDomain(ctx context.Context, tenantID string) string {
	return h.cfFor(ctx, tenantID).BaseDomain
}

// cfFor 返回代理自己的 Cloudflare 客户端；读库失败时按未配置处理（Enabled()==false）。
func (h *clustersHandler) cfFor(ctx context.Context, tenantID string) *cloudflare.Client {
	cf, err := tenantCF(ctx, h.db, tenantID)
	if err != nil {
		log.Printf("[apiv2] load cf credentials for tenant %s: %v", tenantID, err)
		return cloudflare.NewClient("", "", "")
	}
	return cf
}

type clusterWriteRequest struct {
	Name         *string           `json:"name"`
	Description  *string           `json:"description"`
	DefenseCNAME *string           `json:"defense_cname"`
	Failover     *clusterFailover  `json:"failover"`
	Bandwidth    *clusterBandwidth `json:"bandwidth"`
	Role         *string           `json:"role"`
}

func (h *clustersHandler) create(w http.ResponseWriter, r *http.Request, tenantID string) {
	body, fields, err := decodeKnownFields(r, clusterCreateFields)
	if err != nil {
		WriteError(w, err)
		return
	}
	var req clusterWriteRequest
	if err := json.Unmarshal(body, &req); err != nil {
		WriteError(w, NewApiError("invalid_json", "请求体不是合法 JSON"))
		return
	}
	if req.Name == nil || *req.Name == "" {
		WriteError(w, NewApiError("validation_failed", "name 为必填字段").
			WithDetails(map[string]any{"fields": map[string]string{"name": "必填"}}))
		return
	}
	if !validClusterName(*req.Name) {
		WriteError(w, NewApiError("validation_failed", "name 格式不合法").
			WithDetails(map[string]any{"fields": map[string]string{"name": "1-63 位小写字母、数字或 -，不能以 - 开头或结尾"}}))
		return
	}
	_ = fields // create 阶段只用于未知字段校验，字段值已通过 req 读取

	c := &Cluster{TenantID: tenantID, Name: *req.Name, FailoverThreshold: 50, BWDangerPercent: defaultBWDangerPercent}
	if req.Description != nil {
		c.Description = *req.Description
	}
	if req.DefenseCNAME != nil {
		c.DefenseCNAME = *req.DefenseCNAME
	}
	if req.Role != nil {
		isPrimary, isBackup, err := roleToFlags(*req.Role)
		if err != nil {
			WriteError(w, err)
			return
		}
		c.IsPrimary, c.IsBackup = isPrimary, isBackup
	}
	if req.Failover != nil {
		if err := applyFailoverInput(c, req.Failover); err != nil {
			WriteError(w, err)
			return
		}
	}
	if req.Bandwidth != nil {
		if err := applyBandwidthInput(c, req.Bandwidth); err != nil {
			WriteError(w, err)
			return
		}
	}

	created, err := h.repo.Create(r.Context(), c)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, renderCluster(created, h.baseDomain(r.Context(), tenantID)))
}

func (h *clustersHandler) get(w http.ResponseWriter, r *http.Request, tenantID, id string) {
	c, err := h.repo.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	h.withNodeCounts(r.Context(), tenantID, c)
	writeJSON(w, http.StatusOK, renderCluster(c, h.baseDomain(r.Context(), tenantID)))
}

// withNodeCounts 用现算的节点数/在线数覆盖集群的健康信息；查询失败只记日志，按库里的值返回。
func (h *clustersHandler) withNodeCounts(ctx context.Context, tenantID string, clusters ...*Cluster) {
	if len(clusters) == 0 {
		return
	}
	counts, err := h.repo.NodeCounts(ctx, tenantID)
	if err != nil {
		log.Printf("[apiv2] count cluster nodes for tenant %s: %v", tenantID, err)
		return
	}
	for _, c := range clusters {
		applyNodeCount(c, counts[c.ID])
	}
}

// applyFailoverInput 把请求里的 failover 子对象写入 c，校验 threshold 在 1-100、
// target_cluster_id 不能指向自己（MySQL 5.7 不执行 CHECK 约束，范围必须在这里校验）。
func applyFailoverInput(c *Cluster, f *clusterFailover) error {
	if f.Threshold < 0 || f.Threshold > 100 {
		return NewApiError("validation_failed", "failover.threshold 必须在 1-100 之间")
	}
	c.IsAutoFailover = f.Auto
	if f.Threshold > 0 {
		c.FailoverThreshold = f.Threshold
	}
	if f.TargetClusterID != nil {
		if *f.TargetClusterID == c.ID {
			return NewApiError("validation_failed", "target_cluster_id 不能指向自身")
		}
		c.FailoverTargetID.Valid = *f.TargetClusterID != ""
		c.FailoverTargetID.String = *f.TargetClusterID
	}
	return nil
}

// applyBandwidthInput 校验并写入带宽防护设置：limit_mbps=0 表示关闭；danger_percent 不填（0）按默认 90%。
func applyBandwidthInput(c *Cluster, b *clusterBandwidth) error {
	if b.LimitMbps < 0 || b.LimitMbps > 1000000 {
		return NewApiError("validation_failed", "bandwidth.limit_mbps 必须在 0-1000000 之间（0 表示关闭）")
	}
	if b.DangerPercent == 0 {
		b.DangerPercent = defaultBWDangerPercent
	}
	if b.DangerPercent < 1 || b.DangerPercent > 100 {
		return NewApiError("validation_failed", "bandwidth.danger_percent 必须在 1-100 之间")
	}
	c.BWLimitMbps, c.BWDangerPercent = b.LimitMbps, b.DangerPercent
	return nil
}

func (h *clustersHandler) patch(w http.ResponseWriter, r *http.Request, tenantID, id string) {
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
	if bad := DisallowedFields(raw, append(clusterReadonlyFields, "name")); len(bad) > 0 {
		WriteError(w, readonlyFieldError(bad))
		return
	}
	if bad := UnknownFields(raw, clusterWritableFields); len(bad) > 0 {
		WriteError(w, unknownFieldError(bad))
		return
	}

	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)

	c := &Cluster{
		ID: existing.ID, TenantID: tenantID, Description: existing.Description, DefenseCNAME: existing.DefenseCNAME,
		IsPrimary: existing.IsPrimary, IsBackup: existing.IsBackup, IsAutoFailover: existing.IsAutoFailover,
		FailoverThreshold: existing.FailoverThreshold, FailoverTargetID: existing.FailoverTargetID,
		BWLimitMbps: existing.BWLimitMbps, BWDangerPercent: existing.BWDangerPercent,
	}
	if raw, ok := fields["description"]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			WriteError(w, NewApiError("validation_failed", "description 必须是字符串"))
			return
		}
		c.Description = s
	}
	if raw, ok := fields["defense_cname"]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			WriteError(w, NewApiError("validation_failed", "defense_cname 必须是字符串"))
			return
		}
		c.DefenseCNAME = s
	}
	if raw, ok := fields["role"]; ok {
		var s string
		if err := json.Unmarshal(raw, &s); err != nil {
			WriteError(w, NewApiError("validation_failed", "role 必须是字符串"))
			return
		}
		isPrimary, isBackup, err := roleToFlags(s)
		if err != nil {
			WriteError(w, err)
			return
		}
		c.IsPrimary, c.IsBackup = isPrimary, isBackup
	}
	if raw, ok := fields["failover"]; ok {
		var f clusterFailover
		if err := json.Unmarshal(raw, &f); err != nil {
			WriteError(w, NewApiError("validation_failed", "failover 字段格式不正确"))
			return
		}
		if err := applyFailoverInput(c, &f); err != nil {
			WriteError(w, err)
			return
		}
	}
	if raw, ok := fields["bandwidth"]; ok {
		var b clusterBandwidth
		if err := json.Unmarshal(raw, &b); err != nil {
			WriteError(w, NewApiError("validation_failed", "bandwidth 字段格式不正确"))
			return
		}
		if err := applyBandwidthInput(c, &b); err != nil {
			WriteError(w, err)
			return
		}
	}

	updated, err := h.repo.Update(r.Context(), tenantID, id, parseIfMatch(r), c)
	if err != nil {
		WriteError(w, versionConflictOr(err))
		return
	}
	h.withNodeCounts(r.Context(), tenantID, updated)
	writeJSON(w, http.StatusOK, renderCluster(updated, h.baseDomain(r.Context(), tenantID)))
}

func (h *clustersHandler) delete(w http.ResponseWriter, r *http.Request, tenantID, id string) {
	if _, err := h.repo.Get(r.Context(), tenantID, id); err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	nodes, domains, err := h.repo.CountReferences(r.Context(), tenantID, id)
	if err != nil {
		WriteError(w, err)
		return
	}
	if nodes > 0 || domains > 0 {
		WriteError(w, NewApiError("in_use", "集群下仍有节点或域名，无法删除").
			WithDetails(map[string]any{"nodes": nodes, "domains": domains}))
		return
	}
	if err := h.repo.Delete(r.Context(), tenantID, id); err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *clustersHandler) listNodes(w http.ResponseWriter, r *http.Request, tenantID, clusterID string) {
	if _, err := h.repo.Get(r.Context(), tenantID, clusterID); err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	listClusterNodes(w, r, tenantID, clusterID, h.nodeRepo)
}

type clusterFailoverAction struct {
	Action string `json:"action"`
}

// clusterDomains 取出该集群下的全部域名（不分页,故障转移要对全部域名生效)。
func (h *clustersHandler) clusterDomains(ctx context.Context, tenantID, clusterID string) ([]*Domain, error) {
	var out []*Domain
	page := 1
	for {
		rows, total, err := h.domainRepo.List(ctx, tenantID, clusterID, "", nil, "", "created_at ASC", page, maxPageSize)
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
		if len(rows) == 0 || page*maxPageSize >= total {
			break
		}
		page++
	}
	return out, nil
}

// failover 对应 docs/API-v2.md §3.2 的 POST /clusters/:id/failover {"action":"trigger"|"cancel"}：
// 200 同步，对集群下全部域名逐个调用 domains.go 的 switchOneDomain。trigger 按决策 4 的隐式规则
// 选目标：集群自身配置的 failover_target_id 优先；未配置则退回逐域名的 defense_cname
// （不同域名可能各自配置了不同的高防 CNAME，因此这个分支要按域名单独判断，不能统一取一个值）；
// 两者都没有的域名会导致整体 422（不做"部分域名切换成功、部分跳过"的半成品结果）。
// cancel 统一切回集群自身 subdomain。
func (h *clustersHandler) failover(w http.ResponseWriter, r *http.Request, tenantID, id string) {
	c, err := h.repo.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	body, err := readBody(r)
	if err != nil {
		WriteError(w, err)
		return
	}
	var req clusterFailoverAction
	if err := json.Unmarshal(body, &req); err != nil {
		WriteError(w, NewApiError("invalid_json", "请求体不是合法 JSON"))
		return
	}

	cf := h.cfFor(r.Context(), tenantID)
	if !cf.Enabled() {
		WriteError(w, NewApiError("cf_not_configured", "Cloudflare 未配置"))
		return
	}
	clusterSubdomain := cf.ClusterSubdomain(c.Name)

	domains, err := h.clusterDomains(r.Context(), tenantID, id)
	if err != nil {
		WriteError(w, err)
		return
	}

	switch req.Action {
	case "trigger":
		h.doFailoverTrigger(w, r, cf, tenantID, c, clusterSubdomain, domains)
	case "cancel":
		h.doFailoverCancel(w, r, cf, tenantID, c, clusterSubdomain, domains)
	default:
		WriteError(w, NewApiError("validation_failed", "action 必须是 trigger 或 cancel"))
	}
}

func (h *clustersHandler) doFailoverTrigger(w http.ResponseWriter, r *http.Request, cf *cloudflare.Client, tenantID string, c *Cluster, clusterSubdomain string, domains []*Domain) {
	var backupSubdomain string
	if c.FailoverTargetID.Valid && c.FailoverTargetID.String != "" {
		target, err := h.repo.Get(r.Context(), tenantID, c.FailoverTargetID.String)
		if err != nil {
			WriteError(w, NewApiError("cluster_missing", "故障转移目标集群不存在"))
			return
		}
		backupSubdomain = cf.ClusterSubdomain(target.Name)
	} else {
		for _, d := range domains {
			if effectiveDefenseCNAME(d, c) == "" {
				WriteError(w, NewApiError("defense_cname_missing", "域名 "+d.Domain+" 和集群都未配置高防 CNAME，且集群未配置故障转移目标集群"))
				return
			}
		}
	}

	for _, d := range domains {
		var target string
		onDefense := false
		if backupSubdomain != "" {
			target = backupSubdomain
		} else {
			target = effectiveDefenseCNAME(d, c)
			onDefense = true
		}
		if err := switchOneDomain(r.Context(), cf, h.domainRepo, tenantID, d, clusterSubdomain, target, onDefense, true); err != nil {
			WriteError(w, NewApiError("upstream_failed", "域名 "+d.Domain+" 切换失败: "+err.Error()))
			return
		}
	}

	// 手动触发：auto_failover_active=false，监控协程不会自动切回，保持到用户手动取消。
	if err := h.repo.UpdateFailoverState(r.Context(), tenantID, c.ID, "failover_complete", c.FailoverTargetID, false); err != nil {
		WriteError(w, err)
		return
	}
	monitor.reset(c.ID)
	updated, err := h.repo.Get(r.Context(), tenantID, c.ID)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	h.withNodeCounts(r.Context(), tenantID, updated)
	writeJSON(w, http.StatusOK, renderCluster(updated, h.baseDomain(r.Context(), tenantID)))
}

func (h *clustersHandler) doFailoverCancel(w http.ResponseWriter, r *http.Request, cf *cloudflare.Client, tenantID string, c *Cluster, clusterSubdomain string, domains []*Domain) {
	for _, d := range domains {
		if err := switchOneDomain(r.Context(), cf, h.domainRepo, tenantID, d, clusterSubdomain, clusterSubdomain, false, false); err != nil {
			WriteError(w, NewApiError("upstream_failed", "域名 "+d.Domain+" 切回失败: "+err.Error()))
			return
		}
	}

	// failover_target_id 是用户配置的切换目标，取消时原样保留（以前这里传 NULL，取消一次配置就丢了）。
	// 清零监控的连续超限计数：攻击仍在的话要重新连续超限 3 次才会再自动切走。
	if err := h.repo.UpdateFailoverState(r.Context(), tenantID, c.ID, "active", c.FailoverTargetID, false); err != nil {
		WriteError(w, err)
		return
	}
	monitor.reset(c.ID)
	updated, err := h.repo.Get(r.Context(), tenantID, c.ID)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	h.withNodeCounts(r.Context(), tenantID, updated)
	writeJSON(w, http.StatusOK, renderCluster(updated, h.baseDomain(r.Context(), tenantID)))
}

// validClusterName 与 clusters 表的 CHECK 一致：name 同时是 CF 子域名前缀，必须是合法 DNS label。
func validClusterName(name string) bool {
	if len(name) < 1 || len(name) > 63 || name[0] == '-' || name[len(name)-1] == '-' {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}
