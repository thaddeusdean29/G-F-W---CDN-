package apiv2

import (
	"context"
	"database/sql"
	"net/http"

	"cdn/internal/stats"
)

// dashboardHandler 实现 docs/API-v2.md §3.9 看板接口的一个子集：usage/plan 复用
// auth.go 的 countUsage/getTenantPlan，nodes 用 NodeRepo.List 的 onlineFilter 各查一次，
// clusters 汇总 ClusterRepo.List 的 Status 分布，today 与「流量统计」同源（边缘上报）。
type dashboardHandler struct {
	db          *sql.DB
	nodeRepo    *NodeRepo
	clusterRepo *ClusterRepo
	domainRepo  *DomainRepo
}

type dashboardNodes struct {
	Online int `json:"online"`
	Total  int `json:"total"`
}

type dashboardToday struct {
	Requests int64 `json:"requests"`
	Bytes    int64 `json:"bytes"`
	Blocked  int64 `json:"blocked"`
	// Hourly 是今日 0-23 时的分时请求/流量/拦截，固定 24 项（无数据的小时为 0）。
	Hourly []stats.HourBucket `json:"hourly"`
}

type dashboardResponse struct {
	Usage    meUsage        `json:"usage"`
	Plan     mePlan         `json:"plan"`
	Nodes    dashboardNodes `json:"nodes"`
	Today    dashboardToday `json:"today"`
	Clusters map[string]int `json:"clusters"`
}

func (h *dashboardHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	tenantID := SessionFromContext(r.Context()).TenantID
	ctx := r.Context()

	usage, err := countUsage(ctx, h.db, tenantID)
	if err != nil {
		WriteError(w, err)
		return
	}
	plan, err := getTenantPlan(ctx, h.db, tenantID)
	if err != nil {
		WriteError(w, err)
		return
	}
	nodes, err := h.nodesSummary(ctx, tenantID)
	if err != nil {
		WriteError(w, err)
		return
	}
	clusters, err := h.clusterHealthDistribution(ctx, tenantID)
	if err != nil {
		WriteError(w, err)
		return
	}
	today, err := h.todayUsage(ctx, tenantID)
	if err != nil {
		WriteError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, dashboardResponse{
		Usage:    usage,
		Plan:     plan,
		Nodes:    nodes,
		Today:    today,
		Clusters: clusters,
	})
}

// nodesSummary 用 NodeRepo.List 的 onlineFilter 各查一次：只要 List 返回的 total，
// 不需要实际的行数据，pageSize 给 1 即可避免多余的行扫描。
func (h *dashboardHandler) nodesSummary(ctx context.Context, tenantID string) (dashboardNodes, error) {
	online := true
	_, onlineTotal, err := h.nodeRepo.List(ctx, tenantID, "", &online, "added_at DESC", 1, 1)
	if err != nil {
		return dashboardNodes{}, err
	}
	_, total, err := h.nodeRepo.List(ctx, tenantID, "", nil, "added_at DESC", 1, 1)
	if err != nil {
		return dashboardNodes{}, err
	}
	return dashboardNodes{Online: onlineTotal, Total: total}, nil
}

// clusterHealthDistribution 分页遍历该租户全部集群（看板需要完整分布，不能只看一页），
// 汇总 Status 字段出现的次数，如 {"active":3,"degraded":1}。
func (h *dashboardHandler) clusterHealthDistribution(ctx context.Context, tenantID string) (map[string]int, error) {
	dist := map[string]int{}
	page := 1
	for {
		clusters, total, err := h.clusterRepo.List(ctx, tenantID, "created_at ASC", page, maxPageSize)
		if err != nil {
			return nil, err
		}
		for _, c := range clusters {
			dist[c.Status]++
		}
		if len(clusters) == 0 || page*maxPageSize >= total {
			break
		}
		page++
	}
	return dist, nil
}

// todayUsage 与 securityHandler.traffic 同口径：取本代理全部节点最近一次上报的
// overview，请求数/字节数只累加本代理域名的部分，拦截数为当日 status>=400 的请求
// （WAF/CC 的 403、limit_req 的 429 都在其中）。此前这里查的 usage_daily 没有任何
// 写入方，看板恒为 0，而流量统计页有数据。
func (h *dashboardHandler) todayUsage(ctx context.Context, tenantID string) (dashboardToday, error) {
	nodes, err := tenantEdgeNodes(ctx, h.nodeRepo, tenantID)
	if err != nil {
		return dashboardToday{}, err
	}
	domSet, err := tenantDomainSet(ctx, h.domainRepo, tenantID)
	if err != nil {
		return dashboardToday{}, err
	}
	out := dashboardToday{Hourly: make([]stats.HourBucket, 24)}
	for i := range out.Hourly {
		out.Hourly[i].Hour = i
	}
	for _, o := range reportField[stats.Overview](nodes, reportOverview) {
		if o.Err != nil {
			continue
		}
		for _, it := range o.Data.TopDomains {
			if it == nil || !domSet[normHost(it.Key)] {
				continue
			}
			out.Requests += int64(it.Requests)
			out.Bytes += int64(it.Bytes)
		}
		out.Blocked += int64(o.Data.TotalBlocked)
		for _, b := range o.Data.Hourly {
			if b != nil && b.Hour >= 0 && b.Hour < 24 {
				out.Hourly[b.Hour].Requests += b.Requests
				out.Hourly[b.Hour].Bytes += b.Bytes
				out.Hourly[b.Hour].Blocked += b.Blocked
			}
		}
	}
	return out, nil
}
