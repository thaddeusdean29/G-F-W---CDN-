package apiv2

import (
	"encoding/json"
	"net/http"
	"strings"
)

type jobsHandler struct {
	repo *JobRepo
}

// jobResponse 是 docs/API-v2.md §0.8 定义的对外 JSON 形状。owner_instance/lease_until/
// tenant_id/node_id/params 不对外暴露——它们是执行细节（SSH 参数甚至可能间接暴露 host/user），
// 文档里的 job 对象只有这 9 个字段。
type jobResponse struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Status    string          `json:"status"`
	Progress  int             `json:"progress"`
	Message   string          `json:"message"`
	Warning   string          `json:"warning"`
	Result    json.RawMessage `json:"result"`
	CreatedAt string          `json:"created_at"`
	UpdatedAt string          `json:"updated_at"`
}

func renderJob(j *Job) jobResponse {
	result := j.Result
	if len(result) == 0 {
		result = nil
	}
	return jobResponse{
		ID:        j.ID,
		Type:      j.Type,
		Status:    j.Status,
		Progress:  j.Progress,
		Message:   j.Message,
		Warning:   j.Warning,
		Result:    result,
		CreatedAt: j.CreatedAt.UTC().Format(rfc3339Milli),
		UpdatedAt: j.UpdatedAt.UTC().Format(rfc3339Milli),
	}
}

type jobEnvelope struct {
	Job jobResponse `json:"job"`
}

// writeJobAccepted 按 docs/API-v2.md §0.8 写 202 + {"job": {...}}。给发起异步操作的接口
// （节点部署/install-xdp/onboard、域名 resync/purge 等，Stage 2b 后续接入）复用，
// 避免每个 handler 各写一份 202 响应体拼装逻辑。
func writeJobAccepted(w http.ResponseWriter, j *Job) {
	writeJSON(w, http.StatusAccepted, jobEnvelope{Job: renderJob(j)})
}

func (h *jobsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	info := SessionFromContext(r.Context())

	if r.URL.Path == "/api/v2/jobs" {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		h.list(w, r, info.TenantID)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/v2/jobs/")
	if id == "" || strings.Contains(id, "/") {
		WriteError(w, NewApiError("not_found", "未找到该资源"))
		return
	}
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	h.get(w, r, info.TenantID, id)
}

func (h *jobsHandler) get(w http.ResponseWriter, r *http.Request, tenantID, id string) {
	j, err := h.repo.Get(r.Context(), tenantID, id)
	if err != nil {
		WriteError(w, notFoundOr(err))
		return
	}
	writeJSON(w, http.StatusOK, renderJob(j))
}

// list 对应 docs/API-v2.md §3.10 的 GET /jobs?type=&status=，"最近的任务"——
// 复用 resource.go 的分页参数，但不接受 sort（文档没要求自定义排序，固定按创建时间倒序）。
func (h *jobsHandler) list(w http.ResponseWriter, r *http.Request, tenantID string) {
	page, pageSize := parsePagination(r)
	jobs, total, err := h.repo.List(r.Context(), tenantID, r.URL.Query().Get("type"), r.URL.Query().Get("status"), page, pageSize)
	if err != nil {
		WriteError(w, err)
		return
	}
	items := make([]jobResponse, 0, len(jobs))
	for _, j := range jobs {
		items = append(items, renderJob(j))
	}
	writeList(w, items, total, page, pageSize)
}
