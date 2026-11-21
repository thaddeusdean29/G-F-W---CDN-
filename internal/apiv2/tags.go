package apiv2

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"unicode/utf8"
)

// tagsHandler 实现 /api/v2/tags：代理自己的标签分类。
// 列表 = tenant_tags 里登记的标签 ∪ 本代理域名上实际用到的标签，并附带使用该标签的域名数。
// 删除标签会同时把它从本代理所有域名的 tags 里摘掉（version+1，编辑中的表单会收到 412）。
type tagsHandler struct {
	db *sql.DB
}

type tagItem struct {
	Tag     string `json:"tag"`
	Domains int    `json:"domains"`
}

func (h *tagsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tenantID := SessionFromContext(r.Context()).TenantID
	if r.URL.Path == "/api/v2/tags" {
		switch r.Method {
		case http.MethodGet:
			h.list(w, r, tenantID)
		case http.MethodPost:
			h.create(w, r, tenantID)
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
		return
	}
	tag, err := url.PathUnescape(strings.TrimPrefix(r.URL.EscapedPath(), "/api/v2/tags/"))
	if err != nil || tag == "" || r.Method != http.MethodDelete {
		WriteError(w, NewApiError("not_found", "未找到该资源"))
		return
	}
	h.delete(w, r, tenantID, tag)
}

func (h *tagsHandler) list(w http.ResponseWriter, r *http.Request, tenantID string) {
	counts := map[string]int{}
	rows, err := h.db.QueryContext(r.Context(), `SELECT tag FROM tenant_tags WHERE tenant_id = ?`, tenantID)
	if err != nil {
		WriteError(w, err)
		return
	}
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			rows.Close()
			WriteError(w, err)
			return
		}
		counts[t] += 0
	}
	rows.Close()

	drows, err := h.db.QueryContext(r.Context(), `SELECT tags FROM domains WHERE tenant_id = ? AND tags IS NOT NULL`, tenantID)
	if err != nil {
		WriteError(w, err)
		return
	}
	defer drows.Close()
	for drows.Next() {
		var raw []byte
		if err := drows.Scan(&raw); err != nil {
			WriteError(w, err)
			return
		}
		var tags []string
		if json.Unmarshal(raw, &tags) != nil {
			continue
		}
		seen := map[string]bool{}
		for _, t := range tags {
			if t != "" && !seen[t] {
				seen[t] = true
				counts[t]++
			}
		}
	}
	items := make([]tagItem, 0, len(counts))
	for t, n := range counts {
		items = append(items, tagItem{Tag: t, Domains: n})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Tag < items[j].Tag })
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

func validTag(t string) bool {
	return t != "" && utf8.RuneCountInString(t) <= 64 && !strings.ContainsAny(t, "/\\\"")
}

func (h *tagsHandler) create(w http.ResponseWriter, r *http.Request, tenantID string) {
	raw, _, err := decodeKnownFields(r, []string{"tag"})
	if err != nil {
		WriteError(w, err)
		return
	}
	var req struct {
		Tag string `json:"tag"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		WriteError(w, NewApiError("validation_failed", "tag 必须是字符串"))
		return
	}
	req.Tag = strings.TrimSpace(req.Tag)
	if !validTag(req.Tag) {
		WriteError(w, NewApiError("validation_failed", "标签 1-64 个字符，不能包含 / \\ \"").
			WithDetails(map[string]any{"fields": map[string]string{"tag": "格式不正确"}}))
		return
	}
	if _, err := h.db.ExecContext(r.Context(), `INSERT IGNORE INTO tenant_tags (tenant_id, tag) VALUES (?, ?)`, tenantID, req.Tag); err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, tagItem{Tag: req.Tag})
}

func (h *tagsHandler) delete(w http.ResponseWriter, r *http.Request, tenantID, tag string) {
	tx, err := h.db.BeginTx(r.Context(), nil)
	if err != nil {
		WriteError(w, err)
		return
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(r.Context(), `DELETE FROM tenant_tags WHERE tenant_id = ? AND tag = ?`, tenantID, tag); err != nil {
		WriteError(w, err)
		return
	}
	// 逐行在 Go 里重写 tags 数组，避免依赖 JSON_SEARCH 对重复元素/转义字符的行为差异。
	rows, err := tx.QueryContext(r.Context(),
		`SELECT id, tags FROM domains WHERE tenant_id = ? AND JSON_CONTAINS(tags, JSON_QUOTE(?)) FOR UPDATE`, tenantID, tag)
	if err != nil {
		WriteError(w, err)
		return
	}
	type upd struct {
		id   string
		tags []byte
	}
	var updates []upd
	for rows.Next() {
		var id string
		var raw []byte
		if err := rows.Scan(&id, &raw); err != nil {
			rows.Close()
			WriteError(w, err)
			return
		}
		var tags []string
		_ = json.Unmarshal(raw, &tags)
		kept := make([]string, 0, len(tags))
		for _, t := range tags {
			if t != tag {
				kept = append(kept, t)
			}
		}
		b, _ := json.Marshal(kept)
		updates = append(updates, upd{id, b})
	}
	rows.Close()
	for _, u := range updates {
		if _, err := tx.ExecContext(r.Context(),
			`UPDATE domains SET tags = ?, version = version + 1 WHERE tenant_id = ? AND id = ?`, u.tags, tenantID, u.id); err != nil {
			WriteError(w, err)
			return
		}
	}
	if err := tx.Commit(); err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"tag": tag, "domains_updated": len(updates)})
}
