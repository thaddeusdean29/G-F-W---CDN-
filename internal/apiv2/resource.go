package apiv2

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// rfc3339Milli 是响应体里时间字段的统一格式（带毫秒，UTC）。
const rfc3339Milli = "2006-01-02T15:04:05.000Z07:00"

// maxBodySize 防止请求体把内存打爆；docs/API-v2.md 里的资源体都很小,1MiB 足够宽松。
const maxBodySize = 1 << 20

// readBody 读取请求体并校验是不是合法 JSON 对象（PATCH/POST body 都应是对象，
// 不接受裸数组/标量——那种输入不可能匹配任何已知字段，交给后续的 unknown_field 校验没有意义）。
func readBody(r *http.Request) (json.RawMessage, error) {
	raw, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize))
	if err != nil {
		return nil, NewApiError("invalid_json", "请求体读取失败")
	}
	if len(raw) == 0 {
		return json.RawMessage("{}"), nil
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(raw, &probe); err != nil {
		return nil, NewApiError("invalid_json", "请求体必须是 JSON 对象")
	}
	return json.RawMessage(raw), nil
}

// decodeKnownFields 读取请求体，校验顶层字段都在 known 名单内，返回原始字节和逐字段的 RawMessage。
// 用于 POST 创建类接口——docs/API-v2.md §0.3 要求未知字段返回 400 而不是静默忽略。
func decodeKnownFields(r *http.Request, known []string) (json.RawMessage, map[string]json.RawMessage, error) {
	raw, err := readBody(r)
	if err != nil {
		return nil, nil, err
	}
	if bad := UnknownFields(raw, known); len(bad) > 0 {
		return nil, nil, unknownFieldError(bad)
	}
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	return raw, fields, nil
}

func readonlyFieldError(fields []string) *ApiError {
	return NewApiError("readonly_field", "以下字段是只读的，不能修改").
		WithDetails(map[string]any{"fields": fields})
}

func unknownFieldError(fields []string) *ApiError {
	return NewApiError("unknown_field", "请求包含未知字段").
		WithDetails(map[string]any{"fields": fields})
}

// notFoundOr 把 sql.ErrNoRows 翻译成 404 not_found，其他错误原样返回
// （包括已经是 *ApiError 的情况，例如 MySQL 错误分类的结果）。
func notFoundOr(err error) error {
	if errors.Is(err, sql.ErrNoRows) {
		return NewApiError("not_found", "未找到该资源")
	}
	return err
}

// versionConflictOr 在 notFoundOr 的基础上再识别 ErrVersionConflict，
// 用在 Update 调用之后——Update 可能返回 sql.ErrNoRows（不存在）或 ErrVersionConflict（存在但版本不符）。
func versionConflictOr(err error) error {
	if errors.Is(err, ErrVersionConflict) {
		return NewApiError("version_conflict", "资源已被修改，请刷新后重试")
	}
	return notFoundOr(err)
}

// listEnvelope 是 docs/API-v2.md §0.3 定义的列表响应包装。
type listEnvelope struct {
	Items    any `json:"items"`
	Total    int `json:"total"`
	Page     int `json:"page"`
	PageSize int `json:"page_size"`
}

func writeList(w http.ResponseWriter, items any, total, page, pageSize int) {
	writeJSON(w, http.StatusOK, listEnvelope{Items: items, Total: total, Page: page, PageSize: pageSize})
}

const maxPageSize = 200

// parsePagination 解析 page/page_size 查询参数，非法或缺失时回退默认值，不返回错误——
// 分页参数格式错误不值得让整个请求 400，直接当作默认值处理即可。
func parsePagination(r *http.Request) (page, pageSize int) {
	page, pageSize = 1, 20
	if v := r.URL.Query().Get("page"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			page = n
		}
	}
	if v := r.URL.Query().Get("page_size"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			if n > maxPageSize {
				n = maxPageSize
			}
			pageSize = n
		}
	}
	return
}

// parseSort 把形如 "-created_at" 的 sort 参数翻译成 SQL 的 "列名 ASC/DESC" 片段。
// allowed 把 API 侧字段名映射到真实列名，白名单机制防止把用户输入直接拼进 SQL；
// sort 参数缺失或不在白名单内时回退到 def（形如 "-created_at"，必须在 allowed 中登记）。
func parseSort(r *http.Request, allowed map[string]string, def string) string {
	s := r.URL.Query().Get("sort")
	if s == "" {
		s = def
	}
	desc := strings.HasPrefix(s, "-")
	col := strings.TrimPrefix(s, "-")
	sqlCol, ok := allowed[col]
	if !ok {
		col = strings.TrimPrefix(def, "-")
		desc = strings.HasPrefix(def, "-")
		sqlCol = allowed[col]
	}
	if desc {
		return sqlCol + " DESC"
	}
	return sqlCol + " ASC"
}

// parseIfMatch 解析 If-Match 请求头（docs/API-v2.md §0.4：直接是 version 整数，不是 ETag 引号语法）。
// 缺失或不是正整数时返回 0，调用方据此判断"不检查版本"（后台脚本场景）。
func parseIfMatch(r *http.Request) int {
	v := strings.TrimSpace(r.Header.Get("If-Match"))
	// 也接受标准 ETag 写法 "3" / W/"3"：否则带引号的请求会被当成「没带 If-Match」而静默跳过乐观锁。
	v = strings.Trim(strings.TrimPrefix(v, "W/"), `"`)
	if v == "" {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return 0
	}
	return n
}
