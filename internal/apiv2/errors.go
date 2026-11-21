package apiv2

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/go-sql-driver/mysql"
)

// ApiError 是 docs/API-v2.md §0.6 定义的统一错误结构。
type ApiError struct {
	Code    string         `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `json:"details,omitempty"`
}

func (e *ApiError) Error() string { return e.Code + ": " + e.Message }

func NewApiError(code, message string) *ApiError {
	return &ApiError{Code: code, Message: message}
}

func (e *ApiError) WithDetails(details map[string]any) *ApiError {
	e.Details = details
	return e
}

type errorEnvelope struct {
	Error *ApiError `json:"error"`
}

// codeToStatus 镜像 docs/API-v2.md §0.6 的表格。缺失的 code 会 panic——这是故意的：
// 新错误码必须先在这里登记，否则接口会返回 500 而不是文档承诺的状态码。
var codeToStatus = map[string]int{
	"invalid_json":          http.StatusBadRequest,
	"unknown_field":         http.StatusBadRequest,
	"readonly_field":        http.StatusBadRequest,
	"validation_failed":     http.StatusBadRequest,
	"unauthenticated":       http.StatusUnauthorized,
	"invalid_credentials":   http.StatusUnauthorized,
	"csrf_invalid":          http.StatusForbidden,
	"forbidden":             http.StatusForbidden,
	"quota_exceeded":        http.StatusForbidden,
	"tenant_inactive":       http.StatusForbidden,
	"not_found":             http.StatusNotFound,
	"version_conflict":      http.StatusConflict,
	"domain_taken":          http.StatusConflict,
	"conflict":              http.StatusConflict,
	"in_use":                http.StatusConflict,
	"domain_unverified":     http.StatusUnprocessableEntity,
	"cf_not_configured":     http.StatusUnprocessableEntity,
	"defense_cname_missing": http.StatusUnprocessableEntity,
	"cluster_missing":       http.StatusUnprocessableEntity,
	// 域名的 DNS 不归面板配的 Cloudflare Zone 管，dns-01 无处可写 —— 只能走上传证书。
	"acme_unsupported": http.StatusUnprocessableEntity,
	"rate_limited":          http.StatusTooManyRequests,
	"upstream_failed":       http.StatusBadGateway,
	"unavailable":           http.StatusServiceUnavailable,
	"internal_error":        http.StatusInternalServerError,
}

// StatusForCode 返回错误码对应的 HTTP 状态码；未登记的 code 会 panic。
func StatusForCode(code string) int {
	if s, ok := codeToStatus[code]; ok {
		return s
	}
	panic("apiv2: unregistered error code " + code)
}

// WriteError 把 err 写成 docs/API-v2.md §0.6 的响应体。err 不是 *ApiError 时
// 视为未预期的内部错误，返回 500，不把 err.Error() 内容暴露给客户端。
func WriteError(w http.ResponseWriter, err error) {
	var ae *ApiError
	if !errors.As(err, &ae) {
		// 对外只回「内部错误」，真实原因必须落日志，否则线上 500 无从排查。
		log.Printf("apiv2 internal error: %v", err)
		ae = NewApiError("internal_error", "内部错误")
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(errorEnvelope{Error: ae})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(StatusForCode(ae.Code))
	_ = json.NewEncoder(w).Encode(errorEnvelope{Error: ae})
}

var dupKeyRe = regexp.MustCompile(`for key '([^']+)'`)

// extractIndexName 从 MySQL 1062 错误信息里取出索引名。MySQL 8.0.19+ 格式为
// "Duplicate entry 'x' for key 'table.index'"，更早版本没有表名前缀，两种都处理。
func extractIndexName(msg string) string {
	m := dupKeyRe.FindStringSubmatch(msg)
	if m == nil {
		return ""
	}
	name := m[1]
	if i := strings.LastIndex(name, "."); i >= 0 {
		name = name[i+1:]
	}
	return name
}

// ClassifyMySQLError 把触发器/约束抛出的 MySQL 错误翻译成 *ApiError。
// indexCodes 把调用方关心的唯一索引名映射到业务错误码（如 "clusters_name_uq" -> "conflict"，
// "domains_verified_uq" -> "domain_taken"）；命中不了的索引名统一按 conflict 处理。
// err 不是 MySQL 错误时返回 nil，调用方应继续把 err 当成普通内部错误处理。
func ClassifyMySQLError(err error, indexCodes map[string]string) *ApiError {
	var me *mysql.MySQLError
	if !errors.As(err, &me) {
		return nil
	}
	switch me.Number {
	case 1062: // 唯一约束冲突
		idx := extractIndexName(me.Message)
		code, ok := indexCodes[idx]
		if !ok {
			code = "conflict"
		}
		return NewApiError(code, "已存在冲突的记录").WithDetails(map[string]any{"field": idx})
	case 1451: // 外键 RESTRICT（删除父行时子行仍存在）
		return NewApiError("in_use", "仍被其他资源引用")
	case 1452: // 外键约束失败（插入/更新时引用了不存在的父行，如 cluster_id/failover_target_id 填了别的租户或不存在的 ID）
		return NewApiError("validation_failed", "引用的资源不存在")
	case 3819, 4025: // CHECK 约束失败（MySQL 8 为 3819，4025 是 MariaDB）：字段取值不合法，不是服务器故障
		return NewApiError("validation_failed", "字段取值不合法")
	}
	return nil
}
