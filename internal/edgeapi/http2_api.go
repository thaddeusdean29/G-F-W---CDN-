package edgeapi

import (
	"encoding/json"
	"net/http"
	"time"
)

// HTTP2RapidResetAPI 处理 HTTP/2 Rapid Reset 相关的 API 请求
func (h *Handler) serveHTTP2RapidResetAPI(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/edge/http2/rst-report":
		// Tengine 通过此端点上报 RST_STREAM 统计
		h.handleRSTReport(w, r)
	case "/edge/http2/stats":
		// 获取 HTTP/2 Rapid Reset 统计信息
		h.handleHTTP2Stats(w, r)
	default:
		http.Error(w, "Not Found", http.StatusNotFound)
	}
}

// handleRSTReport 处理 Tengine 上报的 RST_STREAM 统计
func (h *Handler) handleRSTReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// 限制只接受本机请求（Tengine 内部调用）
	host, _, _ := splitHostPort(r.RemoteAddr)
	if host != "127.0.0.1" && host != "::1" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	var req struct {
		ClientIP  string `json:"client_ip"`
		RSTCount  int    `json:"rst_count"`
		TimeRange int    `json:"time_range"` // 统计时间范围（秒）
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	detector := h.wafEngine.GetHTTP2RapidResetDetector()
	if detector == nil {
		http.Error(w, "HTTP/2 Rapid Reset detection not enabled", http.StatusServiceUnavailable)
		return
	}

	// 检查是否应封禁
	shouldBan := false
	for i := 0; i < req.RSTCount; i++ {
		if detector.RecordRSTStream(req.ClientIP) {
			shouldBan = true
			break
		}
	}

	if shouldBan {
		// 封禁该 IP（10 分钟）
		h.wafEngine.BlockIP(req.ClientIP, time.Duration(detector.GetConfig().BanDuration)*time.Second)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{
			"action": "banned",
			"ip":     req.ClientIP,
			"reason": "HTTP/2 Rapid Reset attack detected",
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"action": "recorded",
		"ip":     req.ClientIP,
	})
}

// handleHTTP2Stats 返回 HTTP/2 Rapid Reset 统计信息
func (h *Handler) handleHTTP2Stats(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	detector := h.wafEngine.GetHTTP2RapidResetDetector()
	if detector == nil {
		http.Error(w, "HTTP/2 Rapid Reset detection not enabled", http.StatusServiceUnavailable)
		return
	}

	// 返回基本统计信息
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]any{
		"enabled": true,
		"message": "HTTP/2 Rapid Reset detection is active",
	})
}

func splitHostPort(addr string) (host, port string, err error) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:], nil
		}
	}
	return addr, "", nil
}
