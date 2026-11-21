package edgeapi

import (
	"net/http"

	"cdn/internal/waf"
)

// HTTP2Monitor 监控 HTTP/2 连接的 RST_STREAM 帧
type HTTP2Monitor struct {
	detector *waf.HTTP2RapidResetDetector
	banFunc  func(ip string) // 封禁函数
}

// NewHTTP2Monitor 创建 HTTP/2 监控器
func NewHTTP2Monitor(detector *waf.HTTP2RapidResetDetector, banFunc func(ip string)) *HTTP2Monitor {
	if detector == nil {
		return nil
	}
	return &HTTP2Monitor{
		detector: detector,
		banFunc:  banFunc,
	}
}

// HTTP2Middleware 是 HTTP/2 监控中间件，拦截 RST_STREAM 帧
func (m *HTTP2Monitor) HTTP2Middleware(next http.Handler) http.Handler {
	if m == nil || m.detector == nil {
		return next
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 只监控 HTTP/2 请求
		if r.ProtoMajor != 2 {
			next.ServeHTTP(w, r)
			return
		}

		clientIP := extractClientIP(r)
		if clientIP == "" {
			next.ServeHTTP(w, r)
			return
		}

		// 从 Tengine 传递的自定义头获取 RST_STREAM 计数
		// Tengine 配置需要在 HTTP/2 模块中统计 RST 并通过 proxy_set_header 传递
		rstCountStr := r.Header.Get("X-H2-RST-Count")
		if rstCountStr != "" {
			// Tengine 已检测到该客户端有 RST_STREAM 活动
			// 这里记录到检测器进行累积判定
			if m.detector.RecordRSTStream(clientIP) {
				// 超过阈值，封禁该 IP
				if m.banFunc != nil {
					m.banFunc(clientIP)
				}
				http.Error(w, "Too Many RST_STREAM", http.StatusTooManyRequests)
				return
			}
		}

		next.ServeHTTP(w, r)
	})
}

// 注意：Go 的标准库 net/http 不直接暴露 RST_STREAM 事件。
// 实际部署中，需要在反向代理层（如 Tengine/Nginx）监控 RST_STREAM 帧，
// 然后通过自定义请求头（如 X-H2-RST-Count）传递给后端应用。
//
// Tengine 层实现方式：
// 1. 使用 ngx_http_v2_module 的钩子函数或 Lua 钩子捕获 RST_STREAM 帧
// 2. 在 map 指令中统计每个客户端 IP 的 RST 计数（需要自定义模块）
// 3. 通过 proxy_set_header X-H2-RST-Count $http2_rst_stream_count 传递给后端
// 4. 后端 WAF 收到该头后累积判定，超过阈值则封禁
//
// 如果 Tengine 层检测到 RST 超限，也可以直接返回 429 而不转发到后端：
//   if ($h2_attack = 1) {
//       return 429;
//   }

// extractClientIP 从请求中提取客户端 IP
func extractClientIP(r *http.Request) string {
	// 优先从 X-Forwarded-For 或 X-Real-IP 获取（Tengine 设置）
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return xff
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}
	// 回退到 RemoteAddr
	host, _, _ := splitHostPortSimple(r.RemoteAddr)
	return host
}

func splitHostPortSimple(addr string) (host, port string, err error) {
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i], addr[i+1:], nil
		}
	}
	return addr, "", nil
}
