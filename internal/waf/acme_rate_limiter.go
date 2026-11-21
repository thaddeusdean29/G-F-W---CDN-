package waf

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// ACMERateLimiter 针对 ACME 验证路径的速率限制器。
// 防止攻击者滥用 /.well-known/acme-challenge/ 耗尽 Let's Encrypt 配额。
type ACMERateLimiter struct {
	mu           sync.RWMutex
	requests     map[string]*acmeTracker
	maxPerIP     int           // 每个 IP 在窗口内最多请求次数
	maxPerDomain int           // 每个域名在窗口内最多请求次数
	window       time.Duration // 时间窗口
}

type acmeTracker struct {
	count       int
	windowStart time.Time
}

// maxACMETrackers 是 ACME 请求追踪器的数量上限。键包含 IP 和域名（均由攻击者控制），
// 若不设上限会被用来放大内存占用。达上限后不再创建新 tracker（已有条目的限速仍正常工作）。
const maxACMETrackers = 10000

// NewACMERateLimiter 创建 ACME 速率限制器。
// maxPerIP: 每个 IP 在窗口内最多请求次数（推荐 10）
// maxPerDomain: 每个域名在窗口内最多请求次数（推荐 20）
// window: 时间窗口（推荐 1 分钟）
func NewACMERateLimiter(maxPerIP, maxPerDomain int, window time.Duration) *ACMERateLimiter {
	if maxPerIP <= 0 {
		maxPerIP = 10
	}
	if maxPerDomain <= 0 {
		maxPerDomain = 20
	}
	if window == 0 {
		window = time.Minute
	}

	limiter := &ACMERateLimiter{
		requests:     make(map[string]*acmeTracker),
		maxPerIP:     maxPerIP,
		maxPerDomain: maxPerDomain,
		window:       window,
	}

	// 定期清理过期记录
	go limiter.gc()

	return limiter
}

// CheckACMERequest 检查 ACME 验证路径的请求是否超限。
// 返回 nil 表示允许，返回 *Result 表示应拦截。
func (l *ACMERateLimiter) CheckACMERequest(r *http.Request) *Result {
	path := r.URL.Path
	if !strings.HasPrefix(path, "/.well-known/acme-challenge/") {
		return nil // 非 ACME 路径，不限制
	}

	ip := extractClientIP(r)
	host := r.Host

	// 空 IP 或空 Host，允许通过（边缘情况）
	if ip == "" || host == "" {
		return nil
	}

	now := time.Now()

	// 检查 IP 限速
	ipKey := "ip:" + ip
	if blocked := l.checkLimit(ipKey, now, l.maxPerIP); blocked != nil {
		return blocked
	}

	// 检查域名限速
	domainKey := "domain:" + host
	if blocked := l.checkLimit(domainKey, now, l.maxPerDomain); blocked != nil {
		return blocked
	}

	return nil
}

// checkLimit 检查指定键的限速状态并记录请求。
func (l *ACMERateLimiter) checkLimit(key string, now time.Time, max int) *Result {
	l.mu.Lock()
	defer l.mu.Unlock()

	tracker, exists := l.requests[key]
	if !exists {
		// 达到容量上限后不再创建新 tracker，防止攻击者通过伪造 IP/Host 耗尽内存。
		// 已有条目的限速仍正常工作，只是新 IP/域名的 ACME 请求不再限速（仍受上游限制）。
		if len(l.requests) >= maxACMETrackers {
			return nil
		}
		tracker = &acmeTracker{
			count:       0,
			windowStart: now,
		}
		l.requests[key] = tracker
	}

	// 窗口过期，重置计数
	if now.Sub(tracker.windowStart) > l.window {
		tracker.count = 0
		tracker.windowStart = now
	}

	// 检查是否超限
	if tracker.count >= max {
		return &Result{
			Action:  Block,
			Rule:    "acme-rate-limit",
			Message: "ACME challenge rate limit exceeded for " + key,
		}
	}

	// 记录本次请求
	tracker.count++
	return nil
}

// gc 定期清理过期记录
func (l *ACMERateLimiter) gc() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		l.mu.Lock()
		for key, tracker := range l.requests {
			if now.Sub(tracker.windowStart) > l.window+time.Hour {
				delete(l.requests, key)
			}
		}
		l.mu.Unlock()
	}
}

// extractClientIP 提取客户端真实 IP 并归一化（与 waf.clientIP 保持一致）。
// 必须归一化：同一个 IPv6 地址有多种等价写法（"2001:DB8::1" / "2001:db8::0:1"），
// 不归一会导致限速计数被拆散到多个键上，等于给攻击者放大配额。
func extractClientIP(r *http.Request) string {
	// 复用 waf.clientIP 的归一化逻辑，避免各模块对同一 IP 产生不同的键。
	return clientIP(r)
}
