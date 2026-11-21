package waf

import (
	"fmt"
	"net/http"
	"sync"
	"time"
)

// LoginBruteForceDetector 登录暴力破解检测器（简化版，独立使用）。
// 与 LoginBruteforceProtector 不同，这是一个独立的检测器，不依赖 Engine。
type LoginBruteForceDetector struct {
	mu          sync.RWMutex
	attempts    map[string]*loginAttemptTracker
	maxAttempts int
	window      time.Duration
}

type loginAttemptTracker struct {
	failedCount int
	windowStart time.Time
}

// maxLoginDetectorTrackers 是登录尝试检测器的数量上限。IP 可被伪造（XFF），
// 若不设上限会被用来放大内存占用。达上限后不再创建新 tracker（已有 IP 的检测仍正常工作）。
const maxLoginDetectorTrackers = 100000

// NewLoginBruteForceDetector 创建登录暴力破解检测器。
func NewLoginBruteForceDetector(maxAttempts int, window time.Duration) *LoginBruteForceDetector {
	if maxAttempts <= 0 {
		maxAttempts = 5
	}
	if window == 0 {
		window = time.Minute
	}

	d := &LoginBruteForceDetector{
		attempts:    make(map[string]*loginAttemptTracker),
		maxAttempts: maxAttempts,
		window:      window,
	}

	// 定期清理过期记录
	go d.gc()

	return d
}

// IsBlocked 检查 IP 是否因失败次数过多而被限制（只检查，不记录）。
// 返回 nil 表示允许，返回 *Result 表示应拦截。
func (d *LoginBruteForceDetector) IsBlocked(r *http.Request) *Result {
	ip := extractClientIP(r)
	if ip == "" {
		return nil
	}

	d.mu.RLock()
	tracker, exists := d.attempts[ip]
	d.mu.RUnlock()

	if !exists {
		return nil
	}

	// 窗口过期，不拦截
	if time.Now().Sub(tracker.windowStart) > d.window {
		return nil
	}

	// 检查是否超过阈值
	if tracker.failedCount >= d.maxAttempts {
		return &Result{
			Action:  Block,
			Rule:    "login-bruteforce",
			Message: fmt.Sprintf("too many failed login attempts from IP %s", ip),
		}
	}

	return nil
}

// RecordFailure 记录一次失败的登录尝试。
func (d *LoginBruteForceDetector) RecordFailure(r *http.Request) {
	ip := extractClientIP(r)
	if ip == "" {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	tracker, exists := d.attempts[ip]
	if !exists {
		// 达到容量上限后不再创建新 tracker，防止攻击者通过伪造 IP 耗尽内存。
		// 已有 IP 的检测仍正常工作，只是新 IP 的失败不再追踪。
		if len(d.attempts) >= maxLoginDetectorTrackers {
			return
		}
		tracker = &loginAttemptTracker{
			failedCount: 0,
			windowStart: now,
		}
		d.attempts[ip] = tracker
	}

	// 窗口过期，重置计数
	if now.Sub(tracker.windowStart) > d.window {
		tracker.failedCount = 0
		tracker.windowStart = now
	}

	// 增加失败计数
	tracker.failedCount++
}

// RecordSuccess 记录一次成功的登录，重置该 IP 的失败计数。
func (d *LoginBruteForceDetector) RecordSuccess(r *http.Request) {
	ip := extractClientIP(r)
	if ip == "" {
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	if tracker, exists := d.attempts[ip]; exists {
		tracker.failedCount = 0
	}
}

// CheckLogin 检查登录尝试（旧 API，保持兼容性）。
// success 为 true 表示登录成功，会重置该 IP 的失败计数。
// 返回 nil 表示允许，返回 *Result 表示应拦截。
//
// 已废弃：请使用 IsBlocked/RecordFailure/RecordSuccess 分离检查和记录操作。
func (d *LoginBruteForceDetector) CheckLogin(r *http.Request, success bool) *Result {
	if success {
		d.RecordSuccess(r)
		return nil
	}

	// 检查后记录失败（保持旧行为）
	if res := d.IsBlocked(r); res != nil {
		return res
	}
	d.RecordFailure(r)
	return nil
}

// gc 定期清理过期记录
func (d *LoginBruteForceDetector) gc() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		d.mu.Lock()
		for ip, tracker := range d.attempts {
			if now.Sub(tracker.windowStart) > d.window+time.Hour {
				delete(d.attempts, ip)
			}
		}
		d.mu.Unlock()
	}
}
