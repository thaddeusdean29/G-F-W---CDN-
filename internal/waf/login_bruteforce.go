package waf

import (
	"log"
	"strings"
	"sync"
	"time"
)

// LoginBruteforceProtector 登录端点暴力破解防护器。
// 跟踪每个 IP 对登录端点的失败尝试次数，超过阈值时自动封禁。
type LoginBruteforceProtector struct {
	mu               sync.RWMutex
	attempts         map[string]*loginAttemptRecord // ip → 尝试记录
	loginPaths       []string                       // 需要保护的登录路径（如 /api/login, /admin/login）
	softThreshold    int                            // 软阈值：达到后需要 CAPTCHA（未来扩展，暂不实现）
	hardThreshold    int                            // 硬阈值：达到后直接封禁
	banDuration      time.Duration                  // 封禁时长
	windowDuration   time.Duration                  // 失败计数时间窗口
	engine           *Engine                        // WAF 引擎（用于执行封禁）
}

type loginAttemptRecord struct {
	failures      int       // 失败次数
	windowStart   time.Time // 当前窗口开始时间
	lastAttemptAt time.Time // 最后一次尝试时间
}

// maxLoginAttemptTrackers 是登录尝试追踪器的数量上限。IP 可被伪造（XFF），
// 若不设上限会被用来放大内存占用。达上限后不再创建新 tracker（已有 IP 的防护仍正常工作）。
const maxLoginAttemptTrackers = 100000

// LoginBruteforceConfig 暴力破解防护配置。
type LoginBruteforceConfig struct {
	LoginPaths     []string      // 需要保护的登录路径
	SoftThreshold  int           // 软阈值（建议 5）
	HardThreshold  int           // 硬阈值（建议 10）
	BanDuration    time.Duration // 封禁时长（建议 1 小时）
	WindowDuration time.Duration // 时间窗口（建议 10 分钟）
}

// NewLoginBruteforceProtector 创建登录暴力破解防护器。
func NewLoginBruteforceProtector(cfg LoginBruteforceConfig, engine *Engine) *LoginBruteforceProtector {
	if cfg.SoftThreshold <= 0 {
		cfg.SoftThreshold = 5
	}
	if cfg.HardThreshold <= 0 {
		cfg.HardThreshold = 10
	}
	if cfg.BanDuration == 0 {
		cfg.BanDuration = time.Hour
	}
	if cfg.WindowDuration == 0 {
		cfg.WindowDuration = 10 * time.Minute
	}

	p := &LoginBruteforceProtector{
		attempts:       make(map[string]*loginAttemptRecord),
		loginPaths:     cfg.LoginPaths,
		softThreshold:  cfg.SoftThreshold,
		hardThreshold:  cfg.HardThreshold,
		banDuration:    cfg.BanDuration,
		windowDuration: cfg.WindowDuration,
		engine:         engine,
	}

	// 定期清理过期记录
	go p.gc()

	return p
}

// IsLoginPath 判断请求路径是否是登录端点。
func (p *LoginBruteforceProtector) IsLoginPath(path string) bool {
	for _, lp := range p.loginPaths {
		if strings.HasPrefix(path, lp) {
			return true
		}
	}
	return false
}

// RecordFailure 记录一次登录失败。应由应用层在检测到登录失败（如密码错误）时调用。
// 返回是否应该封禁该 IP。
func (p *LoginBruteforceProtector) RecordFailure(ip string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	now := time.Now()
	rec, exists := p.attempts[ip]
	if !exists {
		// 达到容量上限后不再创建新 tracker，防止攻击者通过伪造 IP 耗尽内存。
		// 已有 IP 的防护仍正常工作，只是新 IP 的失败不再追踪（仍可依赖其他防护层）。
		if len(p.attempts) >= maxLoginAttemptTrackers {
			return false
		}
		rec = &loginAttemptRecord{
			windowStart:   now,
			lastAttemptAt: now,
		}
		p.attempts[ip] = rec
	}

	// 如果超出时间窗口，重置计数
	if now.Sub(rec.windowStart) > p.windowDuration {
		rec.failures = 0
		rec.windowStart = now
	}

	rec.failures++
	rec.lastAttemptAt = now

	// 达到硬阈值时封禁
	if rec.failures >= p.hardThreshold {
		if p.engine != nil {
			p.engine.BlockIP(ip, p.banDuration)
			log.Printf("[WAF] Login bruteforce: blocked IP %s (%d failures in %v)", ip, rec.failures, p.windowDuration)
		}
		// 重置计数（避免重复封禁）
		delete(p.attempts, ip)
		return true
	}

	// 达到软阈值时警告（未来可以触发 CAPTCHA）
	if rec.failures >= p.softThreshold {
		log.Printf("[WAF] Login bruteforce: IP %s reached soft threshold (%d failures)", ip, rec.failures)
	}

	return false
}

// RecordSuccess 记录一次登录成功。清除该 IP 的失败计数（避免正常用户偶尔输错密码被累积封禁）。
func (p *LoginBruteforceProtector) RecordSuccess(ip string) {
	p.mu.Lock()
	delete(p.attempts, ip)
	p.mu.Unlock()
}

// GetFailureCount 获取某个 IP 当前的失败次数（用于应用层判断是否需要显示 CAPTCHA）。
func (p *LoginBruteforceProtector) GetFailureCount(ip string) int {
	p.mu.RLock()
	defer p.mu.RUnlock()

	rec, exists := p.attempts[ip]
	if !exists {
		return 0
	}

	// 检查是否过期
	if time.Since(rec.windowStart) > p.windowDuration {
		return 0
	}

	return rec.failures
}

// gc 定期清理超出时间窗口的失败记录。
func (p *LoginBruteforceProtector) gc() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		p.mu.Lock()
		for ip, rec := range p.attempts {
			// 清理超过窗口时长 + 1 小时仍未再次尝试的记录
			if now.Sub(rec.lastAttemptAt) > p.windowDuration+time.Hour {
				delete(p.attempts, ip)
			}
		}
		p.mu.Unlock()
	}
}
