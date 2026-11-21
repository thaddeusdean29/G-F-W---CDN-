package waf

import (
	"sync"
	"time"
)

// verifyFailLimit 是同一 IP 在 verifyFailWindow 时间窗内允许的 /__cc/verify 连续失败次数。
// 正常用户过一次挑战就拿到 cookie，几乎不会连续失败；反复拿不到正确 cookie / 反复重刷
// 极大概率是脚本在爆破票据或环境。达到该阈值即封禁该 IP。
const verifyFailLimit = 3

// verifyFailWindow 是失败计数的滑动清零窗口：窗口内无新失败则计数自动过期，
// 避免把"偶发失败后隔很久又来"的真实用户误当攻击者累计封禁。
const verifyFailWindow = 2 * time.Minute

// verifyBlockDuration 是 verify 爆破触发的封禁时长。挑战验证爆破属于明确恶意，
// 30 分钟足够劝退当前攻击波，又不会因误伤留下持久黑名单。
const verifyBlockDuration = 30 * time.Minute

// maxVerifyTrackers 是 verify 失败追踪器的数量上限。IP 可被伪造（XFF），
// 若不设上限会被用来放大内存占用。达上限后不再创建新 tracker（已有 IP 的限速仍正常工作）。
const maxVerifyTrackers = 50000

// verifyFailTracker 记录单个 IP 对 /__cc/verify 的连续失败情况。
type verifyFailTracker struct {
	count   int
	firstAt time.Time
	lastAt  time.Time
}

// VerifyThrottle 是 /__cc/verify 的应用层失败限速器：按 IP 统计验证失败次数，
// 达阈值交给调用方封禁。与 Tengine 层的 limit_req（挡洪水刷 CPU）互补——
// 这一层精准命中"反复拿不到正确 cookie"的爆破特征。
type VerifyThrottle struct {
	mu       sync.Mutex
	trackers map[string]*verifyFailTracker
}

// NewVerifyThrottle 创建 verify 失败限速器并启动后台清理。
func NewVerifyThrottle() *VerifyThrottle {
	vt := &VerifyThrottle{trackers: make(map[string]*verifyFailTracker)}
	go vt.cleanup()
	return vt
}

// RecordFailure 记录一次 verify 失败，返回该 IP 是否已达到封禁阈值。
// 返回 true 时调用方应封禁该 IP。ip 为空时不计数（返回 false）。
func (vt *VerifyThrottle) RecordFailure(ip string) bool {
	if ip == "" {
		return false
	}
	now := time.Now()

	vt.mu.Lock()
	defer vt.mu.Unlock()

	t, ok := vt.trackers[ip]
	if !ok || now.Sub(t.lastAt) > verifyFailWindow {
		// 首次失败，或距上次失败已超过窗口 → 重新开窗计数。
		// 达到容量上限后不再创建新 tracker，防止攻击者通过伪造 IP 耗尽内存。
		// 已有 IP 的限速仍正常工作，只是新 IP 的失败不再追踪。
		if !ok && len(vt.trackers) >= maxVerifyTrackers {
			return false
		}
		t = &verifyFailTracker{firstAt: now}
		vt.trackers[ip] = t
	}
	t.count++
	t.lastAt = now
	return t.count >= verifyFailLimit
}

// RecordSuccess 清除该 IP 的失败计数：正常用户过一次挑战即成功，应立即归零，
// 不让此前的偶发失败残留累计。
func (vt *VerifyThrottle) RecordSuccess(ip string) {
	if ip == "" {
		return
	}
	vt.mu.Lock()
	delete(vt.trackers, ip)
	vt.mu.Unlock()
}

// cleanup 定期回收已超过失败窗口、不再活跃的追踪器，防止内存无限增长。
func (vt *VerifyThrottle) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		now := time.Now()
		vt.mu.Lock()
		for ip, t := range vt.trackers {
			if now.Sub(t.lastAt) > verifyFailWindow {
				delete(vt.trackers, ip)
			}
		}
		vt.mu.Unlock()
	}
}
