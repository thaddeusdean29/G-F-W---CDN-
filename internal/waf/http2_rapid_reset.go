package waf

import (
	"sync"
	"time"
)

// RapidResetConfig HTTP/2 Rapid Reset 攻击检测配置
type RapidResetConfig struct {
	Enabled      bool // 是否启用
	RSTThreshold int  // RST_STREAM 阈值（次/秒）
	WindowSize   int  // 时间窗口（秒）
	BanDuration  int  // 封禁时长（秒）
}

// HTTP2RapidResetDetector HTTP/2 Rapid Reset 攻击检测器
//
// CVE-2023-44487：攻击者通过 HTTP/2 连接快速发送请求后立即发送 RST_STREAM 帧取消，
// 导致服务器资源耗尽。正常客户端极少频繁 RST，短时间内大量 RST 必为攻击。
//
// 检测逻辑：统计每个客户端 IP 在时间窗口内的 RST_STREAM 次数，超过阈值则封禁。
type HTTP2RapidResetDetector struct {
	mu       sync.RWMutex
	enabled  bool
	cfg      RapidResetConfig
	rstCount map[string]*rstRecord // IP -> RST 计数记录
}

type rstRecord struct {
	count      int
	windowStart time.Time
}

// NewHTTP2RapidResetDetector 创建 HTTP/2 Rapid Reset 检测器
func NewHTTP2RapidResetDetector(cfg RapidResetConfig) *HTTP2RapidResetDetector {
	if !cfg.Enabled {
		return nil
	}
	if cfg.RSTThreshold <= 0 {
		cfg.RSTThreshold = 100 // 默认 100 次/秒
	}
	if cfg.WindowSize <= 0 {
		cfg.WindowSize = 1 // 默认 1 秒窗口
	}
	if cfg.BanDuration <= 0 {
		cfg.BanDuration = 600 // 默认封禁 10 分钟
	}

	d := &HTTP2RapidResetDetector{
		enabled:  true,
		cfg:      cfg,
		rstCount: make(map[string]*rstRecord),
	}

	// 启动后台清理协程：每分钟清理过期的记录
	go d.cleanup()

	return d
}

// RecordRSTStream 记录一次 RST_STREAM 帧，返回是否应封禁该 IP
func (d *HTTP2RapidResetDetector) RecordRSTStream(ip string) bool {
	if !d.enabled || ip == "" {
		return false
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	rec, exists := d.rstCount[ip]

	if !exists {
		// 首次记录
		d.rstCount[ip] = &rstRecord{
			count:       1,
			windowStart: now,
		}
		return false
	}

	// 检查是否在同一时间窗口内
	elapsed := now.Sub(rec.windowStart).Seconds()
	if elapsed > float64(d.cfg.WindowSize) {
		// 窗口已过期，重置计数
		rec.count = 1
		rec.windowStart = now
		return false
	}

	// 窗口内累加计数
	rec.count++

	// 检查是否超过阈值
	if rec.count > d.cfg.RSTThreshold {
		// 清除该 IP 的记录（避免重复封禁）
		delete(d.rstCount, ip)
		return true
	}

	return false
}

// cleanup 后台清理过期的 RST 计数记录
func (d *HTTP2RapidResetDetector) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		d.mu.Lock()
		now := time.Now()
		for ip, rec := range d.rstCount {
			if now.Sub(rec.windowStart).Seconds() > float64(d.cfg.WindowSize*2) {
				delete(d.rstCount, ip)
			}
		}
		d.mu.Unlock()
	}
}

// GetConfig 获取当前配置
func (d *HTTP2RapidResetDetector) GetConfig() RapidResetConfig {
	if d == nil {
		return RapidResetConfig{}
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.cfg
}
