package waf

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// CacheBusterDetector 检测缓存绕过攻击：攻击者通过随机 query 参数打穿 CDN 缓存，
// 让每个请求都 cache MISS 直接轰源站。
//
// 典型攻击模式：
//
//	GET /api/products?_=1001
//	GET /api/products?_=1002
//	GET /api/products?_=1003  (每次不同随机参数)
//
// 同一 IP 短时间内请求相同 path 但 query string 疯狂变化，是缓存绕过的明确信号。
// CC 层按 IP 限速能挡住总 QPS，但挡不住"每个请求都打穿缓存"这件事——单 IP 即使
// 只发 10 req/s，若每次参数都不同，源站仍要扛 10 次真实查询。
type CacheBusterDetector struct {
	mu       sync.RWMutex
	trackers map[string]*cacheBusterTracker // key: IP

	// 容量压力：IP 追踪器表一张，外加"单 IP 路径变体超上限被丢弃"的累计次数。
	// 两者都只在打满时才写，热路径成本是一次原子加。
	trackerPressure pressureCounters
	pathPressure    pressureCounters
	pathEntries     atomic.Int64 // 当前 pathVariants 条目总数（跨所有 IP）
}

// cacheBusterTracker 单个 IP 的缓存绕过行为追踪器。
type cacheBusterTracker struct {
	mu             sync.Mutex
	pathVariants   map[string]*pathVariantStats // key: normalized path（去掉已知无害参数后的路径）
	lastSeen       time.Time                    // 该 IP 最近一次带 query 的请求，用于表满时挑最不活跃的牺牲品
	lastCleanup    time.Time
	blockedUntil   time.Time // 非零且未过期时，该 IP 因缓存绕过被临时封禁
	violationCount int       // 累计违规次数

	// 路径扇出计数：detectionWindow 内因额度用尽而被丢掉的路径条数。
	// 单 IP 额度既是内存上限，也是检测信号本身——"每个请求换一个路径"正是打穿缓存的
	// 另一种形态，它绕过了按路径统计的唯一 query 阈值，但不该绕过检测。
	overflowWindowStart time.Time
	overflowCount       int
}

// pathVariantStats 单个规范化路径的变体统计。
type pathVariantStats struct {
	uniqueQueries map[string]time.Time // key: normalized query hash, value: 首次出现时间
	requestCount  int                  // 该路径总请求数（含重复 query）
	windowStart   time.Time            // 统计窗口开始时间
	lastSeen      time.Time            // 最后一次请求时间
}

const (
	// detectionWindow 是统计窗口：同一 path 在此时间内出现过多唯一 query 才判定为攻击。
	detectionWindow = 10 * time.Second

	// uniqueQueryThreshold 是同一 path 在 detectionWindow 内允许的最大唯一 query 数。
	// 超过此阈值视为缓存绕过攻击。正常用户不会在 10 秒内对同一资源请求 20 种不同参数。
	uniqueQueryThreshold = 20

	// requestDiversityRatio 是"唯一 query 数 / 总请求数"的最小比例。
	// 若该比例 >= 此值，说明几乎每次请求都换参数（高度可疑）。
	// 例如 0.8 表示：10 次请求中有 8 次用了不同参数。
	requestDiversityRatio = 0.8

	// blockDuration 是检测到缓存绕过后的封禁时长。
	blockDuration = 10 * time.Minute

	// trackerCleanupInterval 是 tracker 清理周期：删除长期不活跃的条目。
	trackerCleanupInterval = 5 * time.Minute

	// trackerIdleTimeout 是 tracker 被视为不活跃的时长。
	trackerIdleTimeout = 15 * time.Minute

	// maxTrackers 是 IP 追踪器数量上限（防内存放大）。达上限后采样回收最不活跃的 IP
	// 腾位，而不是拒绝为新 IP 建档：后者等于让检测器在攻击最凶的时候静默下线。
	maxTrackers = 100000

	// maxPathsPerIP 是单个 IP 能占用的路径变体条目上限。
	//
	// 没有它，"每个请求换一个路径"的攻击就能无限撑大 pathVariants：检测窗口 10 秒、
	// 清理周期 5 分钟，一条路径统计能活 15 分钟，而 CC 层按 IP 限速挡的是总 QPS，
	// 挡不住"检测器自己的内存被买断"这件事。超上限时丢掉最久未见的那条路径统计——
	// 攻击者要的就是"让检测器跟不上"，这里用有界换精度，而不是用无限内存换精确。
	//
	// 64 条对真实访客足够：只有带 query 的请求才建条目，一个重页面在 10 秒里也
	// 凑不出 64 个不同的带参 URL。
	maxPathsPerIP = 64

	// maxTotalPathEntries 是跨所有 IP 的路径变体条目总预算，也是这个检测器真正的内存天花板。
	//
	// 只有 maxPathsPerIP 不够：单 IP 的 64 条管得住一个源，管不住「10 万个源各刷 64 条」，
	// 那就是 maxTrackers × maxPathsPerIP = 640 万条目 ≈ 1.9GB，攻击者花一份僵尸网络带宽
	// 就能把节点买到 OOM——而被 OOM 的是 cdnedge，等于 CC/WAF 全体下线。
	// 50 万条（每条约 300B，含 uniqueQueries 小 map）≈ 150MB，够同时跟踪几万个真实访客
	// 的路径画像；打满时按「先保已在统计的 IP，新 IP 这次不统计」降级并计入 dropped，
	// 而不是无声增长。
	maxTotalPathEntries = 500000
)

// knownCacheParams 是已知合法的缓存控制参数列表，这些参数的变化不算作攻击信号。
// 业务合法使用的版本号、时间戳、认证 token 等应加入此列表（或在域名配置中指定）。
var knownCacheParams = map[string]bool{
	"v":       true, // version
	"ver":     true,
	"version": true,
	"t":       true, // timestamp（某些 CDN 的合法缓存刷新）
	"ts":      true,
}

func NewCacheBusterDetector() *CacheBusterDetector {
	d := &CacheBusterDetector{
		trackers: make(map[string]*cacheBusterTracker),
	}
	d.trackerPressure.limit = maxTrackers
	// 路径条目的额度是全局那一条，不是「每 IP 64 条 × 10 万 IP」的乘积：后者算得出上限，
	// 但那个上限本身就把节点买爆了。
	d.pathPressure.limit = maxTotalPathEntries
	go d.cleanupLoop()
	return d
}

// Check 检查请求是否为缓存绕过攻击。返回 true 表示应该封禁。
//
// whitelistParams 是该域名配置的白名单参数（业务合法使用的参数名），这些参数的变化
// 不计入攻击信号。例如某些站点的 ?token= 是用户认证凭证，每次都不同但完全正常。
func (d *CacheBusterDetector) Check(ip, fullURL string, whitelistParams []string) (blocked bool, reason string) {
	parsed, err := url.Parse(fullURL)
	if err != nil {
		return false, ""
	}

	// 没有 query string 的请求不会触发缓存绕过检测
	if parsed.RawQuery == "" {
		return false, ""
	}

	now := time.Now()
	d.mu.Lock()
	tracker, exists := d.trackers[ip]
	if !exists {
		// 表满时先采样回收最不活跃的 IP 腾位，而不是对这次请求放弃建档：后者等于
		// 检测器在攻击最凶的时候静默下线。仍腾不出空位（采到的都在封禁期内）才退回
		// 不检测，并把这次放弃计进 dropped。
		if len(d.trackers) >= maxTrackers &&
			!evictOneLocked(d.trackers, &d.trackerPressure, func(t *cacheBusterTracker) (time.Time, bool, bool) {
				t.mu.Lock()
				defer t.mu.Unlock()
				live := !t.blockedUntil.IsZero() && now.Before(t.blockedUntil)
				return t.lastSeen, !t.blockedUntil.IsZero() && !live, live
			}) {
			d.mu.Unlock()
			return false, ""
		}
		tracker = &cacheBusterTracker{
			pathVariants: make(map[string]*pathVariantStats),
			lastSeen:     now,
			lastCleanup:  now,
		}
		d.trackers[ip] = tracker
	}
	d.mu.Unlock()

	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	tracker.lastSeen = now

	// 检查是否在封禁期内
	if !tracker.blockedUntil.IsZero() && now.Before(tracker.blockedUntil) {
		return true, "cache-bypass attack detected (blocked)"
	}

	// 封禁已过期，重置状态
	if !tracker.blockedUntil.IsZero() && now.After(tracker.blockedUntil) {
		tracker.blockedUntil = time.Time{}
		tracker.violationCount = 0
		tracker.overflowCount = 0
		tracker.overflowWindowStart = time.Time{}
		d.pathEntries.Add(-int64(len(tracker.pathVariants)))
		tracker.pathVariants = make(map[string]*pathVariantStats)
	}

	// 规范化路径（去掉已知无害参数）
	normalizedPath, normalizedQuery := normalizeURL(parsed, whitelistParams)

	stats, exists := tracker.pathVariants[normalizedPath]
	if !exists {
		// 两条额度谁先撞线都按同一种方式降级：丢掉本 IP 最久未见的一条，再记新的。
		// 单 IP 那条是精度上限，全局那条是内存上限；两者都不能变成「攻击者刷爆额度就
		// 换到检测盲区」，所以腾位同时计入 overflowCount（判定条件3）。
		if len(tracker.pathVariants) >= maxPathsPerIP || int(d.pathEntries.Load()) >= maxTotalPathEntries {
			if len(tracker.pathVariants) == 0 {
				// 全局预算已满、而这个 IP 一条都还没占过：这次请求不统计，计进 dropped。
				// 不去挤别人已有的条目——正在被统计的 IP 更可能是真攻击源，宁可保住它。
				d.pathPressure.drops.Add(1)
				return false, ""
			}
			if now.Sub(tracker.overflowWindowStart) > detectionWindow {
				tracker.overflowWindowStart = now
				tracker.overflowCount = 0
			}
			tracker.overflowCount++
			d.evictStalePathLocked(tracker)
		}
		stats = &pathVariantStats{
			uniqueQueries: make(map[string]time.Time),
			windowStart:   now,
			lastSeen:      now,
		}
		tracker.pathVariants[normalizedPath] = stats
		d.pathEntries.Add(1)
	}

	// 滚动时间窗口：超过 detectionWindow 就重置统计
	if now.Sub(stats.windowStart) > detectionWindow {
		stats.uniqueQueries = make(map[string]time.Time)
		stats.requestCount = 0
		stats.windowStart = now
	}

	stats.requestCount++
	stats.lastSeen = now

	// 记录唯一 query（用 hash 避免存储完整字符串）
	queryHash := hashQuery(normalizedQuery)
	if _, seen := stats.uniqueQueries[queryHash]; !seen {
		stats.uniqueQueries[queryHash] = now
	}

	uniqueCount := len(stats.uniqueQueries)
	totalCount := stats.requestCount

	// 判定条件1：唯一 query 数超过阈值
	condition1 := uniqueCount > uniqueQueryThreshold

	// 判定条件2：请求多样性比例过高（几乎每次都换参数）
	diversity := float64(uniqueCount) / float64(totalCount)
	condition2 := diversity >= requestDiversityRatio && totalCount >= 5

	// 判定条件3：路径扇出刷爆额度。攻击者每个请求换一个路径，任何单条路径都攒不满
	// 前两个条件，但源站扛住的是 100% MISS。真实访客在 10 秒里换不出 84 个带参 URL。
	condition3 := tracker.overflowCount > uniqueQueryThreshold

	if condition1 || condition2 || condition3 {
		tracker.violationCount++
		tracker.blockedUntil = now.Add(blockDuration)
		if condition3 && !condition1 && !condition2 {
			return true, "cache-bypass attack: path fan-out exceeded the per-IP tracking budget"
		}
		return true, "cache-bypass attack: excessive unique query parameters on " + normalizedPath
	}

	// 定期清理该 tracker 下不活跃的 path 统计
	if now.Sub(tracker.lastCleanup) > trackerCleanupInterval {
		d.pathEntries.Add(-int64(tracker.cleanupPathsLocked(now)))
		tracker.lastCleanup = now
	}

	return false, ""
}

// normalizeURL 规范化 URL：提取 path，并过滤掉白名单参数后生成 query 字符串。
// 返回: (规范化的 path, 规范化的 query string)
func normalizeURL(u *url.URL, whitelistParams []string) (string, string) {
	path := u.Path
	if path == "" {
		path = "/"
	}

	whitelist := make(map[string]bool)
	for _, p := range whitelistParams {
		whitelist[p] = true
	}
	// 合并全局已知参数
	for p := range knownCacheParams {
		whitelist[p] = true
	}

	// 提取非白名单参数并排序（确保相同参数组合产生相同 hash）
	params := u.Query()
	var keys []string
	for k := range params {
		if !whitelist[k] {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	// 重建 query string（只保留非白名单参数的键，不保留值以减少存储）
	var parts []string
	for _, k := range keys {
		parts = append(parts, k+"="+strings.Join(params[k], ","))
	}

	return path, strings.Join(parts, "&")
}

// hashQuery 对 query string 做 SHA256 并取前 16 字节十六进制，作为 map key。
func hashQuery(query string) string {
	h := sha256.Sum256([]byte(query))
	return hex.EncodeToString(h[:16])
}

// cleanupPathsLocked 清理该 IP 下长期不活跃的 path 统计，返回删除条数（调用方须持有 t.mu，
// 以便同步维护全局条目计数）。
func (t *cacheBusterTracker) cleanupPathsLocked(now time.Time) int {
	removed := 0
	for path, stats := range t.pathVariants {
		if now.Sub(stats.lastSeen) > trackerIdleTimeout {
			delete(t.pathVariants, path)
			removed++
		}
	}
	return removed
}

// evictStalePathLocked 在该 IP 的路径变体额度用尽时丢掉最久未见的一条，
// 调用方须持有 tracker.mu。
//
// 这里全量扫描而不是采样：单 IP 最多 maxPathsPerIP 条，扫一遍比维护 LRU 链表便宜，
// 而且这条路径只在真的超出额度时才走。
func (d *CacheBusterDetector) evictStalePathLocked(tracker *cacheBusterTracker) {
	victim, oldest := "", time.Time{}
	for path, stats := range tracker.pathVariants {
		if victim == "" || stats.lastSeen.Before(oldest) {
			victim, oldest = path, stats.lastSeen
		}
	}
	if victim == "" {
		return
	}
	delete(tracker.pathVariants, victim)
	d.pathEntries.Add(-1)
	// 被丢掉的是"还在被统计的路径"，不是闲置清理：计入 dropped，
	// 让运维看得见"这个 IP 的路径多样性已经超过检测器愿意跟的量"。
	d.pathPressure.drops.Add(1)
}

// Capacity 返回检测器两张表的占用与退化读数：IP 追踪器表（上限 maxTrackers），以及跨所有
// IP 的路径变体总条目（上限 maxTotalPathEntries，不是每 IP 上限的乘积）。
func (d *CacheBusterDetector) Capacity() (trackers, paths CapacityPressure) {
	d.mu.RLock()
	nTrackers := len(d.trackers)
	d.mu.RUnlock()
	return d.trackerPressure.snapshot(nTrackers),
		d.pathPressure.snapshot(int(d.pathEntries.Load()))
}

// cleanupLoop 后台定期清理不活跃的 IP tracker。
func (d *CacheBusterDetector) cleanupLoop() {
	ticker := time.NewTicker(trackerCleanupInterval)
	defer ticker.Stop()

	for range ticker.C {
		d.mu.Lock()
		now := time.Now()
		for ip, tracker := range d.trackers {
			tracker.mu.Lock()
			// 清理条件：封禁已过期 + 所有 path 统计都已过期
			expired := tracker.blockedUntil.IsZero() || now.After(tracker.blockedUntil)
			allPathsIdle := true
			for _, stats := range tracker.pathVariants {
				if now.Sub(stats.lastSeen) <= trackerIdleTimeout {
					allPathsIdle = false
					break
				}
			}
			pathCount := int64(len(tracker.pathVariants))
			tracker.mu.Unlock()

			if expired && allPathsIdle {
				delete(d.trackers, ip)
				// 整个 tracker 连带它的路径统计一起消失，全局计数要跟着减，
				// 否则 pathEntries 只增不减，面板上的占用会一路漂到上限。
				d.pathEntries.Add(-pathCount)
			}
		}
		d.mu.Unlock()
	}
}
