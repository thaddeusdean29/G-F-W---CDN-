package waf

import (
	"net/http"
	"sync"
	"time"

	"cdn/internal/config"
)

// domainPolicySource 是获取域名 CC 策略所需的最小接口，由 *config.Store 实现。
type domainPolicySource interface {
	GetByDomain(domain string) (*config.Domain, error)
}

// CCDefense CC攻击防御引擎 - 基于请求频率的智能防护
type CCDefense struct {
	mu                  sync.RWMutex
	config              CCConfig
	requestTrackers     map[string]*requestTracker
	domainTrackers      map[string]*domainTracker      // key: 域名（Host），用于判断该域名处于第二/三层的哪个攻击态
	fingerprintTrackers map[string]*fingerprintTracker // key: 域名+"|"+JA4H，用于第三层单指纹限速
	waf                 *Engine                        // 用于自动封禁IP
	domainStore         domainPolicySource             // 用于读取每个域名的强检测策略（可为 nil，此时强检测功能关闭）
	broadcaster         AttackStateBroadcaster         // 攻击态跨节点广播器（可为 nil，此时不广播）
	stopCleanup         chan struct{}                  // cleanup 协程停止信号

	// 三张追踪表各自的容量压力。表打满后一律走"采样回收闲置条目腾位"，而不是静默停止
	// 统计——退化到什么程度由 GetStats 一并上报，因为"表满了"只有攻击进行中才会发生。
	ipPressure          pressureCounters // requestTrackers
	domainPressure      pressureCounters // domainTrackers
	fingerprintPressure pressureCounters // fingerprintTrackers
}

// domainAttackCooldown 是域名进入第三层攻击态后，即使当前秒请求数回落，仍维持攻击态的冷却时长，
// 避免攻击流量间歇性波动时频繁在"无感"与"指纹检测"之间切换。
const domainAttackCooldown = 3 * time.Minute

// defaultChallengeThreshold 是域名未配置 challenge_threshold 时使用的第二层（人机验证）判定线，
// 单位是域名整体每秒请求数。取值要显著低于 defaultStrictThreshold：第二层是"开始要凭证"，
// 第三层是"开始按指纹封"，两条线倒挂会让高强度检测先于人机验证生效。
const defaultChallengeThreshold = 100

// defaultChallengeHold 是域名 QPS 越过第二层判定线后，开盾态至少维持的时长：攻击停手后真人访客
// 凭此前拿到的凭证继续放行，未验证的客户端在这段窗口内仍被要求验证，QPS 回落后状态机自动降级。
// 域名可用 challenge_hold_seconds 覆盖（校验侧限定 10~900 秒）。
const defaultChallengeHold = 90 * time.Second

// defaultStrictThreshold 是域名未单独配置第三层阈值时使用的默认 QPS 阈值。
const defaultStrictThreshold = 300

// defaultFingerprintThreshold 是单个 JA4H 指纹未单独配置阈值时使用的默认每秒请求数阈值。
const defaultFingerprintThreshold = 20

// maxFingerprintTrackers 是 (域名, JA4H) 指纹追踪器的数量上限。JA4H 由攻击者的请求头
// 完全决定，随机化 header 顺序/数量即可造出无限种 key，若不设上限会被用来放大内存占用。
//
// 打满后采样回收闲置条目腾位（见 evictOneLocked），而不是停止建追踪器：后者等于
// 第三层指纹检测在攻击最凶的时候静默下线。
const maxFingerprintTrackers = 200000

// maxRequestTrackers 是按 IP 的请求追踪器数量上限，防止 IPv6 海量源地址轮换把内存打满。
// 达上限后采样回收闲置条目腾位，新 IP 照样有跨请求统计（不影响已生效的封禁）。
const maxRequestTrackers = 500000

// maxDomainTrackers 是域名追踪器的数量上限。只有已在面板配置的域名才会建 tracker
// （未配置的 Host 在读策略那一步就返回了），因此正常运营远达不到这个额度；留着它是
// 为了在域名表被异常灌满时兜住内存。达上限后同样采样回收闲置域名。
const maxDomainTrackers = 50000

// domainTracker 单个域名的整体请求速率追踪器，是自适应状态机的载体：
// requestsInSec 算出的 QPS 决定何时开盾，两个 until 时刻决定盾牌举多久。
type domainTracker struct {
	mu             sync.Mutex
	requestsInSec  int
	secWindowStart time.Time
	// challengeUntil 非零且未过期 = 第二层开盾态：无有效凭证的访客一律先发验证（401）。
	// 与 strictUntil 分开记录，是因为两者的维持时长不同——人机验证只要挑战冷却期一过就降级，
	// 指纹统计要撑满 3 分钟；合并成一个字段就只能取更长的那个，攻击停了真人还要多挨一会儿。
	challengeUntil time.Time
	strictUntil    time.Time // 非零且未过期时，表示该域名当前处于第三层攻击态
	// lastBroadcast 用来节流攻击态广播（见 broadcastMinInterval）。它不是拦截依据，
	// 因此参与"最久未活动"的回收判定，但不参与"是否仍在拦截态"的判定。
	lastBroadcast time.Time
}

// fingerprintTracker 单个（域名, JA4H指纹）组合的请求速率追踪器，用于第三层检测。
type fingerprintTracker struct {
	mu             sync.Mutex
	requestsInSec  int
	secWindowStart time.Time
	blockedUntil   time.Time // 非零且未过期时，表示该指纹当前被判定为可疑，直接拦截
}

// CCConfig CC防御配置
type CCConfig struct {
	Enabled           bool          `json:"enabled"`             // 是否启用CC防御
	RequestsPerSecond int           `json:"requests_per_second"` // 每秒请求数阈值（超过则触发防御）
	RequestsPerMinute int           `json:"requests_per_minute"` // 每分钟请求数阈值
	BurstSize         int           `json:"burst_size"`          // 突发流量容忍值
	BlockDuration     time.Duration `json:"block_duration"`      // 封禁时长（纳秒；前端按分钟发送时需 * 60e9）
	WhitelistIPs      []string      `json:"whitelist_ips"`       // 白名单IP（不限制）
	PathWhitelist     []string      `json:"path_whitelist"`      // 白名单路径（不限制）
}

// requestTracker 单个IP的请求追踪器
type requestTracker struct {
	mu             sync.Mutex
	ip             string
	lastRequest    time.Time
	requestsInSec  int       // 当前秒内请求数
	requestsInMin  int       // 当前分钟内请求数
	secWindowStart time.Time // 秒级窗口开始时间
	minWindowStart time.Time // 分钟级窗口开始时间
	violations     int       // 违规次数
	lastViolation  time.Time // 最后违规时间
	blocked        bool      // 是否已被封禁
	// downgraded 表示这个 IP 上一次拿到的是"过了主验证但缺环境证据"的弱档凭证。
	// 只用于统计面板：降权如果不被看见，运维无从判断这条路径是根本没生效，
	// 还是隐私模式/老内核用户正在大批量走进这一档。
	downgraded bool
	// 以下为封禁元数据：仅在触发封禁那一刻记录，用于前端展示"因何被封/封了哪个站点路径/何时封何时解"。
	blockedAt    time.Time // 拉黑时间
	blockedUntil time.Time // 预计解封时间（拉黑时间 + 封禁时长）
	blockRule    string    // 触发封禁的规则/攻击方式，如 cc-defense-rate-limit
	blockHost    string    // 被攻击的域名/网站
	blockPath    string    // 被攻击的请求路径/API
}

// markBlocked 在触发封禁的瞬间记录封禁元数据。调用方须已持有 t.mu。
func (t *requestTracker) markBlocked(rule, host, path string, dur time.Duration, now time.Time) {
	t.blocked = true
	t.blockedAt = now
	t.blockedUntil = now.Add(dur)
	t.blockRule = rule
	t.blockHost = host
	t.blockPath = path
}

// NewCCDefense 创建CC防御引擎。domainStore 用于读取按域名配置的强检测策略，传 nil 则强检测功能关闭
// （行为退化为原来的纯频率限制，不影响现有的每秒/每分钟阈值和自动封禁逻辑）。
func NewCCDefense(waf *Engine, domainStore domainPolicySource) *CCDefense {
	cc := &CCDefense{
		requestTrackers:     make(map[string]*requestTracker),
		domainTrackers:      make(map[string]*domainTracker),
		fingerprintTrackers: make(map[string]*fingerprintTracker),
		waf:                 waf,
		domainStore:         domainStore,
		stopCleanup:         make(chan struct{}),
		config: CCConfig{
			Enabled:           true,
			RequestsPerSecond: 20,  // 默认每秒20个请求
			RequestsPerMinute: 300, // 默认每分钟300个请求
			BurstSize:         5,   // 容忍突发5个请求
			BlockDuration:     10 * time.Minute,
			WhitelistIPs:      []string{},
			PathWhitelist:     []string{"/health", "/ping"},
		},
	}
	cc.ipPressure.limit = maxRequestTrackers
	cc.domainPressure.limit = maxDomainTrackers
	cc.fingerprintPressure.limit = maxFingerprintTrackers

	// 启动清理协程
	go cc.cleanup()

	return cc
}

// Check 检查请求是否触发CC防御
func (cc *CCDefense) Check(r *http.Request) *Result {
	// 一次性取配置快照。此前这里（以及下方取 cfg 处）是裸读 cc.config，而 UpdateConfig
	// 持写锁整体替换该结构体 —— CCConfig 含 slice 字段，赋值非原子，高并发下可读到撕裂值
	// （阈值读到一半、白名单 slice 头尾不一致）。压测正是最容易触发的场景。
	cfg := cc.GetConfig()
	if !cfg.Enabled {
		return &Result{Action: Allow}
	}

	ip := clientIP(r)

	// 检查IP白名单
	if cc.isWhitelisted(ip) {
		return &Result{Action: Allow}
	}

	// 检查路径白名单
	if cc.isPathWhitelisted(r.URL.Path) {
		return &Result{Action: Allow}
	}

	cc.mu.Lock()
	tracker, exists := cc.requestTrackers[ip]
	if !exists {
		now := time.Now()
		// 容量上限防内存放大（IPv6 海量源地址轮换）。达上限时腾一个空位出来，
		// 而不是发一个"用完即弃"的临时追踪器：临时追踪器每次请求都从 requestsInSec=0
		// 重新开始，永远涨不到阈值，等于表一满 CC 限速就对所有新 IP 静默失效
		// ——而"表被打满"恰恰是攻击进行中的标志，正是最不能失效的时刻。
		if len(cc.requestTrackers) >= maxRequestTrackers {
			cc.evictRequestTrackerLocked(now)
		}
		// 腾位失败（极端情况下所有采样条目都在封禁期内）时不入表。此时宁可放弃对这个
		// 新 IP 的跨请求统计，也不能挤掉正在生效的封禁记录。
		if len(cc.requestTrackers) < maxRequestTrackers {
			tracker = &requestTracker{
				ip:             ip,
				secWindowStart: now,
				minWindowStart: now,
			}
			cc.requestTrackers[ip] = tracker
		} else {
			tracker = &requestTracker{ip: ip, secWindowStart: now, minWindowStart: now}
		}
	}
	cc.mu.Unlock()

	// 域名级攻击等级检测：level 0=静默放行（无感），1=第二层人机验证开盾，2=第三层 JA4H 指纹检测。
	// 使用带广播的版本，确保攻击态变更时通知其他节点。
	level, policy := cc.domainAttackLevelWithBroadcast(r.Host)

	bindFP := ChallengeBindingFP(r.Header.Get("User-Agent"))
	bindScope := policy.ChallengeBindScope

	// 被动 / 开盾判定（Adaptive Threshold Mode）：默认只在域名真的进入攻击态后才要求人机验证，
	// 低频首访访客、合规爬虫与搜索引擎巡检因此在平时直接拿到 200 —— 面板上「人机验证」那行的
	// 文案本来就是"受到强攻击时才对访客做浏览器验证"，此前引擎执行的是"开启即始终验证"。
	//
	// challenge_always 是显式的例外开关：把行为退回"进门先验证一次"的强校验模式，给确有需要的
	// 站点留着（这个开关在此之前只写在前端，服务端从不读它）。
	//
	// 注意这里刻意不在被动态校验 Cookie：ChallengeCookieTier 每次都要算一遍 HMAC，
	// 反正没有凭证也要放行，省下这份开销正是高频低攻站点的收益所在。
	inChallengeMode := policy.ChallengeAlways || level >= 1
	hasValidCookie := false
	cookieTier := ChallengeTierFull
	if inChallengeMode {
		if tier, ok := ChallengeCookieTier(r.Host, ip, bindFP, r.Header.Get("Cookie"), bindScope); ok {
			hasValidCookie = true
			cookieTier = tier
		}

		// 双轨制限速：已验证用户使用宽松阈值，未验证用户使用严格阈值。
		// 弱凭证（过了主验证但环境证据采不到）走严格档：它不再被反复挑战，但也不领
		// verified_* 的配额——否则"两次 HTTP 往返换 30 分钟宽松额度"就是零成本的绕过。
		if hasValidCookie && cookieTier == ChallengeTierFull {
			// 已通过验证的真人用户：使用 verified_rps/verified_rpm（未设置时回退到 challenge_rps/rpm）
			if policy.VerifiedRPS > 0 {
				cfg.RequestsPerSecond = policy.VerifiedRPS
			} else if policy.ChallengeRPS > 0 {
				cfg.RequestsPerSecond = policy.ChallengeRPS
			}
			if policy.VerifiedRPM > 0 {
				cfg.RequestsPerMinute = policy.VerifiedRPM
			} else if policy.ChallengeRPM > 0 {
				cfg.RequestsPerMinute = policy.ChallengeRPM
			}
		} else {
			// 未验证的攻击者与弱档凭证共用严格阈值：后者过了主验证但拿不出环境证据，
			// 不能因为它"验证过了"就回到 verified_* 的宽松额度。
			if policy.ChallengeRPS > 0 {
				cfg.RequestsPerSecond = policy.ChallengeRPS
			}
			if policy.ChallengeRPM > 0 {
				cfg.RequestsPerMinute = policy.ChallengeRPM
			}
		}

		// 降权必须在面板上看得见：这条路径既可能是"根本没触发"（环境采集全绿），
		// 也可能是"隐私模式/老内核用户正在大批量掉档"（该改采集脚本了）。
		// 静默降权和静默放行一样，运维都没法判断。
		tracker.mu.Lock()
		tracker.downgraded = hasValidCookie && cookieTier == ChallengeTierWeak
		tracker.mu.Unlock()
	}

	needChallenge, challengeRule := "", ""
	if inChallengeMode && !hasValidCookie {
		needChallenge = "domain " + r.Host + " requires human verification"
		// 盾牌为什么举着，必须在规则名上就分得开：攻击态触发的是自适应开盾，
		// level==0 却仍在发验证只可能是 challenge_always 把门焊死了。两种情况的处置
		// 完全不同（前者看流量，后者看配置），日志合并成一条就看不出差别。
		challengeRule = "cc-defense-challenge"
		if level == 0 {
			challengeRule = "cc-defense-challenge-always"
		}
	}

	// 静默放行不等于无条件放行。畸形 JA4H 在这里拦，另外两类硬拦截例外不经过本函数：
	// 已知恶意扫描器 UA 与 IP 黑名单由 wafProxy.check 的第二步（waf.Engine.Check）负责，
	// 它在本函数返回 Allow 之后照常执行，所以被动态照样拦得住。
	//
	// 畸形 JA4H：X-Ja4h 只可能由边缘自己算出（site.conf.tmpl 已清空客户端同名头，
	// wafProxy.check 也是重建 Header 后才 Set），值不成形说明这个头绕过了那两道清理，
	// 即转发链被伪造或被改写。真实浏览器不可能产出这种值，因此不需要等攻击态。
	// 指纹不可用（空值）仍按"跳过第三层"处理，不能当成攻击信号——lua 模块未启用或
	// 旧版边缘二进制都是空值。
	ja4h := r.Header.Get("X-Ja4h")
	if ja4h != "" && !ValidJA4H(ja4h) {
		return &Result{
			Action:  Block,
			Rule:    "cc-defense-ja4h-malformed",
			Message: "client fingerprint " + ja4h + " is not a valid JA4H value on domain " + r.Host,
		}
	}

	if needChallenge != "" {
		// 关键：发挑战之前必须先把这次请求计入该 IP 的速率统计。
		//
		// 此前这里直接 return Challenge，导致 checkRate 永远不被调用 —— 不执行 JS 的
		// 压测/攻击客户端永远拿不到 cookie，于是每个请求都在这里返回，requestsInSec
		// 永不累加、违规计数恒为 0、该 IP 永远不会被封禁。表现就是"3 秒盾在触发，
		// 但攻击 IP 一个都封不掉"，攻击者可无限量领挑战页，每次都消耗一轮
		// auth_request 子请求 + 挑战页渲染的 CPU。
		//
		// 反复领挑战页而不通过验证本身就是最强的攻击信号：真人只会领一次，拿到
		// 30 分钟 cookie 后就走正常路径。所以超限即按攻击处理（封禁），而不是继续发盾。
		// inChallengeMode=true 意味着"单次超限就封禁"（不等累计 3 次违规）。
		if rate := tracker.checkRate(&cfg, cc.waf, r, inChallengeMode); rate.Action == Block {
			return rate
		}
		return &Result{Action: Challenge, Rule: challengeRule, Message: needChallenge}
	}

	// 第三层：JA4H 指纹统计检测。形态已在上面校验过，这里只在攻击态按指纹算速率；
	// 指纹不可用（空值）时直接跳过，不影响速率限制照常生效。
	if level >= 2 && ja4h != "" && cc.fingerprintOverThreshold(r.Host, ja4h, policy) {
		return &Result{
			Action:  Block,
			Rule:    "cc-defense-ja4h-fingerprint",
			Message: "suspicious client fingerprint " + ja4h + " exceeded rate threshold on domain " + r.Host,
		}
	}

	// 第四层：缓存绕过检测（CC 防护的关键补丁）
	// 攻击者通过随机 query 参数打穿 CDN 缓存，让每个请求都 cache MISS 直达源站。
	// 即使通过了挑战页、在速率限制之内，大量唯一 URL 仍会让源站扛不住。
	// 从域名配置中获取白名单参数（业务合法使用的参数名）
	var whitelistParams []string
	if policy.CacheBusting != nil && len(policy.CacheBusting.WhitelistParams) > 0 {
		whitelistParams = policy.CacheBusting.WhitelistParams
	}
	if blocked, reason := cc.waf.cacheBuster.Check(ip, r.URL.String(), whitelistParams); blocked {
		// 缓存绕过检测命中，立即封禁该 IP
		cc.waf.BlockIP(ip, cfg.BlockDuration)
		return &Result{
			Action:  Block,
			Rule:    "cc-defense-cache-bypass",
			Message: reason,
		}
	}

	// 检查频率限制。inChallengeMode 表示该域名当前处于"需要人机验证"状态
	// （challenge_always 开启，或 QPS 触发了攻击态）：此时同一 IP 单次超限就直接封禁，
	// 不再走默认状态下"累计违规 3 次才封禁"的宽容机制。
	//
	// 弱凭证不套用"单次超限即封禁"：这一档里混着隐私模式、老内核、缓存了旧挑战页的真实用户，
	// 他们的 env 采集本来就会失败。对他们降配额但不秒杀，否则降权就等于把另一批真人踢出站外。
	strictBan := inChallengeMode && cookieTier != ChallengeTierWeak
	return tracker.checkRate(&cfg, cc.waf, r, strictBan)
}

// evictTrackerSample 是达容量上限时为腾空位而采样考察的条目数。
// Go 的 map 迭代顺序随机，因此采样即随机采样，无需维护 LRU 链表（那需要额外的
// 双向链表 + 每次请求都在写锁下移动节点，热路径代价远高于偶发的一次采样）。
const evictTrackerSample = 64

// evictOneLocked 在追踪表满时腾出一个空位，返回是否腾到了。调用方须已持有该表的写锁。
//
// 择优顺序按"代价从小到大"：先删"拦截态已到期且最久未活动"的条目（它已不再承担拦截
// 职责，本来也会被清理协程删掉）；采样里没有可删的到期条目时，退而删采样中最久未活动
// 的非拦截条目。仍在拦截期内的条目绝不删——它的 blocked / strictUntil / blockedUntil
// 就是拦截依据，删掉等于当场给攻击 IP、攻击态域名或可疑指纹放行。
//
// 三张表共用这段逻辑，靠 classify 把各自的字段折成三个信号：last 是最近一次活动时刻
// （用来挑最久未活动者），dead 表示"曾进入拦截态且现已到期"，live 表示"当前仍在拦截态"。
//
// 一个空位都腾不出来时返回 false，调用方自行决定退化方式（放弃建追踪器 / 用一次性
// 追踪器），并计进 drops——静默降级和静默放行一样，运维必须看得见。
func evictOneLocked[T any](
	m map[string]T,
	pressure *pressureCounters,
	classify func(T) (last time.Time, dead, live bool),
) bool {
	var victim string
	var victimAt time.Time
	var victimDead bool
	checked := 0

	for key, v := range m {
		last, dead, live := classify(v)
		if !live {
			better := victim == "" ||
				(dead && !victimDead) ||
				(dead == victimDead && last.Before(victimAt))
			if better {
				victim, victimAt, victimDead = key, last, dead
			}
		}
		if checked++; checked >= evictTrackerSample {
			break
		}
	}
	if victim == "" {
		pressure.drops.Add(1)
		return false
	}
	// 两条路删的都是不承担拦截职责的条目，一律记回收；提前解除拦截（early_unbanned）
	// 在这张表上永远为 0——这正是它和封禁表的区别：追踪器丢了下次请求就能重建，
	// 封禁丢了却是一次真实的放行。
	pressure.reclaims.Add(1)
	delete(m, victim)
	return true
}

// evictRequestTrackerLocked 是按 IP 追踪表对通用腾位逻辑的封装。调用方须持有 cc.mu 写锁。
func (cc *CCDefense) evictRequestTrackerLocked(now time.Time) bool {
	return evictOneLocked(cc.requestTrackers, &cc.ipPressure, func(t *requestTracker) (time.Time, bool, bool) {
		t.mu.Lock()
		defer t.mu.Unlock()
		// blockedUntil 为零值时按"无限期封禁"处理，与 cleanup 的判定保持一致。
		live := t.blocked && (t.blockedUntil.IsZero() || now.Before(t.blockedUntil))
		return t.lastRequest, t.blocked && !live, live
	})
}

// domainTrackerFor 取（必要时创建）指定域名的自适应攻击态追踪器，并一并返回当前广播器。
// tracker 返回 nil 表示域名表已满且一个空位都腾不出来。
//
// 先走读锁：自适应模式把域名 QPS 统计从"开了第三层的域名"扩到"所有开了强检测的域名"，
// 也就是每个请求都要过这里。若沿用每次拿写锁的写法，CC 泛洪时所有域名、所有核都会串行化
// 在同一张 map 的写锁上——而泛洪恰恰是最不能串行化的时刻。
//
// 建好之后 tracker 的指针不再更换，所以读锁取到的指针可以长期用：条目随后被 cleanup 或
// 腾位删除，旧指针依旧有效（只是下一次请求会另建一个新条目，最坏情况是这一秒的计数重开）。
func (cc *CCDefense) domainTrackerFor(host string) (*domainTracker, AttackStateBroadcaster) {
	now := time.Now()
	cc.mu.RLock()
	dt, broadcaster := cc.domainTrackers[host], cc.broadcaster
	cc.mu.RUnlock()
	if dt != nil {
		return dt, broadcaster
	}

	cc.mu.Lock()
	defer cc.mu.Unlock()
	// 等写锁期间可能已有别的请求建好了，domainTrackerLocked 内部会再查一次。
	return cc.domainTrackerLocked(host, now), cc.broadcaster
}

// domainTrackerLocked 取（必要时创建）指定域名的攻击态追踪器，返回 nil 表示域名表已满
// 且一个空位都腾不出来。调用方须已持有 cc.mu 写锁。
//
// 打满时先采样回收闲置域名，而不是拒建：能走到这里的域名都是面板里配置过的
// （未配置的 Host 在读策略那一步就返回了），拒建等于让真实站点的自适应开盾下线。
// 仍在开盾期或第三层冷却期内的域名绝不回收——那是正在生效的拦截。
func (cc *CCDefense) domainTrackerLocked(host string, now time.Time) *domainTracker {
	if dt, exists := cc.domainTrackers[host]; exists {
		return dt
	}
	if len(cc.domainTrackers) >= maxDomainTrackers &&
		!evictOneLocked(cc.domainTrackers, &cc.domainPressure, func(d *domainTracker) (time.Time, bool, bool) {
			d.mu.Lock()
			defer d.mu.Unlock()
			live := now.Before(d.challengeUntil) || now.Before(d.strictUntil)
			armed := !d.challengeUntil.IsZero() || !d.strictUntil.IsZero()
			return d.secWindowStart, armed && !live, live
		}) {
		return nil
	}
	dt := &domainTracker{secWindowStart: now}
	cc.domainTrackers[host] = dt
	return dt
}

// fingerprintOverThreshold 判断给定域名下的某个 JA4H 指纹当前请求速率是否超过阈值。
// 超过一次后会维持 domainAttackCooldown 冷却期直接判定为超限，避免瞬时窗口回落后立刻放行。
func (cc *CCDefense) fingerprintOverThreshold(host, ja4h string, policy config.CCPolicy) bool {
	threshold := policy.FingerprintThreshold
	if threshold <= 0 {
		threshold = defaultFingerprintThreshold
	}

	key := host + "|" + ja4h
	now := time.Now()
	cc.mu.Lock()
	ft, exists := cc.fingerprintTrackers[key]
	if !exists {
		// 容量上限防内存放大：key 含 JA4H，而 JA4H 完全由攻击者的请求头决定
		// （随机化 header 顺序/数量即可造出无限种指纹），cleanup 每 5 分钟才跑一次，
		// 期间可无限堆积。打满时先采样回收闲置指纹腾位，只对"每次都换指纹"的攻击者
		// 放弃单指纹限速（本就无从统计），但已判定可疑的指纹绝不因为腾位而被放行；
		// 这类流量仍受第一层按 IP 限速与域名整体阈值约束。
		if len(cc.fingerprintTrackers) >= maxFingerprintTrackers &&
			!evictOneLocked(cc.fingerprintTrackers, &cc.fingerprintPressure, func(f *fingerprintTracker) (time.Time, bool, bool) {
				f.mu.Lock()
				defer f.mu.Unlock()
				live := now.Before(f.blockedUntil)
				return f.secWindowStart, !f.blockedUntil.IsZero() && !live, live
			}) {
			cc.mu.Unlock()
			return false
		}
		ft = &fingerprintTracker{secWindowStart: now}
		cc.fingerprintTrackers[key] = ft
	}
	cc.mu.Unlock()

	ft.mu.Lock()
	defer ft.mu.Unlock()

	if now.Before(ft.blockedUntil) {
		return true
	}

	if now.Sub(ft.secWindowStart) >= time.Second {
		ft.requestsInSec = 0
		ft.secWindowStart = now
	}
	ft.requestsInSec++

	if ft.requestsInSec > threshold {
		ft.blockedUntil = now.Add(domainAttackCooldown)
		return true
	}
	return false
}

// checkRate 检查单个IP的请求频率。underAttack 表示该域名当前已处于强检测/高强度攻击态
// （domainAttackLevel >= 1）：此时单次超限就直接封禁该 IP，不再走默认状态下"累计违规
// 3 次才封禁"的宽容机制，因为域名整体流量已经被判定为异常，没必要再给宽容期。
func (t *requestTracker) checkRate(config *CCConfig, waf *Engine, r *http.Request, underAttack bool) *Result {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	t.lastRequest = now
	host := r.Host
	path := r.URL.Path

	// 如果仍在封禁期内，直接拒绝。封禁是"临时"的：到达 blockedUntil 后自动解封，
	// 与 waf.Engine 侧按到期时间自动失效的封禁表保持一致。若只看 blocked 布尔标志，
	// 该 IP 会被 CC 层永久拦死（Engine 那边早已到期放行），且 cleanup 因 !blocked
	// 条件永不回收其 tracker，等于给正常用户留下永久黑名单。
	if t.blocked {
		if t.blockedUntil.IsZero() || now.Before(t.blockedUntil) {
			return &Result{
				Action:  Block,
				Rule:    "cc-defense-blocked",
				Message: "IP " + t.ip + " is temporarily blocked due to excessive requests",
			}
		}
		// 封禁已到期：解封并清零违规计数，让该 IP 重新按正常阈值参与限速。
		t.blocked = false
		t.violations = 0
		t.requestsInSec = 0
		t.requestsInMin = 0
		t.secWindowStart = now
		t.minWindowStart = now
	}

	// 更新秒级统计窗口
	if now.Sub(t.secWindowStart) >= time.Second {
		t.requestsInSec = 0
		t.secWindowStart = now
	}
	t.requestsInSec++

	// 更新分钟级统计窗口
	if now.Sub(t.minWindowStart) >= time.Minute {
		t.requestsInMin = 0
		t.minWindowStart = now
	}
	t.requestsInMin++

	// 检查每秒请求数限制
	if t.requestsInSec > config.RequestsPerSecond+config.BurstSize {
		t.violations++
		t.lastViolation = now

		// 已处于攻击态，或累计违规达到3次，自动封禁
		if underAttack || t.violations >= 3 {
			t.markBlocked("cc-defense-rate-limit(per-second)", host, path, config.BlockDuration, now)
			waf.BlockIP(t.ip, config.BlockDuration)
			return &Result{
				Action:  Block,
				Rule:    "cc-defense-rate-limit",
				Message: "IP " + t.ip + " blocked: exceeded rate limit (per second)",
			}
		}

		return &Result{
			Action:  Block,
			Rule:    "cc-defense-rate-limit",
			Message: "Request rate too high (per second)",
		}
	}

	// 检查每分钟请求数限制
	if t.requestsInMin > config.RequestsPerMinute {
		t.violations++
		t.lastViolation = now

		// 已处于攻击态，或累计违规达到3次，自动封禁
		if underAttack || t.violations >= 3 {
			t.markBlocked("cc-defense-rate-limit(per-minute)", host, path, config.BlockDuration, now)
			waf.BlockIP(t.ip, config.BlockDuration)
			return &Result{
				Action:  Block,
				Rule:    "cc-defense-rate-limit",
				Message: "IP " + t.ip + " blocked: exceeded rate limit (per minute)",
			}
		}

		return &Result{
			Action:  Block,
			Rule:    "cc-defense-rate-limit",
			Message: "Request rate too high (per minute)",
		}
	}

	// 如果有违规记录但最近5分钟内无违规，重置违规计数
	if t.violations > 0 && now.Sub(t.lastViolation) > 5*time.Minute {
		t.violations = 0
	}

	return &Result{Action: Allow}
}

// isWhitelisted 检查IP是否在白名单中
func (cc *CCDefense) isWhitelisted(ip string) bool {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	for _, whiteIP := range cc.config.WhitelistIPs {
		if whiteIP == ip {
			return true
		}
	}
	return false
}

// isPathWhitelisted 检查路径是否在白名单中
func (cc *CCDefense) isPathWhitelisted(path string) bool {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	for _, whitePath := range cc.config.PathWhitelist {
		if whitePath == path {
			return true
		}
	}
	return false
}

// UpdateConfig 更新CC防御配置
func (cc *CCDefense) UpdateConfig(config CCConfig) {
	cc.mu.Lock()
	cc.config = config
	cc.mu.Unlock()
}

// GetConfig 获取当前配置
func (cc *CCDefense) GetConfig() CCConfig {
	cc.mu.RLock()
	defer cc.mu.RUnlock()
	return cc.config
}

// GetStats 获取CC防御统计信息
func (cc *CCDefense) GetStats() CCStats {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	stats := CCStats{
		TotalTracked: len(cc.requestTrackers),
	}
	busterTrackers, busterPaths := cc.waf.cacheBuster.Capacity()
	stats.Capacity = CCPressure{
		IPs:          cc.ipPressure.snapshot(len(cc.requestTrackers)),
		Domains:      cc.domainPressure.snapshot(len(cc.domainTrackers)),
		Fingerprints: cc.fingerprintPressure.snapshot(len(cc.fingerprintTrackers)),
		CacheBuster:  busterTrackers,
		CachePaths:   busterPaths,
	}

	now := time.Now()
	for _, tracker := range cc.requestTrackers {
		tracker.mu.Lock()
		if tracker.blocked {
			stats.BlockedIPs++
		}
		if tracker.violations > 0 {
			stats.ViolatingIPs++
		}
		// 降权只统计近一分钟仍在发请求的 IP：档位标记是随请求写入的，
		// 已经离开的访客不该继续占在这个指标里。
		if active := now.Sub(tracker.lastRequest) < time.Minute; active {
			stats.ActiveIPs++
			if tracker.downgraded {
				stats.DowngradedIPs++
			}
		}
		tracker.mu.Unlock()
	}

	// 自适应模式下盾牌平时是收起来的，"没有验证流量"既可能是真没攻击，也可能是判定线
	// 太高或域名根本没开强检测。把当前处于开盾态的域名数一并报出来，运维才分得清这两者。
	for _, dt := range cc.domainTrackers {
		dt.mu.Lock()
		if now.Before(dt.challengeUntil) {
			stats.DomainsInChallenge++
		}
		if now.Before(dt.strictUntil) {
			stats.DomainsInStrict++
		}
		dt.mu.Unlock()
	}

	return stats
}

// CCStats CC防御统计信息
type CCStats struct {
	TotalTracked int `json:"total_tracked"` // 总追踪IP数
	ActiveIPs    int `json:"active_ips"`    // 活跃IP数(1分钟内有请求)
	ViolatingIPs int `json:"violating_ips"` // 违规IP数
	BlockedIPs   int `json:"blocked_ips"`   // 已封禁IP数
	// DowngradedIPs 是近一分钟内凭"弱档挑战凭证"被放行的 IP 数：过了主验证但环境证据
	// 采不到（隐私模式、老内核、缓存了旧挑战页）。它们走严格配额、不享受秒杀豁免。
	DowngradedIPs int `json:"downgraded_ips"`

	// DomainsInChallenge / DomainsInStrict 是当前处于第二层开盾态 / 第三层攻击态的域名数。
	// 自适应模式下这两个数平时应当是 0，非 0 就说明真有域名越过了 QPS 判定线；用它们区分
	// "没攻击所以没验证"和"检测没生效"，比看验证流量条数可靠。
	DomainsInChallenge int `json:"domains_in_challenge"`
	DomainsInStrict    int `json:"domains_in_strict"`

	// Capacity 是三张追踪表（按 IP / 按域名 / 按 JA4H 指纹）的容量压力。表打满后走的
	// 是"采样回收闲置条目"而不是"停止统计"，dropped 不为 0 说明连空位都腾不出来、
	// 该 IP/域名/指纹已经不再被跨请求追踪了——这正是攻击最凶时会看到的现象。
	Capacity CCPressure `json:"capacity"`
}

// CCPressure 汇总 CC 各层追踪表的占用与退化计数。
//
// CacheBuster 是缓存绕过检测器的 IP 追踪器表，CachePaths 是它跨所有 IP 的路径变体
// 总条目（上限 = 追踪器上限 × 单 IP 额度）——路径扇出刷爆单 IP 额度时计进后者的 dropped。
type CCPressure struct {
	IPs          CapacityPressure `json:"ips"`
	Domains      CapacityPressure `json:"domains"`
	Fingerprints CapacityPressure `json:"fingerprints"`
	CacheBuster  CapacityPressure `json:"cache_buster"`
	CachePaths   CapacityPressure `json:"cache_paths"`
}

// Add 跨节点汇总：每张表各自累加。
func (p *CCPressure) Add(other CCPressure) {
	p.IPs.Add(other.IPs)
	p.Domains.Add(other.Domains)
	p.Fingerprints.Add(other.Fingerprints)
	p.CacheBuster.Add(other.CacheBuster)
	p.CachePaths.Add(other.CachePaths)
}

// UnblockIP 解除IP封禁
func (cc *CCDefense) UnblockIP(ip string) {
	cc.mu.Lock()
	if tracker, exists := cc.requestTrackers[ip]; exists {
		tracker.mu.Lock()
		tracker.blocked = false
		tracker.violations = 0
		tracker.mu.Unlock()
	}
	cc.mu.Unlock()

	// 同时从WAF封禁列表中移除
	cc.waf.UnblockIP(ip)
}

// ResetIPStats 重置IP的统计数据
func (cc *CCDefense) ResetIPStats(ip string) {
	cc.mu.Lock()
	defer cc.mu.Unlock()

	if tracker, exists := cc.requestTrackers[ip]; exists {
		tracker.mu.Lock()
		tracker.requestsInSec = 0
		tracker.requestsInMin = 0
		tracker.violations = 0
		tracker.blocked = false
		tracker.mu.Unlock()
	}
}

// cleanup 定期清理过期的追踪器
func (cc *CCDefense) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			cc.mu.Lock()
			now := time.Now()
			for ip, tracker := range cc.requestTrackers {
				tracker.mu.Lock()
				// 删除 30 分钟内无活动的追踪器。仍处于封禁期内的保留（其 blocked 状态是
				// 拦截依据）；封禁已到期的按普通空闲追踪器处理，否则被封 IP 的 tracker
				// 会永久驻留内存，攻击波过后越积越多。
				stillBlocked := tracker.blocked && (tracker.blockedUntil.IsZero() || now.Before(tracker.blockedUntil))
				if now.Sub(tracker.lastRequest) > 30*time.Minute && !stillBlocked {
					delete(cc.requestTrackers, ip)
				}
				tracker.mu.Unlock()
			}
			for host, dt := range cc.domainTrackers {
				dt.mu.Lock()
				// 删除已脱离攻击态（第二层开盾与第三层冷却都到期）且 5 分钟内无新窗口活动
				// 的域名追踪器。只盯 strictUntil 会把还在举盾的域名回收掉——那等于在攻击
				// 进行中把状态机的记忆抹掉，下一秒 QPS 又从 0 开始数。
				if now.After(dt.challengeUntil) && now.After(dt.strictUntil) &&
					now.Sub(dt.secWindowStart) > 5*time.Minute {
					delete(cc.domainTrackers, host)
				}
				dt.mu.Unlock()
			}
			for key, ft := range cc.fingerprintTrackers {
				ft.mu.Lock()
				// 删除已脱离拦截态且5分钟内无新窗口活动的指纹追踪器
				if now.After(ft.blockedUntil) && now.Sub(ft.secWindowStart) > 5*time.Minute {
					delete(cc.fingerprintTrackers, key)
				}
				ft.mu.Unlock()
			}
			cc.mu.Unlock()
		case <-cc.stopCleanup:
			return
		}
	}
}

// Stop 停止 CC 防御引擎的后台清理协程。
func (cc *CCDefense) Stop() {
	close(cc.stopCleanup)
}

// GetTrackedIPs 获取所有被追踪的IP及其状态
func (cc *CCDefense) GetTrackedIPs() []IPStatus {
	cc.mu.RLock()
	defer cc.mu.RUnlock()

	result := make([]IPStatus, 0, len(cc.requestTrackers))
	for ip, tracker := range cc.requestTrackers {
		tracker.mu.Lock()
		result = append(result, IPStatus{
			IP:                ip,
			RequestsPerSecond: tracker.requestsInSec,
			RequestsPerMinute: tracker.requestsInMin,
			Violations:        tracker.violations,
			Blocked:           tracker.blocked,
			LastRequest:       tracker.lastRequest,
			BlockedAt:         tracker.blockedAt,
			BlockedUntil:      tracker.blockedUntil,
			BlockRule:         tracker.blockRule,
			BlockHost:         tracker.blockHost,
			BlockPath:         tracker.blockPath,
			Downgraded:        tracker.downgraded,
		})
		tracker.mu.Unlock()
	}

	return result
}

// IPStatus IP状态信息
type IPStatus struct {
	IP                string    `json:"ip"`
	RequestsPerSecond int       `json:"requests_per_second"`
	RequestsPerMinute int       `json:"requests_per_minute"`
	Violations        int       `json:"violations"`
	Blocked           bool      `json:"blocked"`
	LastRequest       time.Time `json:"last_request"`
	// 封禁元数据：仅在 Blocked=true 时有意义，用于前端展示封禁明细。
	BlockedAt    time.Time `json:"blocked_at"`    // 拉黑时间
	BlockedUntil time.Time `json:"blocked_until"` // 预计解封时间
	BlockRule    string    `json:"block_rule"`    // 触发封禁的规则/攻击方式
	BlockHost    string    `json:"block_host"`    // 被攻击的域名
	BlockPath    string    `json:"block_path"`    // 被攻击的请求路径
	// Downgraded 表示该 IP 最近一次请求用的是降权凭证（过了主验证但环境证据缺失）。
	// 它不进封禁表、也不代表异常，只是运维判断"环境采集是否在真实用户身上失效"的线索。
	Downgraded bool `json:"downgraded"`
	// 归属地：由主控在聚合返回时填充，边缘节点不参与查询。
	Country  string `json:"country,omitempty"`  // ISO 国家码，如 CN / US
	Location string `json:"location,omitempty"` // 可读归属地，如 "China / Beijing"
}
