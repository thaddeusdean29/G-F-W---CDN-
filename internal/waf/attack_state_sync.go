package waf

import (
	"log"
	"time"

	"cdn/internal/config"
)

// AttackStateBroadcaster 域名攻击态跨节点同步广播器。
// 当某个域名在本节点进入第二层（人机验证开盾）或第三层（JA4H 指纹统计）攻击态时，
// 通过该接口向其他节点广播攻击态，确保全网同步响应。
type AttackStateBroadcaster interface {
	// BroadcastDomainAttackState 向其他节点广播域名的攻击态到期时刻。
	// NodeID 由实现方填写——只有它知道自己是谁；这里传进来的消息该字段为空。
	BroadcastDomainAttackState(msg AttackStateMessage)
}

// AttackStateMessage 攻击态同步消息。两个到期时刻各自独立，零值表示该层不在攻击态。
//
// challenge_until 是新加字段：老版本边缘解不出来会直接忽略，只按 strict_until 同步，
// 于是滚动升级期间跨节点同步退化为"只同步第三层"。本节点自己的开盾判定不依赖对端
// （它读的是本地 QPS 计数），所以退化只是别的节点少举一会儿盾，不会放行攻击流量。
type AttackStateMessage struct {
	Domain         string    `json:"domain"`
	ChallengeUntil time.Time `json:"challenge_until,omitempty"` // 第二层开盾到期时刻
	StrictUntil    time.Time `json:"strict_until"`              // 第三层攻击态持续到的时刻（零值表示已退出攻击态）
	NodeID         string    `json:"node_id"`                   // 发起节点ID（用于日志追踪，避免循环广播）
}

// broadcastMinInterval 是同一域名两次攻击态广播之间的最小间隔。自适应开盾的判定线
// （默认 100 QPS）远低于第三层的 300 QPS，正常业务的流量抖动就可能反复穿越阈值；
// 若每次"刚进入"都发一轮全网 fan-out，主控的推送带宽就成了被攻击者用流量精确控制的
// 第二个打击面。到期时刻仍在本地逐请求延长，节流只是不发网，不会提前降级。
const broadcastMinInterval = 30 * time.Second

// challengeHold 返回该域名开盾态的最短维持时长。面板侧已把非零值限定在 10~900 秒，
// 这里只兜"未配置"与"绕过面板直接写库"两种情况，取默认值而不是夹紧。
func challengeHold(policy config.CCPolicy) time.Duration {
	if policy.ChallengeHoldSeconds <= 0 {
		return defaultChallengeHold
	}
	return time.Duration(policy.ChallengeHoldSeconds) * time.Second
}

// SetBroadcaster 为 CC 防御引擎设置攻击态广播器（由主控或边缘节点在初始化时注入）。
func (cc *CCDefense) SetBroadcaster(broadcaster AttackStateBroadcaster) {
	cc.mu.Lock()
	cc.broadcaster = broadcaster
	cc.mu.Unlock()
}

// domainAttackLevelWithBroadcast 判断指定域名当前所处的攻击等级（自适应阈值状态机），
// 并在域名进入攻击态时节流地向其他节点广播：
//
//	0 - 静默放行：未开强检测，或开了但 QPS 未越过第二层判定线。无凭证的首访请求照常 200。
//	1 - 第二层开盾：无有效凭证的访客一律先发人机验证（401）。
//	2 - 第三层：在第二层之上追加 JA4H 指纹统计检测。
//
// 域名未配置策略、未开强检测、或未超过阈值时返回 0。
func (cc *CCDefense) domainAttackLevelWithBroadcast(host string) (int, config.CCPolicy) {
	if host == "" || cc.domainStore == nil {
		return 0, config.CCPolicy{}
	}
	d, err := cc.domainStore.GetByDomain(host)
	if err != nil || d == nil {
		return 0, config.CCPolicy{}
	}
	policy := d.CCPolicy

	// 没开强检测的域名既不统计也不开盾：它不发人机验证，也就没有"为一次用不上的计数
	// 在热路径上多挨一次锁"的理由。第三层依赖第二层的凭证收紧，单独开启没有意义。
	if !policy.ChallengeEnabled {
		return 0, policy
	}

	challengeThreshold := policy.ChallengeThreshold
	if challengeThreshold <= 0 {
		challengeThreshold = defaultChallengeThreshold
	}
	strictThreshold := policy.StrictThreshold
	if strictThreshold <= 0 {
		strictThreshold = defaultStrictThreshold
	}
	// 分层判定线必须单调：第三层是第二层的加强档，若把 challenge_threshold 配得比
	// strict_threshold 还高，就会出现"先按指纹封、后开始要凭证"的倒挂——指纹统计在还没
	// 有凭证门槛的站点上直接产出 403，面板看到的执行顺序与配置意图正好相反。
	if strictThreshold < challengeThreshold {
		strictThreshold = challengeThreshold
	}
	hold := challengeHold(policy)

	dt, broadcaster := cc.domainTrackerFor(host)
	if dt == nil {
		// 域名表打满且腾不出空位：这个域名本轮不做攻击态判定，dropped 计数已记上。
		// 第一层按 IP 的速率限制不依赖这张表，照常生效。
		return 0, policy
	}

	now := time.Now()
	dt.mu.Lock()
	if now.Sub(dt.secWindowStart) >= time.Second {
		dt.requestsInSec = 0
		dt.secWindowStart = now
	}
	dt.requestsInSec++

	var shouldBroadcast bool
	if dt.requestsInSec > challengeThreshold {
		// wasIdle 按"是否已过期"判定，而不是"是否为零值"：持续攻击中到期时刻被逐请求推后，
		// 只有真的掉出开盾态后再次越过判定线，才算一次新的状态切换。
		wasIdle := !now.Before(dt.challengeUntil)
		if until := now.Add(hold); until.After(dt.challengeUntil) {
			dt.challengeUntil = until
		}
		if wasIdle && now.Sub(dt.lastBroadcast) >= broadcastMinInterval {
			shouldBroadcast = true
			dt.lastBroadcast = now
		}
	}
	// 第三层维持原有语义：只在域名显式开启指纹检测时才判定，撑满 domainAttackCooldown。
	if policy.StrictEnabled && dt.requestsInSec > strictThreshold {
		wasIdle := !now.Before(dt.strictUntil)
		if until := now.Add(domainAttackCooldown); until.After(dt.strictUntil) {
			dt.strictUntil = until
			liftChallengeUntil(dt, dt.strictUntil)
		}
		if wasIdle && now.Sub(dt.lastBroadcast) >= broadcastMinInterval {
			shouldBroadcast = true
			dt.lastBroadcast = now
		}
	}

	level := 0
	switch {
	case now.Before(dt.strictUntil):
		level = 2
	case now.Before(dt.challengeUntil):
		level = 1
	}
	msg := AttackStateMessage{Domain: host, ChallengeUntil: dt.challengeUntil, StrictUntil: dt.strictUntil}
	dt.mu.Unlock()

	// 解锁后再广播：持锁调用外部接口可能长时间阻塞，那会把所有核都卡在这一个域名的
	// 攻击态判定上——而广播恰恰发生在流量已经异常的时刻。
	if shouldBroadcast && broadcaster != nil {
		go func(m AttackStateMessage) {
			broadcaster.BroadcastDomainAttackState(m)
			log.Printf("[CC] broadcast domain %s attack state: challengeUntil=%v strictUntil=%v",
				m.Domain, m.ChallengeUntil, m.StrictUntil)
		}(msg)
	}

	return level, policy
}

// ApplyAttackState 应用从其他节点收到的攻击态广播（由边缘节点的 /edge/cc/attack-state
// 端点调用），更新本地域名追踪器的到期时刻，使本节点同步进入对应攻击态。
func (cc *CCDefense) ApplyAttackState(msg AttackStateMessage) {
	if msg.Domain == "" {
		return
	}

	dt, _ := cc.domainTrackerFor(msg.Domain)
	if dt == nil {
		// 域名表已满且腾不出空位：丢弃这条远端攻击态，本地已有封禁/攻击态不因它让位。
		return
	}

	now := time.Now()
	dt.mu.Lock()
	defer dt.mu.Unlock()

	// 只接受"晚于现在、且晚于本地现有结论"的时刻：过期的消息不能把已开盾的域名提前降级，
	// 也不能缩短正在生效的第三层拦截。对端时钟明显超前时本节点会多撑一段，不会永久卡住
	// ——面板的解封操作与 cleanup 都能回收。
	if msg.ChallengeUntil.After(now) && msg.ChallengeUntil.After(dt.challengeUntil) {
		dt.challengeUntil = msg.ChallengeUntil
	}
	if msg.StrictUntil.After(now) && msg.StrictUntil.After(dt.strictUntil) {
		dt.strictUntil = msg.StrictUntil
		// 对端只说"这域名进了第三层"（老版本消息里压根没有 challenge_until）时，本节点
		// 也要把凭证门槛抬到同样长的窗口，见 liftChallengeUntil。
		liftChallengeUntil(dt, msg.StrictUntil)
		log.Printf("[CC] applied domain %s attack state from node %s: strictUntil=%v", msg.Domain, msg.NodeID, msg.StrictUntil)
	}
}

// liftChallengeUntil 把第二层开盾的到期时刻抬到至少 keepAt。调用方须持有 dt.mu 写锁。
//
// 第三层是第二层的加强档，"按指纹拉黑"必然建立在"无凭证一律先发验证"之上。判定逻辑里
// level==2 已经隐含了举证（inChallengeMode = level>=1），但那条不变量只活在推导里，
// 第三层撑满 3 分钟而第二层默认只举 90 秒时，面板的"开盾域名"会在明明 100% 发验证的
// 窗口里报 0。把它写进数据，读数才与执行一致。
func liftChallengeUntil(dt *domainTracker, keepAt time.Time) {
	if keepAt.After(dt.challengeUntil) {
		dt.challengeUntil = keepAt
	}
}
