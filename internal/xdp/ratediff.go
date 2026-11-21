package xdp

import "time"

// 本文件刻意不带 //go:build linux：速率差分是纯算术，与 eBPF 无关，放在无标签文件里
// 才能在任意平台被单元测试覆盖。monitor.go（linux only）只负责读 map 并把结果喂进来。

// rateSample 是一类速率 map 的一次读数。
//
// name 用于在快照里区分不同的 map：同一个 IP 在 syn_rate / ack_rate / pps_rate 里各有
// 一份独立的累计值，若共用一个键，三张表的读数会互相覆盖，差分结果变成随机噪声。
type rateSample struct {
	name   string           // map 简名，如 "syn"、"ack6"
	totals map[string]int64 // IP 字符串 -> 累计包数（struct rate_entry.total）
	limit  uint64           // 每秒阈值；0 表示该项关闭
	reason string           // 触发封禁时记录的原因
}

// rateHit 是一次超速判定的结果。
type rateHit struct {
	IP     string
	Reason string
	PPS    float64
}

// rateDiffer 把 XDP 速率 map 里单调递增的累计包数换算成两次扫描之间的真实 pps。
//
// 为什么必须差分：total 是单调累计值，直接拿它跟"每秒多少包"的阈值比较，任何长期活跃的
// 正常 IP 迟早会累计到超过阈值而被误封 —— 一个稳定 50 pps 的正常客户端在 16 秒后就会
// 越过 synLimit=800。Δtotal / Δt 才是该 IP 在这一段时间里的实际速率。
//
// 反过来也不能读 rate_entry.count：那是 1 秒滑窗字段，每秒被 XDP 重置，而扫描每 10 秒
// 才跑一次；且 count 超过 XDP 侧 limit 后 rate_check 就提前 return 不再自增，实际封顶在
// limit+1，永远到不了 AutoBlocker 更高的封禁阈值。
//
// 非并发安全：仅供 AutoBlocker 的单个 run 协程使用。
type rateDiffer struct {
	// lastTotals 是上一轮的快照，键格式 "<map 简名>|<IP>"。
	lastTotals map[string]uint64
	lastScan   time.Time
	// olderTotals/olderScan 是再上一轮的快照。用途见 diff 里的「新键」规则：一个键在上一轮
	// 快照里缺席，可能是新出现的源，也可能只是上一轮遍历恰好漏了它（LRU map 在高频增删时
	// 遍历会跳过条目）。在再上一轮里找得到，就说明是后者，用那一轮的读数正常差分。
	olderTotals map[string]uint64
	olderScan   time.Time
	// fallback 是无法从时间戳算出间隔时（时钟回拨、同一时刻重复扫描）使用的兜底间隔，
	// 通常就是扫描周期。取 0 会导致除零得到 +Inf，把所有 IP 判成超速。
	fallback time.Duration
}

func newRateDiffer(fallback time.Duration) *rateDiffer {
	if fallback <= 0 {
		fallback = time.Second
	}
	return &rateDiffer{
		lastTotals: make(map[string]uint64),
		fallback:   fallback,
	}
}

// diff 记录本轮读数并返回超速的条目。
//
// 首轮调用只建立基线、返回空：此时没有前一个快照，任何差分都等于该 IP 的全部历史累计量，
// 会把长期活跃的正常 IP 立刻误判成洪水。
//
// 快照整体替换而非增量更新：IP 被 LRU 淘汰后其键自然从 lastTotals 消失，不需要单独清理，
// 也不会让陈旧读数无限驻留内存。
//
// 新键 / 回退键按「下界速率」判定：以前没有基线就只记录不判定，而轮换源地址的洪水里每个
// 源都会在速率表被挤满后被 LRU 淘汰、下一轮以新条目重现 —— 永远没有基线，永远不会被封。
// 条目是在上一轮扫描之后才创建的，total 只累计了创建以来的包，而创建以来的时间 ≤ elapsed，
// 所以 cur/elapsed 是真实速率的下界：它超阈值，真实速率一定超阈值，不会误封。
// 这条规则要求至少有两轮历史（见 olderTotals）：第二轮时上一轮就是首轮基线，基线遍历
// 漏掉的长期活跃键会带着全部历史累计量出现，按下界算会被误判。
func (d *rateDiffer) diff(now time.Time, samples []rateSample) []rateHit {
	baseline := d.lastScan.IsZero()
	elapsed := now.Sub(d.lastScan).Seconds()
	if elapsed <= 0 {
		elapsed = d.fallback.Seconds()
	}
	olderElapsed := now.Sub(d.olderScan).Seconds()
	haveOlder := !d.olderScan.IsZero() && olderElapsed > 0

	snapshot := make(map[string]uint64)
	var hits []rateHit

	for _, s := range samples {
		for ipStr, total := range s.totals {
			key := s.name + "|" + ipStr
			cur := uint64(total)
			snapshot[key] = cur

			// 阈值为 0 表示该项关闭。仍要记快照，否则下次开启时首轮差分会把关闭期间
			// 累积的全部包数算成一个扫描周期内的速率。
			if s.limit == 0 || baseline {
				continue
			}
			var pps float64
			if prev, seen := d.lastTotals[key]; seen && cur >= prev {
				pps = float64(cur-prev) / elapsed
			} else if seen {
				// total 回退：条目被 LRU 淘汰后在上一轮之后重建，cur 只含重建以来的包。
				pps = float64(cur) / elapsed
			} else if old, ok := d.olderTotals[key]; ok && haveOlder && cur >= old {
				// 上一轮遍历漏掉了它，用再上一轮的读数差分。
				pps = float64(cur-old) / olderElapsed
			} else if haveOlder {
				pps = float64(cur) / elapsed
			} else {
				continue
			}
			if pps > float64(s.limit) {
				hits = append(hits, rateHit{IP: ipStr, Reason: s.reason, PPS: pps})
			}
		}
	}

	d.olderTotals, d.olderScan = d.lastTotals, d.lastScan
	d.lastTotals, d.lastScan = snapshot, now
	return hits
}
