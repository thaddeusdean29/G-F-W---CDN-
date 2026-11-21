//go:build linux

// 挂在 AutoBlocker 上的累犯记账方法。单独成文件而不是放在 escalate.go 里，
// 是因为 AutoBlocker 只在 linux 下存在（monitor.go 带 //go:build linux），
// 而 escalate.go 里的常量和 ParseBanLadder 要在 Windows/Mac 上也能编译
// （cmd/cdnedge 解析 flag 时引用）。
package xdp

import (
	"log"
	"time"
)

// banDurationFor 记一次该 IP 的封禁并返回本次应使用的时长。
//
// 调用方必须持有 a.mu。返回的时长来自 a.ladder，而实际过期时刻由调用方算成绝对时间
// 存进 blockedIPs —— 这样即使之后改了阶梯配置，已生效封禁的剩余时长也不会变
// （与 blockedIPs 存绝对过期时刻的理由相同）。
func (a *AutoBlocker) banDurationFor(ip string, now time.Time) time.Duration {
	if len(a.ladder) == 0 {
		// 没有配置阶梯时退化为固定时长，保持与旧行为一致。
		return a.duration
	}

	rec := a.offenders[ip]
	if rec == nil || now.Sub(rec.LastSeen) > a.offenderTTL {
		// 首次，或上次被封已超出遗忘窗口：从首档重新开始。
		rec = &offenderRecord{}
		a.offenders[ip] = rec
	}
	rec.Count++
	rec.LastSeen = now

	// 先算时长再淘汰：pruneOffendersLocked 可能把这条刚写入的记录淘汰掉
	// （超限时按最久未见淘汰，而它的 LastSeen 是最新的，实际不会被选中，
	// 但顺序上不依赖这一点更稳）。
	dur := ladderDuration(a.ladder, rec.Count, a.duration)
	a.pruneOffendersLocked(now)
	return dur
}

// restoreBanConfig 从存档里恢复面板下发过的阶梯配置。
//
// 解析失败时保留启动 flag 的值并打日志，而不是 Fatal 或清空：存档里的这两项是次要
// 信息，为了它们让一个本来能正常启动、能恢复 141 条封禁的节点起不来是不成比例的。
func (a *AutoBlocker) restoreBanConfig(st *stateFile) {
	if st == nil || (st.Ladder == "" && st.OffenderTTL == "") {
		return
	}
	ladder, err := ParseBanLadder(st.Ladder)
	if err != nil {
		log.Printf("[XDP] restore ban config: bad ladder %q in state file, keeping startup value: %v",
			st.Ladder, err)
		return
	}
	var ttl time.Duration
	if st.OffenderTTL != "" {
		ttl, err = time.ParseDuration(st.OffenderTTL)
		if err != nil || ttl <= 0 {
			log.Printf("[XDP] restore ban config: bad offender_ttl %q in state file, keeping startup value",
				st.OffenderTTL)
			return
		}
	}
	if err := ValidateBanConfig(ladder, ttl); err != nil {
		log.Printf("[XDP] restore ban config: %v, keeping startup value", err)
		return
	}

	// 直接改字段而不是走 SetBanConfig：那个会 persistState，而这里还在 restoreState
	// 里、a.mu 之外的解析阶段，且封禁记账都还没恢复 —— 此刻落盘会写出一份空存档，
	// 把节点上的封禁全丢掉。
	a.mu.Lock()
	if len(ladder) > 0 {
		a.ladder = ladder
	}
	if ttl > 0 {
		a.offenderTTL = ttl
	}
	a.banConfigFromPanel = true
	a.mu.Unlock()
	log.Printf("[XDP] restored panel-configured ban ladder: %v (offender TTL %v)",
		LadderPreview(a.ladder), a.offenderTTL)
}

// SetBanConfig 在运行时替换封禁阶梯和遗忘窗口（面板下发 / 主控推送）。
//
// 传 nil 阶梯或 ttl<=0 表示「该项不变」，而不是「重置为默认」—— 面板可能只想改其中
// 一项，把另一项静默恢复成默认值会让用户的另一半配置无声丢失。
//
// 已生效的封禁不受影响：blockedIPs 里存的是**绝对过期时刻**，改阶梯不会延长或缩短
// 正在进行的封禁。这是刻意的 —— 把 24 小时档改短以后，已经被关进去的 IP 应该按封
// 它的时候的承诺放出来，而不是因为一次配置调整集体提前解封。新阶梯从下一次判定起生效。
func (a *AutoBlocker) SetBanConfig(ladder []time.Duration, ttl time.Duration) {
	a.mu.Lock()
	if len(ladder) > 0 {
		// 复制一份：调用方（HTTP handler 解析出来的切片）之后可能复用底层数组，
		// 直接存引用会让阶梯在扫描协程读到一半时被改掉。
		a.ladder = append([]time.Duration(nil), ladder...)
	}
	if ttl > 0 {
		a.offenderTTL = ttl
		// 缩短窗口时立刻按新窗口清一遍记账，而不是等下一次封禁才发现。否则运维把
		// 窗口从 48h 调到 1h 想「放过误封的用户」，那些记账其实还挂着，直到该 IP
		// 再次撞线时才被丢弃 —— 而那一次它已经按旧档位挨了一次长封。
		a.pruneOffendersLocked(time.Now())
	}
	// 标记为面板下发，persistState 才会把它写进存档并在重启后继续生效。
	a.banConfigFromPanel = true
	a.dirty = true
	a.mu.Unlock()
	// 立即落盘：这是用户的显式配置操作，不能在下一轮扫描前被重启吞掉。
	a.persistState()
}

// BanConfig 返回当前生效的阶梯与遗忘窗口，供面板回显。
// 返回阶梯的副本，避免调用方（JSON 编码之外的路径）改到扫描协程正在读的切片。
func (a *AutoBlocker) BanConfig() ([]time.Duration, time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]time.Duration(nil), a.ladder...), a.offenderTTL
}

// offenderCount 返回该 IP 当前的累犯次数（0 表示无记录）。调用方必须持有 a.mu。
func (a *AutoBlocker) offenderCount(ip string) int {
	if rec := a.offenders[ip]; rec != nil {
		return rec.Count
	}
	return 0
}

// pruneOffendersLocked 清理过期记账，并在仍然超限时按「最久未见」淘汰到上限以内。
// 调用方必须持有 a.mu。
func (a *AutoBlocker) pruneOffendersLocked(now time.Time) {
	for ip, rec := range a.offenders {
		if rec == nil || now.Sub(rec.LastSeen) > a.offenderTTL {
			delete(a.offenders, ip)
		}
	}
	if len(a.offenders) <= maxOffenders {
		return
	}
	// 超限：逐轮淘汰最久未见的条目。这里用朴素的「每次扫一遍找最老」而不是建堆 ——
	// 只有在攻击规模真的撑破 65536 条时才会进这条路径，且每次调用最多淘汰到刚好
	// 回到上限，摊销下来每次 banDurationFor 只多一次遍历。
	for len(a.offenders) > maxOffenders {
		var oldestIP string
		var oldest time.Time
		for ip, rec := range a.offenders {
			if oldestIP == "" || rec.LastSeen.Before(oldest) {
				oldestIP, oldest = ip, rec.LastSeen
			}
		}
		if oldestIP == "" {
			return
		}
		delete(a.offenders, oldestIP)
	}
}
