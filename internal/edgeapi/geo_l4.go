package edgeapi

import (
	"log"

	"cdn/internal/geo"
)

// 本文件是区域规则在四层（XDP）的那一侧：把"整节点 deny 哪些国家"变成网卡上的 LPM trie，
// 让被封国家的包在驱动层就被丢掉，不进内核栈。
//
// 该不该进四层、装哪些前缀，都不在这里判断——那份语义只有 geo.Guard.BuildL4Install 一处，
// 七层与四层共用它。这里只负责挑准时机把结论交给 XDP、把结果留在日志里。
// 一旦边缘自己再写一遍"什么时候该丢包"，面板上"封了这个国家"和网卡上实际丢的包
// 就成了两条代码路径算出来的两件事。
//
// 四个时机：装载/撤下前缀表、换整节点策略、启动时从存档恢复、XDP 热安装成功。
// 后两个容易漏：前者会让节点升级后四层空着直到下一次下发；后者是启动时 .o 还没编好、
// 后来在面板上补装的节点，同一件事。

// applyGeoL4 按当前配置与当前表重算四层该装什么，然后整表换上去。
//
// what 只进日志，说明这一轮是谁触发的：出问题时"表换了但四层没跟上"和"策略改了没跟上"
// 是两种不同的查法。
func (h *Handler) applyGeoL4(what string) {
	if h.geoGuard == nil || h.xdpMgr == nil {
		return
	}
	// XDP 没挂上网卡时四棵 trie 的句柄根本不存在，ApplyGeo 只会硬报错。
	// 那句原因 GeoState() 已经给了（"XDP 没加载：四层不会丢任何包"），
	// 这里再打一遍只是把日志刷成噪声。
	if !h.xdpMgr.Loaded() {
		return
	}
	in := h.geoGuard.BuildL4Install()
	if err := h.xdpMgr.ApplyGeo(in); err != nil {
		// 只记日志，不影响本轮 HTTP 应答：四层装失败时七层照常按整节点策略拦，
		// 请求不会漏过去。这个失败同时进了 GeoState().Error，会随下一次上报出现在面板上——
		// "面板显示规则开着、网卡其实没在丢包"必须是看得见的状态，不能只留在节点日志里。
		log.Printf("GEO L4 %s: 装表失败: %v", what, err)
		return
	}
	if in.Skip != "" {
		log.Printf("GEO L4 %s: 四层不装表：%s", what, in.Skip)
		return
	}
	log.Printf("GEO L4 %s: 已装载 v4=%d v6=%d 例外 v4=%d v6=%d 指纹=%s",
		what, len(in.Block4), len(in.Block6), len(in.Exc4), len(in.Exc6), in.Fingerprint)
}

// geoL4Reader 把四层实况接进区域读数。
//
// 读数走 Manager.GeoState() 而不是"我上次下发成功了"：后者在节点重启从存档恢复、
// 或 XDP 被别的路径卸掉之后就会说谎，而面板上那个勾正是靠它撑起来的。
func (h *Handler) geoL4Reader() geo.L4State {
	if h.xdpMgr == nil {
		return geo.L4State{NotInstall: true, Error: "本节点没有 XDP 管理器：四层不会丢任何包"}
	}
	return h.xdpMgr.GeoState()
}
