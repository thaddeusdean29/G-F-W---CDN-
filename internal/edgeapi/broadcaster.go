package edgeapi

import (
	"cdn/internal/waf"
	"time"
)

// SetCCBroadcaster 为边缘节点的 CC 防御引擎设置攻击态广播器（由主控侧调用，边缘节点不需要）。
// 边缘节点只需要接收广播（通过 /edge/cc/attack-state 端点），不需要主动发起广播。
func (h *Handler) SetCCBroadcaster(broadcaster waf.AttackStateBroadcaster) {
	if h.ccDefense != nil {
		h.ccDefense.SetBroadcaster(broadcaster)
	}
}

// SetupXDPBroadcast 为 XDP AutoBlocker 设置广播 hook，使其封禁时同步到 WAF 并触发 L4BlockHook。
// 这样 XDP 自动封禁的 IP 会：
//   1. 写入 WAF 封禁列表（面板可见、可手动解封）
//   2. 触发 L4BlockHook 广播到其他节点（如果注册了 hook）
func (h *Handler) SetupXDPBroadcast() {
	ab := h.blocker()
	if ab == nil || h.wafEngine == nil {
		return
	}

	ab.SetBroadcastHook(func(ip string, duration time.Duration) {
		// 同步到 WAF 封禁表：这会触发 l4BlockHook（如果边缘节点注册了广播回调的话）
		h.wafEngine.BlockIP(ip, duration)
	})
}
