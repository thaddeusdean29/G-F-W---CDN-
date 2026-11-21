package xdp

import "net"

// IsBogonSource 判断一个源地址是否**不可能**属于真实的互联网主机。
//
// 这是 cdn_xdp.c 里 is_bogon_v4 / IPv6 ff00::/8 判断的 Go 侧镜像，两处必须保持一致。
// eBPF 侧在驱动层就丢掉这些包，正常情况下它们根本到不了 AutoBlocker；Go 侧仍然需要
// 同一份判断，原因有三：
//
//   - 存档兼容：加入过滤之前落盘的 xdp_blocked.json 里已经攒了伪造源地址（作者的节点上
//     141 条封禁里有 19 条），restoreState 会把它们重新写回 blocklist，白占 map 条目。
//   - 版本错配：cdn_xdp.o 与 cdnedge 二进制是分别部署的（install.sh 编译 .o，面板按钮
//     也能单独重装）。节点跑着旧 .o + 新 cdnedge 时，eBPF 侧没有过滤，Go 侧是唯一防线。
//   - bogon_drop 可被关闭：SetConfig 允许置 0，此时封禁记账依然不该被伪造源填满。
//
// 收录范围与 eBPF 侧严格相同，刻意收得很窄 —— 误判一段合法地址会让那些用户在
// 驱动层被静默丢包，iptables 和应用日志都看不出痕迹。特别地，**不**包含
// 169.254.0.0/16（云元数据服务的返回包源地址）、0.0.0.0/8（DHCP）、
// 100.64.0.0/10（运营商 CGNAT，后面是真实用户）、RFC1918 私网（内网回源/前置 LB）
// 以及 IPv6 的 fe80::/10（NDP/RA，丢了 IPv6 直接断网）。
func IsBogonSource(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		// 127.0.0.0/8 环回；224.0.0.0/3（首字节 >=224）一次覆盖组播、
		// IANA 保留的 Class E 和广播 255.255.255.255。
		return v4[0] == 127 || v4[0] >= 224
	}
	if len(ip) == net.IPv6len {
		// ff00::/8 组播。组播地址按定义不能作为源地址。
		return ip[0] == 0xff
	}
	return false
}

// IsBogonSourceStr 是 IsBogonSource 的字符串入口。**无法解析的地址返回 false**：
// 这里的职责只是识别伪造源，不是校验格式；调用方（blockIfNeeded）自己会因为
// ParseIP 失败而提前返回。返回 true 会导致静默丢弃，不能用在"拿不准"的输入上。
func IsBogonSourceStr(ip string) bool {
	return IsBogonSource(net.ParseIP(ip))
}
