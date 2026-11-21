package xdp

import (
	"net"
	"strconv"
	"strings"
)

// ipv4Key 把 IPv4 地址转成 eBPF map 的键：**4 字节原始网络序**，与 C 侧
// `__u32 src_ip = ip->saddr` 在内存里的字节完全一致。
//
// 绝不能用 uint32 做键。cilium/ebpf 按 NativeEndian（x86 上是小端）序列化 uint32，
// 而此前的 ipToUint32 先按 BigEndian 解出整数 —— 两次转换叠加，写进 map 的字节是
// 反的：封 1.2.3.4 实际写入的是 4.3.2.1。后果：
//   - 面板/主控下发的封禁、WAF 下沉的封禁、白名单，对真实流量**全部无效**；
//   - 读速率 map 时又反一次，AutoBlocker 恰好封对了键，但记账、日志、面板、落盘和
//     广播给 WAF/其他节点的都是倒序的 IP —— 等于在全网封一个无辜地址。
//
// [4]byte 由 cilium 按原始内存拷贝，不经过任何字节序转换。
func ipv4Key(ip net.IP) ([4]byte, bool) {
	var key [4]byte
	v4 := ip.To4()
	if v4 == nil {
		return key, false
	}
	copy(key[:], v4)
	return key, true
}

// ipv4FromKey 是 ipv4Key 的逆：map 键字节即网络序地址。
func ipv4FromKey(key [4]byte) net.IP {
	return net.IPv4(key[0], key[1], key[2], key[3]).To4()
}

// reverseIPv4String 把点分十进制 IPv4 的四段倒序；非 IPv4 原样返回。
// 仅用于迁移 v2 存档里按旧（错误）字节序记下的地址。
func reverseIPv4String(s string) string {
	if ip := net.ParseIP(s); ip == nil || ip.To4() == nil || strings.Contains(s, ":") {
		return s
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return s
	}
	for _, p := range parts {
		if _, err := strconv.Atoi(p); err != nil {
			return s
		}
	}
	return parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
}

// fixLegacyV4Order 把 v2 及更早存档里的 IPv4 键倒回正确顺序。
//
// 旧版存档里的 IPv4 键来自读速率 map 时的错误解码（见 ipv4Key），全部是倒序的。
// 不转换的话，新二进制按正确字节序把它们写回 blocklist，封的就是那个倒序的无辜地址，
// 而真正的攻击源被放行 —— 恰好在升级那一刻。IPv6 不受影响（一直是 [16]byte 键）。
func fixLegacyV4Order(bans map[string]string, offenders map[string]*offenderRecord) (map[string]string, map[string]*offenderRecord) {
	nb := make(map[string]string, len(bans))
	for ip, exp := range bans {
		nb[reverseIPv4String(ip)] = exp
	}
	no := make(map[string]*offenderRecord, len(offenders))
	for ip, rec := range offenders {
		no[reverseIPv4String(ip)] = rec
	}
	return nb, no
}
