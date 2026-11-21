package waf

import (
	"net"
	"net/url"
	"strings"
)

// IsSSRFAttempt 检测目标 URL 是否为 SSRF（服务端请求伪造）攻击尝试。
// 拦截访问内网地址、云平台元数据服务、本地回环等敏感目标的请求。
//
// 适用场景：
// - 回源 URL 验证（防止攻击者控制回源目标访问内网）
// - 代理请求验证（防止通过 CDN 节点作为跳板访问内网）
// - Webhook/回调 URL 验证
//
// 返回 true 表示检测到 SSRF 攻击尝试，应拒绝该请求。
func IsSSRFAttempt(targetURL string) bool {
	// 解析 URL
	u, err := url.Parse(targetURL)
	if err != nil {
		// 解析失败视为可疑，拒绝
		return true
	}

	host := u.Hostname()
	if host == "" {
		// 无 host 字段视为可疑
		return true
	}

	// 1. 检查已知的敏感主机名（大小写不敏感）
	forbiddenHosts := []string{
		// 本地回环
		"localhost",
		"127.0.0.1",
		"0.0.0.0",

		// IPv6 回环
		"::1",
		"0000:0000:0000:0000:0000:0000:0000:0001",
		"::ffff:127.0.0.1", // IPv4-mapped IPv6

		// AWS 元数据服务
		"169.254.169.254",
		"fd00:ec2::254", // AWS IMDSv2 IPv6

		// GCP 元数据服务
		"metadata.google.internal",
		"metadata",

		// Azure 元数据服务
		"169.254.169.254", // 与 AWS 共用

		// Alibaba Cloud 元数据服务
		"100.100.100.200",

		// Kubernetes 内部 DNS
		"kubernetes.default.svc",
		"kubernetes.default.svc.cluster.local",
	}

	hostLower := strings.ToLower(host)
	for _, forbidden := range forbiddenHosts {
		if hostLower == strings.ToLower(forbidden) {
			return true
		}
	}

	// 2. 检查 IP 地址（如果 host 是 IP）
	ip := net.ParseIP(host)
	if ip != nil {
		// IPv4 映射的 IPv6 地址转换为 IPv4
		if ip4 := ip.To4(); ip4 != nil {
			ip = ip4
		}

		// 检查各种内网/保留地址
		if ip.IsLoopback() {
			// 127.0.0.0/8, ::1
			return true
		}

		if ip.IsPrivate() {
			// 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, fc00::/7
			return true
		}

		if ip.IsLinkLocalUnicast() {
			// 169.254.0.0/16 (包含 AWS/Azure 元数据), fe80::/10
			return true
		}

		if ip.IsLinkLocalMulticast() {
			// 224.0.0.0/24, ff02::/10
			return true
		}

		// 额外检查：运营商级 NAT (CGNAT)
		// 100.64.0.0/10 - RFC 6598
		// 这个地址段在某些云环境中被用于内网，应该拦截
		if ip4 := ip.To4(); ip4 != nil {
			if ip4[0] == 100 && (ip4[1]&0xC0) == 64 {
				// 100.64.0.0/10
				return true
			}
		}

		// 检查未指定地址（0.0.0.0, ::）
		if ip.IsUnspecified() {
			return true
		}

		// 检查多播地址
		if ip.IsMulticast() {
			return true
		}

		// 检查接口本地多播（IPv6）
		if ip.IsInterfaceLocalMulticast() {
			return true
		}
	}

	// 3. 检查主机名模式（防止通过域名绕过 IP 检测）
	// 例如：localhost.evil.com, 127.0.0.1.nip.io 等
	suspiciousPatterns := []string{
		"localhost",
		"127.0.0.1",
		"0.0.0.0",
		"metadata",
		"internal",
		"169.254",
		"100.100.100",
		"kubernetes",
		"consul",
		"etcd",
	}

	for _, pattern := range suspiciousPatterns {
		if strings.Contains(hostLower, pattern) {
			// 可疑模式：主机名中包含内网相关关键词
			// 这是一个保守的检测，可能误报，但安全优先
			return true
		}
	}

	// 通过所有检查
	return false
}
