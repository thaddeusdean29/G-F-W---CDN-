package config

import (
	"fmt"
	"regexp"
	"strings"
)

var domainRe = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

func ValidateDomain(d *Domain) error {
	if d.Domain == "" {
		return fmt.Errorf("domain is required")
	}
	if !domainRe.MatchString(d.Domain) {
		return fmt.Errorf("invalid domain: %s", d.Domain)
	}
	// OriginScheme 只允许 http 或 https，空值默认为 http
	switch d.OriginScheme {
	case "", "http":
		d.OriginScheme = "http"
	case "https":
	default:
		return fmt.Errorf("origin_scheme must be http or https")
	}
	// GatewayProfile 一旦分配就固定，不允许被清空或随机替换
	// 空值时自动分配（兼容旧域名迁移，同时补全 TraceHdr）
	if d.GatewayProfile.Server == "" {
		d.GatewayProfile = GetRandomProfile()
	}
	// 已分配过皮肤的存量记录里没有 challenge_url/verify_url 这两个新字段，
	// 必须在渲染前补齐：模板把它们直接当 nginx location 名用，空串会让整份配置语法失败。
	d.GatewayProfile.Normalize()
	if len(d.Upstreams) == 0 {
		return fmt.Errorf("at least one upstream is required")
	}
	for i, u := range d.Upstreams {
		if u.Address == "" {
			return fmt.Errorf("upstream[%d].address is required", i)
		}
		if u.Weight <= 0 {
			d.Upstreams[i].Weight = 1
		}
	}
	for i, r := range d.CacheRules {
		if len(r.Extensions) == 0 {
			return fmt.Errorf("cache_rule[%d].extensions is required", i)
		}
		if r.TTL == "" {
			return fmt.Errorf("cache_rule[%d].ttl is required", i)
		}
		if !validTTL(r.TTL) {
			return fmt.Errorf("cache_rule[%d].ttl invalid format (use e.g. 30d, 7d, 1h, 60m)", i)
		}
	}
	if err := NormalizeDefenseCNAME(&d.DefenseCNAME); err != nil {
		return err
	}
	// 验证凭证的地址绑定粒度必须是已知取值。这里拒绝未知值而不是静默回退到默认档：
	// 该字段决定挑战 Cookie 能否跨地址复用，拼错一个词（"Subnet"、"/24"）若被当成默认
	// 处理，管理员会以为自己放宽了绑定、实际没生效，于是继续被无限挑战循环困住；
	// 反过来若把未知值当成 none，就是在管理员不知情的情况下把防复用保护关掉。
	switch d.CCPolicy.ChallengeBindScope {
	case "", "ip", "subnet", "none":
	default:
		return fmt.Errorf("cc_policy.challenge_bind_scope must be ip, subnet, or none")
	}
	// 越界值直接拒绝，不静默夹到边界：自适应模式下这个数决定攻击停手后真人还要被挡多久。
	// 写 5（想让搜索引擎巡检尽快放行）或写 86400（想常驻开盾）若被夹成 10/900，面板显示的
	// 和实际执行的就是两回事，排障时会被这个差异彻底带偏。
	if s := d.CCPolicy.ChallengeHoldSeconds; s != 0 && (s < 10 || s > 900) {
		return fmt.Errorf("cc_policy.challenge_hold_seconds must be 0 (default 90) or within 10..900")
	}
	if d.SSL.Enabled {
		switch d.SSL.Mode {
		case "autocert", "manual", "disabled":
		default:
			return fmt.Errorf("ssl.mode must be autocert, manual, or disabled")
		}
		if d.SSL.Mode == "manual" {
			if d.SSL.CertFile == "" || d.SSL.KeyFile == "" {
				return fmt.Errorf("ssl.cert_file and ssl.key_file are required for manual mode")
			}
		}
	}
	return nil
}

var ttlRe = regexp.MustCompile(`^\d+[smhd]$`)

func validTTL(ttl string) bool {
	return ttlRe.MatchString(strings.TrimSpace(ttl))
}

// NormalizeDefenseCNAME 规范化高防 CDN 给的 CNAME 目标：去空白、去协议前缀与末尾点号、转小写。
// 空值合法（表示未配置）。必须是纯主机名：它会原样写成切换记录的 CNAME 内容，
// 写错了（带路径、带端口、写成 IP）等于把全站解析到一个不存在的地方。
func NormalizeDefenseCNAME(s *string) error {
	v := strings.ToLower(strings.TrimSpace(*s))
	v = strings.TrimPrefix(strings.TrimPrefix(v, "https://"), "http://")
	v = strings.TrimSuffix(strings.TrimSuffix(v, "/"), ".")
	*s = v
	if v != "" && !domainRe.MatchString(v) {
		return fmt.Errorf("高防 CNAME 必须是域名（如 xxx.cdn-provider.com），不能带协议、端口或路径: %s", v)
	}
	return nil
}
