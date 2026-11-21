package tengine

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"

	"cdn/internal/config"
)

// 站点配置用 text/template + 自制 join 渲染，租户可控字段是逐字写进 nginx 配置的，没有任何转义。
//
// 这不是理论风险。upstreams[].address 很早就在 API 侧配了拒绝清单，cache_rules[].extensions
// 却只挡了空字符串，于是 extensions 里塞一段换行加大括号就能在自己的站点里开出新的
// location。tengine -t 只判语法，载荷只要括号配平就通过并触发整节点 reload——一个付费
// 账号换一台节点。
//
// 所以这里按"实际会被插值的位置"逐个收口，判据是模板里的取值清单而不是字段名清单：
// .Domain（兼 conf 文件名与日志文件名）、.ID（upstream 块名）、.Address、join .Extensions
// "|"、证书两行路径、.GatewayProfile 的五个字符串、.EdgePort。
// .Weight/.TTL 是数值或经 ttlToSeconds 归一成 int，类型本身就关住了；$.OriginScheme 只进
// eq 比较、输出的是字面量 https/http，都不在这里。
//
// 校验放在渲染侧而不是只放 API 侧：历史脏数据、主控直推、以后新增的写入路径都从这一个门口过。
// 输入取渲染结果而不是 d 本身——newTemplateData 里的 Normalize() 会把历史数据里缺失的两条
// 皮肤路径补成默认值，拿归一化之后的值判定才是"即将落盘的内容"；判归一化之前的空串会把
// 老域名全部误杀。
//
// 判非法就拒写这条域名的 conf 并返回错误，不产出"阉割版"配置：边缘只剩半份配置比这个域名
// 暂时没配置更难排查。磁盘上已存在的旧 conf 不受影响，站点继续按上一版提供服务。
var (
	// renderDomainRe：域名同时是 server_name、conf 文件名和日志文件名，
	// 因此除了主机名字符集，还必须排除 ".."（下面单独判）。
	renderDomainRe = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)
	// renderIDRe：内部 ID 会拼成 upstream 块名与 proxy_pass 目标，形如 dom_1a2b。
	renderIDRe  = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
	renderExtRe = regexp.MustCompile(`^[A-Za-z0-9]{1,10}$`)
	// renderAddrRe：upstream server 只认 IP / 域名 [:端口]，带协议或路径会让 tengine -t 失败。
	renderAddrRe = regexp.MustCompile(`^[A-Za-z0-9._:\[\]-]{1,253}$`)
	renderPathRe = regexp.MustCompile(`^/[A-Za-z0-9._/-]{0,254}$`)
	// renderPortRe：EdgePort 由边缘进程自己配置（非租户字段），输出在 listen/proxy_pass 里。
	renderPortRe = regexp.MustCompile(`^[0-9]{1,5}$`)
)

// quotedBadChars 出现在双引号内的 nginx 取值里就能逃出引号、提前收尾指令。
// 这里必须用黑名单而不是白名单：合法皮肤值形如 "Apache/2.4.62 (Unix)"，空格和括号都要放过。
const quotedBadChars = "\"'`;{}#\\\r\n"

// validateRenderData 检查 data 中每一个会被逐字写进站点配置的字段。
// 错误文案面向节点运维：点明字段与非法取值，否则现场只能看到"这条域名没配置"。
func validateRenderData(data domainTemplateData) error {
	if !renderDomainRe.MatchString(data.Domain) || strings.Contains(data.Domain, "..") {
		return fmt.Errorf("域名 %q 不能作为站点配置：它同时是 server_name、conf 文件名和日志文件名", data.Domain)
	}
	if !renderIDRe.MatchString(data.ID) {
		return fmt.Errorf("域名 %s 的内部 ID %q 非法：它会拼成 upstream 块名", data.Domain, data.ID)
	}
	if !renderPortRe.MatchString(data.EdgePort) {
		return fmt.Errorf("边缘端口 %q 非法：只能是 1-5 位数字", data.EdgePort)
	}
	for _, u := range data.Upstreams {
		if !renderAddrRe.MatchString(u.Address) {
			return fmt.Errorf("域名 %s 的源站地址 %q 非法：upstream server 只接受 IP 或域名（可带 :端口）", data.Domain, u.Address)
		}
	}
	for i, rule := range data.CacheRules {
		for _, ext := range rule.Extensions {
			if !renderExtRe.MatchString(ext) {
				return fmt.Errorf("域名 %s 第 %d 条缓存规则的扩展名 %q 非法：只允许 1-10 个字母或数字，它会被逐字拼进 location ~* \\.(...)$ 的正则体",
					data.Domain, i+1, ext)
			}
		}
	}
	if data.SSL.Enabled {
		for _, p := range []string{data.SSL.CertFile, data.SSL.KeyFile} {
			if !renderPathRe.MatchString(p) {
				return fmt.Errorf("域名 %s 的证书路径 %q 非法：需要是绝对路径且不含空格或引号", data.Domain, p)
			}
		}
	}
	for _, kv := range []struct{ name, val string }{
		{"Server 头皮肤值", data.GatewayProfile.Server},
		{"追踪头名", data.GatewayProfile.TraceHdr},
		{"追踪头值", data.GatewayProfile.TraceVal},
	} {
		// 空值由模板的 {{- if }} 整行跳过，不输出指令，所以 "" 合法。
		if strings.ContainsAny(kv.val, quotedBadChars) {
			return fmt.Errorf("域名 %s 的皮肤 %s=%q 含可逃出引号的字符", data.Domain, kv.name, kv.val)
		}
	}
	// ChallengeUrl/VerifyUrl 会成为 location 名与 error_page 目标，是"一条记录写错、整节点
	// tengine -t 失败"的那类字段。newTemplateData 已经用 Normalize() 把非法值兜底成默认路径，
	// 这里对兜底之后的结果再断一次：哪天 Normalize 被删掉或被挪到渲染之后，由这里挡住空
	// location 名落盘，而不是等整节点 reload 失败。
	for _, kv := range []struct{ name, val string }{
		{"挑战路径", data.GatewayProfile.ChallengeUrl},
		{"上报路径", data.GatewayProfile.VerifyUrl},
	} {
		if !config.IsSafeLocationPath(kv.val) {
			return fmt.Errorf("域名 %s 的皮肤 %s=%q 不是合法 location 路径", data.Domain, kv.name, kv.val)
		}
	}
	return nil
}

// domainConfPath 把域名换成磁盘上的站点配置文件路径。
//
// 凡是从 d.Domain 拼文件名的入口都必须走这里，不能各自 filepath.Join：域名是租户可控字段，
// 而 Join 会把 "../.." 清洗成真实生效的越界路径——"删自己这条站点"于是变成
// "删别人的站点 / 建一条指向别人配置的符号链接"。Restore 会按快照里记下的路径原样写回，
// 所以快照侧同样不能收这种名字。
func domainConfPath(dir, domain string) (string, error) {
	if !renderDomainRe.MatchString(domain) || strings.Contains(domain, "..") {
		return "", fmt.Errorf("域名 %q 不能用作站点配置文件名", domain)
	}
	return filepath.Join(dir, domain+".conf"), nil
}
