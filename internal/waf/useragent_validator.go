package waf

import (
	"fmt"
	"net/http"
	"strings"
)

// UserAgentValidator 异常 User-Agent 检测器。
// 检测空 UA、超长 UA、已知攻击工具 UA，可在 L7 层快速拦截。
type UserAgentValidator struct{}

// NewUserAgentValidator 创建 UA 验证器。
func NewUserAgentValidator() *UserAgentValidator {
	return &UserAgentValidator{}
}

// knownAttackTools 已知攻击工具的 UA 关键词（小写）。
var knownAttackTools = []string{
	// 扫描器
	"nmap", "masscan", "zmap", "nikto", "acunetix", "nessus", "openvas",
	"sqlmap", "havij", "pangolin",
	"burpsuite", "burp", "owasp zap", "zaproxy",
	"metasploit", "msfconsole",
	"dirbuster", "dirb", "gobuster", "wfuzz", "ffuf",
	"nuclei", "jaeles", "subfinder",

	// 爬虫/抓取工具（非搜索引擎）
	"scrapy", "beautiful soup", "mechanize", "wget", "curl",
	"python-requests", "go-http-client", "java/",
	"http_request", "httpclient", "apache-httpclient",

	// DDoS 工具
	"hulk", "torshammer", "slowloris", "pyloris",
	"goldeneye", "xerxes",

	// 其他攻击工具
	"hydra", "medusa", "aircrack",
	"w3af", "webscarab", "paros",
	"grabber", "jbrofuzz",

	// 明显的测试标记
	"test", "scanner", "exploit", "vulnerability", "pentest",
	"security", "attack", "payload",
}

// ValidateUserAgent 验证请求的 User-Agent，检测异常或恶意 UA。
// 返回 nil 表示验证通过，返回 *Result 表示检测到可疑 UA。
func (v *UserAgentValidator) ValidateUserAgent(r *http.Request) *Result {
	ua := r.Header.Get("User-Agent")

	// 1. 检测空 UA（可疑，但不直接拦截，允许健康检查和监控工具）
	// 注意：某些 CDN 健康检查、内部监控可能无 UA，不能一刀切拦截
	if ua == "" {
		// 如果是明显的攻击路径（如扫描器探测路径），才拦截空 UA
		if isProbeRequest(r) {
			return &Result{
				Action:  Block,
				Rule:    "empty-ua",
				Message: "empty User-Agent from suspicious request",
			}
		}
		// 正常路径的空 UA，记录但放行
		return nil
	}

	// 2. 检测超长 UA（>1024 字节，可能是攻击载荷或尝试溢出）
	if len(ua) > 1024 {
		return &Result{
			Action:  Block,
			Rule:    "oversized-ua",
			Message: fmt.Sprintf("User-Agent too long: %d bytes", len(ua)),
		}
	}

	// 3. 先检查是否是白名单 bot，如果是则跳过后续检测
	if v.IsWhitelistedBot(ua) {
		return nil
	}

	// 4. 检测已知攻击工具 UA
	uaLower := strings.ToLower(ua)
	for _, tool := range knownAttackTools {
		if strings.Contains(uaLower, tool) {
			return &Result{
				Action:  Block,
				Rule:    "attack-tool-ua",
				Message: "known attack tool in User-Agent: " + tool,
			}
		}
	}

	// 5. 检测明显伪造的 UA（非字母数字字符占比过高，可能是编码后的载荷）
	// 但要排除白名单 bot（上面已经检查过了）
	if v.isSuspiciousEncoding(ua) {
		return &Result{
			Action:  Block,
			Rule:    "suspicious-ua-encoding",
			Message: "suspicious encoding in User-Agent",
		}
	}

	return nil
}

// isProbeRequest 判断是否是扫描器探测请求（访问已知扫描路径或使用可疑方法）。
func isProbeRequest(r *http.Request) bool {
	path := r.URL.Path

	// 常见扫描器探测路径
	probePatterns := []string{
		"/admin", "/phpmyadmin", "/wp-admin", "/wp-login",
		"/phpinfo", "/test", "/demo", "/backup",
		"/.git", "/.env", "/.svn",
		"/shell", "/webshell", "/c99", "/r57",
		"/config", "/setup", "/install",
	}

	for _, pattern := range probePatterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}

	// 可疑方法（OPTIONS/TRACE 在某些场景下用于探测）
	if r.Method == "OPTIONS" || r.Method == "TRACE" {
		return true
	}

	return false
}

// isSuspiciousEncoding 检测 UA 字符串中非字母数字字符占比是否过高。
// 正常 UA 主要由字母、数字、空格、斜杠、括号组成，特殊字符占比不应超过 30%。
func (v *UserAgentValidator) isSuspiciousEncoding(ua string) bool {
	if len(ua) < 10 {
		return false // 太短，不判断
	}

	normalChars := 0
	for _, ch := range ua {
		// 允许的正常字符：字母、数字、空格、常见标点
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
			(ch >= '0' && ch <= '9') ||
			ch == ' ' || ch == '/' || ch == '(' || ch == ')' ||
			ch == '.' || ch == '-' || ch == '_' || ch == ':' ||
			ch == ';' || ch == ',' {
			normalChars++
		}
	}

	normalRatio := float64(normalChars) / float64(len(ua))
	return normalRatio < 0.6 // 正常字符占比低于 60% 视为可疑
}

// IsWhitelistedBot 判断是否是白名单爬虫（搜索引擎、CDN 等合法 bot）。
// 这些 bot 即使 UA 包含某些关键词，也不应拦截。
func (v *UserAgentValidator) IsWhitelistedBot(ua string) bool {
	if ua == "" {
		return false
	}

	uaLower := strings.ToLower(ua)

	// 主流搜索引擎
	whitelistedBots := []string{
		"googlebot", "google", "bingbot", "baiduspider", "yandexbot",
		"duckduckbot", "slurp", "yahoo", "sogou", "exabot",
		// 社交媒体爬虫
		"facebookexternalhit", "twitterbot", "linkedinbot", "whatsapp", "slackbot",
		// CDN 和监控
		"cloudflare", "uptimerobot", "pingdom", "statuscake",
		// 合法服务
		"feedfetcher", "feedburner", "embedly", "quora",
	}

	for _, bot := range whitelistedBots {
		if strings.Contains(uaLower, bot) {
			return true
		}
	}

	return false
}
