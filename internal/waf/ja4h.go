package waf

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// ValidJA4H 判断一个 JA4H 串是否符合 ComputeJA4H 产出的 a_b_c_d 形态：
// 四个下划线分段；首段 12 位且逐位有定式（方法 2 位小写字母数字 + 版本 2 位小写字母数字 +
// cookie 位 c/n + referer 位 r/n + 头数 2 位数字 + 语言 4 位小写字母数字），
// 其余三段各 12 位小写十六进制。
//
// 边缘自己算出的值恒满足这个形状，因此"非空但不成形"只有一个来源：这个 X-Ja4h 不是本地算的
// （模板的头清理被绕过，或有人直连了明文 WAF 端口）。调用方按伪造处理是安全的，
// 不需要先证明请求本身有害。空串不在此列——那表示指纹不可用，属于放行范畴。
//
// 首段的每一位都参与校验，是因为校验强度直接决定误伤面：规则在静默放行态也会把非法值 403，
// 只要 ComputeJA4H 有任何一种输入能产出未覆盖的形状，真人就会被挡在门外。上面这套定式
// 与 ja4hMethod / ja4hVersion / ja4hFlag / ja4hLanguage 的产出逐位对齐（它们一律小写）。
func ValidJA4H(fp string) bool {
	parts := strings.Split(fp, "_")
	if len(parts) != 4 || len(parts[0]) != 12 {
		return false
	}
	a := parts[0]
	// 版本两位按"小写字母数字"而非"数字"校验：现在传的是 "11"，将来对外提供 HTTP/2 时
	// 会是 "h2" 之类，把这里写死成数字就会在那一天把所有 h2 流量判成伪造。
	if !isAlphaNumLower(a[0]) || !isAlphaNumLower(a[1]) || !isAlphaNumLower(a[2]) || !isAlphaNumLower(a[3]) {
		return false
	}
	if a[4] != 'c' && a[4] != 'n' {
		return false
	}
	if a[5] != 'r' && a[5] != 'n' {
		return false
	}
	if !isDigit(a[6]) || !isDigit(a[7]) {
		return false
	}
	for i := 8; i < 12; i++ {
		if !isAlphaNumLower(a[i]) {
			return false
		}
	}
	for _, seg := range parts[1:] {
		if len(seg) != 12 {
			return false
		}
		for i := 0; i < len(seg); i++ {
			if !isHexDigit(seg[i]) {
				return false
			}
		}
	}
	return true
}

func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f')
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

func isAlphaNumLower(b byte) bool {
	return isDigit(b) || (b >= 'a' && b <= 'z')
}

// ParseRawHeaders 解析 Tengine 经 lua-nginx-module 转发的 base64 原始请求头文本
// （ngx.req.raw_header(true) 的输出，不含请求行），返回：
//   - names：按客户端发送的原始顺序排列的头名称列表，不含 Cookie/Referer/HTTP2 伪头（":"开头）；
//   - hasCookie / hasReferer：原始头中是否出现过 Cookie / Referer；
//   - acceptLang：Accept-Language 头的原始值（用于 JA4H a 段）。
//
// rawB64 为空或无法 base64 解码时返回全部零值，调用方应按"指纹不可用"处理，不应当作攻击信号。
func ParseRawHeaders(rawB64 string) (names []string, hasCookie, hasReferer bool, acceptLang string) {
	if rawB64 == "" {
		return nil, false, false, ""
	}
	raw, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		return nil, false, false, ""
	}

	for _, line := range strings.Split(string(raw), "\r\n") {
		if line == "" {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		name := strings.TrimSpace(line[:colon])
		if name == "" || strings.HasPrefix(name, ":") {
			continue
		}

		switch strings.ToLower(name) {
		case "cookie":
			hasCookie = true
			continue
		case "referer":
			hasReferer = true
			continue
		case "accept-language":
			acceptLang = strings.TrimSpace(line[colon+1:])
		}
		names = append(names, name)
	}
	return names, hasCookie, hasReferer, acceptLang
}

// ComputeJA4H 按 FoxIO JA4H 规范
// (https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4H.md) 计算 HTTP
// 客户端指纹，返回格式为 a_b_c_d（不带 "JA4H" 前缀，与官方工具输出的指纹值本身一致，
// 便于和其他 JA4H 实现/威胁情报直接比对）：
//
//	a: method(2位小写) + httpVersion(2位，如"11") + cookie存在标记(1位 c/n) +
//	   referer存在标记(1位 r/n) + 头数量(2位，不含Cookie/Referer，超过99记为99) +
//	   Accept-Language 前4位（小写，去掉'-'，按','/';'切分取第一段，不足4位补'0'）
//	b: 头名称按原始顺序（不含Cookie/Referer）以','连接后 SHA256 截断前12位十六进制
//	c: Cookie 字段名按字母排序后以','连接的 SHA256 截断前12位（无Cookie为12个'0'）
//	d: Cookie "名=值" 按名排序后以','连接的 SHA256 截断前12位（无Cookie为12个'0'）
//
// httpVersion 由调用方固定传入（当前边缘仅对外提供 HTTP/1.1，见 site.conf.tmpl 的
// ssl_alpn_protocols 配置）。rawHeadersB64 为空或无法解析时返回空字符串，表示指纹不可用
// （例如 lua-nginx-module 未启用或旧版边缘二进制），调用方应 fail-open，只跳过第三层指纹
// 检测，不影响第一、二层照常生效。
func ComputeJA4H(method, httpVersion, rawHeadersB64, cookieHeader string) string {
	names, hasCookie, hasReferer, acceptLang := ParseRawHeaders(rawHeadersB64)
	if rawHeadersB64 == "" || (names == nil && !hasCookie && !hasReferer && acceptLang == "") {
		return ""
	}

	a := ja4hMethod(method) + ja4hVersion(httpVersion) +
		ja4hFlag(hasCookie || cookieHeader != "") + ja4hFlag2(hasReferer) +
		fmt.Sprintf("%02d", min(len(names), 99)) +
		ja4hLanguage(acceptLang)

	b := sha12(strings.Join(names, ","))

	c, d := "000000000000", "000000000000"
	if cookieHeader != "" {
		if fieldNames, pairs := sortedCookiePairs(cookieHeader); len(fieldNames) > 0 {
			c = sha12(strings.Join(fieldNames, ","))
			d = sha12(strings.Join(pairs, ","))
		}
	}

	return a + "_" + b + "_" + c + "_" + d
}

func ja4hMethod(method string) string {
	m := strings.ToLower(method)
	if len(m) >= 2 {
		return m[:2]
	}
	return (m + "00")[:2]
}

func ja4hVersion(version string) string {
	if len(version) >= 2 {
		return version[:2]
	}
	return (version + "00")[:2]
}

func ja4hFlag(present bool) string {
	if present {
		return "c"
	}
	return "n"
}

func ja4hFlag2(present bool) string {
	if present {
		return "r"
	}
	return "n"
}

// ja4hLanguage 按 JA4H 规范归一化 Accept-Language 头的首选语言为固定 4 字符。
func ja4hLanguage(v string) string {
	if v == "" {
		return "0000"
	}
	v = strings.ToLower(v)
	v = strings.ReplaceAll(v, "-", "")
	v = strings.ReplaceAll(v, ";", ",")
	if idx := strings.IndexByte(v, ','); idx >= 0 {
		v = v[:idx]
	}
	if len(v) > 4 {
		v = v[:4]
	}
	for len(v) < 4 {
		v += "0"
	}
	return v
}

// sortedCookiePairs 解析 "name1=value1; name2=value2" 格式的 Cookie 头，按字段名字母排序
// 后返回字段名列表和对应的原始 "name=value" 对列表（顺序一致）。
func sortedCookiePairs(cookieHeader string) (fieldNames []string, pairs []string) {
	type kv struct{ name, pair string }
	var list []kv
	for _, part := range strings.Split(cookieHeader, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name := part
		if eq := strings.IndexByte(part, '='); eq >= 0 {
			name = strings.TrimSpace(part[:eq])
		}
		if name == "" {
			continue
		}
		list = append(list, kv{name: name, pair: part})
	}
	sort.Slice(list, func(i, j int) bool { return list[i].name < list[j].name })
	for _, e := range list {
		fieldNames = append(fieldNames, e.name)
		pairs = append(pairs, e.pair)
	}
	return fieldNames, pairs
}

func sha12(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:12]
}
