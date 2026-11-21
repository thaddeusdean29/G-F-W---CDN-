package config

import (
	_ "embed"
	"encoding/json"
	"math/rand"
	"regexp"
	"strings"
	"sync"
	"time"

	"cdn/internal/secure"
)

// 挑战页两条内部路由的默认值，与 templates/site.conf.tmpl 里改造后的
// `location = {{ .GatewayProfile.ChallengeUrl }}` / `location = {{ .GatewayProfile.VerifyUrl }}`
// 一一对应。默认值保持升级前的线上路径，因此主控不下发这两个字段时配置逐字不变。
const (
	DefaultVerifyPath    = "/__cc/verify"
	DefaultChallengePath = "/edge-waf-challenge"
)

// locationPathRe 是能被安全渲染进 nginx location / error_page 的路径字符集。
// 刻意排除空格、引号、尖括号、分号、花括号、$ 、反斜杠、%、? # *：
// 这些字符要么让 nginx -t 直接挂在语法上，要么给配置注入留出缝隙。
var locationPathRe = regexp.MustCompile(`^/[A-Za-z0-9._/@:~-]{0,127}$`)

// IsSafeLocationPath 判定一个皮肤路径字段能否直接渲染成 location。
//
// 这不是防御性冗余：模板里 location 与 error_page 的目标一旦是空串或非法字符，
// 渲染出来就是 `location =  {` 这种语法错误，nginx -t 失败 → 整次 reload 失败 →
// 该节点上所有域名都停在上一个配置版本（新域名则完全起不来）。一条域名记录里
// 一个字段写错，代价是整个节点，所以必须在渲染前就归一化掉。
//
// 同一个值还会被写进等待页 JS 的 fetch() 目标，所以这里同时按"浏览器侧可安全使用"的标准
// 收紧：`//host/x` 是协议相对 URL，fetch 到它会把凭证 POST 到别人域名去。
func IsSafeLocationPath(p string) bool {
	if !locationPathRe.MatchString(p) {
		return false
	}
	// 根路径会与 location / 撞成重复 location；带 ~ 或 * 的写法会改变匹配语义。
	if p == "/" || strings.HasPrefix(p, "//") || strings.Contains(p, "..") {
		return false
	}
	return !strings.ContainsAny(p, "~*")
}

// GatewayProfile 白标签安全网关皮肤。
type GatewayProfile struct {
	Server       string `json:"server"`        // Server 响应头值
	TraceHdr     string `json:"trace_hdr"`     // 内部链路追踪 Header 字段名
	TraceVal     string `json:"trace_val"`     // 链路追踪 Header 值（按皮肤格式生成）
	ChallengeUrl string `json:"challenge_url"` // 401 内部跳转的挑战页 location（同时作为等待页展示的前端组件路径）
	VerifyUrl    string `json:"verify_url"`    // 挑战页 JS 提交凭证的上报路径
}

// UnmarshalJSON 向下兼容旧数据格式：早期主控下发的是裸字符串（仅皮肤名）。
//
// 这里必须一次解出结构体的全部字段。此前的实现用一个只含 server/trace_hdr 的 alias
// 结构先行探测，对象分支总是成功并立即 return，于是 trace_val 被静默丢弃——边缘节点
// 从主控/DB 解出的皮肤永远带不上按皮肤格式生成的 trace 值，与字段注释里
// "确保能通过主控网络序列化下发"的意图正好相反。
func (g *GatewayProfile) UnmarshalJSON(data []byte) error {
	var wire struct {
		Server       *string `json:"server"`
		TraceHdr     *string `json:"trace_hdr"`
		TraceVal     *string `json:"trace_val"`
		ChallengeUrl *string `json:"challenge_url"`
		VerifyUrl    *string `json:"verify_url"`
	}
	if err := json.Unmarshal(data, &wire); err == nil {
		setStr(&g.Server, wire.Server)
		setStr(&g.TraceHdr, wire.TraceHdr)
		setStr(&g.TraceVal, wire.TraceVal)
		setStr(&g.ChallengeUrl, wire.ChallengeUrl)
		setStr(&g.VerifyUrl, wire.VerifyUrl)
		g.Normalize()
		return nil
	}
	var legacy string
	if err := json.Unmarshal(data, &legacy); err != nil {
		return err
	}
	g.Server = legacy
	g.TraceHdr = ""
	g.TraceVal = ""
	g.ChallengeUrl = ""
	g.VerifyUrl = ""
	g.Normalize()
	return nil
}

func setStr(dst *string, src *string) {
	if src != nil {
		*dst = *src
	}
}

// reservedLocationPaths 是模板里以硬编码形式存在的 location，皮肤路径不能与它们重名：
// nginx 对同一 server 块内的重复精确匹配 location 直接报配置错误，reload 整体失败。
// /edge-waf-check 是 auth_request 子请求目标（保持硬编码），/purge 是缓存清理入口。
var reservedLocationPaths = map[string]bool{
	"/edge-waf-check": true,
	"/purge":          true,
}

// Normalize 把两条内部路由归一成"一定能渲染进 nginx 配置"的值。
//
// 必须无条件跑在模板渲染之前：历史域名记录里根本没有 challenge_url/verify_url 这两个字段，
// 于是模板拿到空串就会产出 `location =  {` 这种语法错误。两条路径撞成同一个值（或与模板
// 里硬编码的 location 撞名）同样会产生重复 location。
func (g *GatewayProfile) Normalize() {
	if !IsSafeLocationPath(g.VerifyUrl) || reservedLocationPaths[g.VerifyUrl] {
		g.VerifyUrl = DefaultVerifyPath
	}
	if !IsSafeLocationPath(g.ChallengeUrl) || reservedLocationPaths[g.ChallengeUrl] {
		g.ChallengeUrl = DefaultChallengePath
	}
	// 两条路径撞成同一个值：先让挑战侧回到默认，仍冲突则让上报侧回到默认。
	// 两个默认值互不相同、都合法且都不在保留名单里，所以两轮之后必然安全且互斥。
	if g.ChallengeUrl == g.VerifyUrl {
		g.ChallengeUrl = DefaultChallengePath
	}
	if g.ChallengeUrl == g.VerifyUrl {
		g.VerifyUrl = DefaultVerifyPath
	}
}

// 皮肤表以密封资源形态编译进二进制：明文数据源只留在构建仓库，分发出去的那份只有密文。
// 改完明文必须重新密封（build.sh 会自动做），否则改动不生效且构建全程零报错。
//
//go:embed gateway_profiles.enc
var gatewayProfilesEnc []byte

// skinSpec 是皮肤表里的一条记录。trace_parts 按数组顺序拼出 TraceVal：
// lit 原样写入，hex/alnum 各取 n 个随机字符。数组顺序就是取随机数的顺序，
// 与改造前 fmt.Sprintf 的实参求值顺序一致，所以同一随机种子下输出逐字节相同。
type skinSpec struct {
	Server       string      `json:"server"`
	TraceHdr     string      `json:"trace_hdr"`
	TraceParts   []tracePart `json:"trace_parts"`
	ChallengeUrl string      `json:"challenge_url"`
	VerifyUrl    string      `json:"verify_url"`
}

type tracePart struct {
	Lit      string `json:"lit,omitempty"`
	Hex      int    `json:"hex,omitempty"`
	AlphaNum int    `json:"alnum,omitempty"`
}

var gatewaySkins = loadGatewaySkins()

// loadGatewaySkins 在包初始化时解密并解析皮肤表。解不开就 panic：这份资源是编译期
// 密封进去的，失败只可能是二进制被篡改或构建流程漏了密封，此时继续跑没有意义。
func loadGatewaySkins() []skinSpec {
	var specs []skinSpec
	if err := json.Unmarshal(secure.MustDecrypt(gatewayProfilesEnc), &specs); err != nil {
		panic("config: 皮肤表解析失败: " + err.Error())
	}
	if len(specs) == 0 {
		panic("config: 皮肤表为空")
	}
	return specs
}

var (
	rngMu sync.Mutex
	rng   = rand.New(rand.NewSource(time.Now().UnixNano()))
)

const (
	hexChars      = "0123456789abcdef"
	alphaNumChars = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
)

// GetRandomProfile 随机返回一个网关皮肤，并按该皮肤的格式生成 Trace 值与两条内部路由。
func GetRandomProfile() GatewayProfile {
	// 锁必须一直持有到随机数取完：math/rand.Rand 不是并发安全的，只锁住"选哪条皮肤"
	// 那一步的话，并发调用会同时读写 rngSource 的 tap 下标，把它踩成负数，
	// 直接 panic: index out of range [-1] 把整个进程带走（面板侧是在 HTTP 请求里调的）。
	// 用 defer 而不是中途 Unlock，是为了生成过程万一 panic 也不会把锁永久留在 locked 状态。
	rngMu.Lock()
	defer rngMu.Unlock()

	idx := rng.Intn(len(gatewaySkins))
	spec := gatewaySkins[idx]
	profile := GatewayProfile{
		Server:       spec.Server,
		TraceHdr:     spec.TraceHdr,
		ChallengeUrl: spec.ChallengeUrl,
		VerifyUrl:    spec.VerifyUrl,
	}
	profile.TraceVal = buildTraceVal(spec.TraceParts)
	// 两条内部路由取值在此归一：模板把它们直接渲染成 location，空串会让 nginx -t 挂掉。
	profile.Normalize()

	return profile
}

func buildTraceVal(parts []tracePart) string {
	var b strings.Builder
	for _, p := range parts {
		switch {
		case p.Hex > 0:
			writeRandChars(&b, hexChars, p.Hex)
		case p.AlphaNum > 0:
			writeRandChars(&b, alphaNumChars, p.AlphaNum)
		default:
			b.WriteString(p.Lit)
		}
	}
	return b.String()
}

func writeRandChars(b *strings.Builder, chars string, n int) {
	for i := 0; i < n; i++ {
		b.WriteByte(chars[rng.Intn(len(chars))])
	}
}
