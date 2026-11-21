package waf

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"cdn/internal/config"
)

// challengeCookieName 是强检测通过后写入客户端的验证凭证 Cookie 名称。
const challengeCookieName = "__cc_chk"

// challengeTTL 是挑战通过后的免验证有效期。
const challengeTTL = 30 * time.Minute

// ticketTTL 是验证票据（页面下发到提交验证之间）的有效期，够真人完成交互即可。
const ticketTTL = 5 * time.Minute

// shieldMinDwell 是 3 秒盾模式下，从票据签发到提交验证之间必须经过的最小时长。
const shieldMinDwell = 3 * time.Second

// interactiveMinDwell 是滑块/文字模式下的最小交互耗时，用于挡住瞬时脚本秒过。
const interactiveMinDwell = 800 * time.Millisecond

// 验证模式常量。空字符串等价于 ChallengeModeJS（无感，向后兼容）。
const (
	ChallengeModeJS     = "js"
	ChallengeModeShield = "shield"
	ChallengeModeSlider = "slider"
	ChallengeModeText   = "text"
)

// ── 签名密钥 ─────────────────────────────────────────────────────────
//
// 凭证 Cookie 与票据的 HMAC 密钥必须是「本部署独有、不随二进制分发」的随机密钥。
// 此前由 secure.DeriveKey（内置于每个二进制的静态 resourceKey）派生：任何拿到
// cdnedge/cdnpanel 二进制的人都能离线算出密钥，直接伪造 __cc_chk 凭证，绕过全部
// 人机验证并享受 VerifiedRPS 的宽松阈值——高级 CC 只需预先铸好每个 IP 的 Cookie。
//
// 现在：进程启动时默认生成一把随机密钥（未收到主控密钥的节点也不会退回可预测的值），
// 边缘再用 SetChallengeSecret 换成主控下发的部署级密钥，使同一部署的所有节点互认
// （用户在节点间漂移不必重复验证）。

// MinChallengeSecretLen 是部署密钥的最小字节数。
const MinChallengeSecretLen = 32

type challengeKeySet struct {
	cookie []byte
	ticket []byte
	id     string // 密钥指纹（sha256 前 8 字节 hex），仅用于日志/排障比对，不可逆推密钥
}

var challengeKeys atomic.Pointer[challengeKeySet]

func init() {
	buf := make([]byte, MinChallengeSecretLen)
	if _, err := rand.Read(buf); err != nil {
		// 拿不到随机数时宁可起不来，也不能用可预测的密钥签凭证。
		panic("waf: generate challenge key: " + err.Error())
	}
	challengeKeys.Store(newChallengeKeySet(buf))
}

func newChallengeKeySet(secret []byte) *challengeKeySet {
	derive := func(purpose string) []byte {
		mac := hmac.New(sha256.New, secret)
		mac.Write([]byte(purpose))
		return mac.Sum(nil)
	}
	sum := sha256.Sum256(secret)
	return &challengeKeySet{
		cookie: derive("cc-challenge"),
		ticket: derive("cc-ticket"),
		id:     hex.EncodeToString(sum[:8]),
	}
}

// SetChallengeSecret 用部署级密钥替换当前签名密钥。换钥后旧密钥签发的凭证/票据立即失效
// （用户重新验证一次）。密钥过短时返回错误并保持原密钥不变。
func SetChallengeSecret(secret []byte) error {
	if len(secret) < MinChallengeSecretLen {
		return fmt.Errorf("challenge secret too short: %d bytes, need >= %d", len(secret), MinChallengeSecretLen)
	}
	challengeKeys.Store(newChallengeKeySet(append([]byte(nil), secret...)))
	return nil
}

// ParseChallengeSecret 解析 hex 编码的部署密钥（主控下发与落盘均用此格式）。
func ParseChallengeSecret(s string) ([]byte, error) {
	b, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf("challenge secret is not hex: %w", err)
	}
	if len(b) < MinChallengeSecretLen {
		return nil, fmt.Errorf("challenge secret too short: %d bytes, need >= %d", len(b), MinChallengeSecretLen)
	}
	return b, nil
}

// ChallengeKeyID 返回当前密钥指纹，用于核对各节点是否已统一到主控密钥。
func ChallengeKeyID() string {
	return challengeKeys.Load().id
}

// 验证凭证绑定客户端地址的粒度。空字符串等价于 BindScopeIP（向后兼容）。
const (
	// BindScopeIP 绑定完整客户端 IP：最严，但客户端出口 IP 一变凭证立即失效。
	BindScopeIP = "ip"
	// BindScopeSubnet 绑定客户端所在网段（IPv4 /24、IPv6 /48）：容忍同一出口池内的
	// 地址漂移，同时仍然把凭证限制在一个网段内，无法被搬到任意其它网络复用。
	BindScopeSubnet = "subnet"
	// BindScopeNone 完全不绑地址：凭证只绑 host+UA 指纹。跨运营商漂移也不会失效，
	// 防复用完全依赖 UA 指纹 + 30 分钟 TTL，是三者中最松的一档。
	BindScopeNone = "none"
)

// bindingAddr 按 scope 把客户端 IP 折算成参与绑定的地址分量。
//
// 这是"真人反复收到验证页却进不去"的根治点：凭证绑定串里含客户端地址，而现实中大量
// 网络的出口地址会在请求之间漂移（CGNAT 出口池轮换、移动网络基站切换、多线路负载
// 均衡、家宽拨号重连、客户端挂代理）。绑完整 IP 时，任何一次漂移都会让 HMAC 校验
// 失败，用户被打回验证页；进去之后再漂移，就是无限挑战循环。
//
// 折算成网段是这里的折中：同一出口池的地址几乎总落在同一 /24（IPv6 同一 /48），
// 凭证在池内保持有效，但仍然无法搬到别的网络去用。scope 为 none 时不绑地址，
// 适用于跨运营商漂移（例如手机在 Wi-Fi 与蜂窝之间切换）的场景。
func bindingAddr(ip, scope string) string {
	switch scope {
	case BindScopeNone:
		return ""
	case BindScopeSubnet:
		parsed := net.ParseIP(ip)
		if parsed == nil {
			// 解析不出地址时退回原串：宁可绑得更严（等价于 BindScopeIP），
			// 也不能因为一个畸形输入把地址分量整体丢掉、退化成 BindScopeNone。
			return ip
		}
		if v4 := parsed.To4(); v4 != nil {
			return v4.Mask(net.CIDRMask(24, 32)).String() + "/24"
		}
		return parsed.Mask(net.CIDRMask(48, 128)).String() + "/48"
	default:
		return ip
	}
}

// bindingID 把域名、客户端地址与客户端指纹拼成绑定标识。指纹为空（不可用）时退化为
// 不含指纹分量，与既有"指纹不可用则跳过指纹检测"的回退语义一致。
//
// host 必须参与绑定：同一边缘节点承载多个域名，且 cookie 名固定、Path=/。若不绑域名，
// 攻击者只需在防护最松（例如未开强检测）的域名上过一次验证，就能把 cookie 手动带到
// 同节点其它域名上直接放行——防护等级最低的站点会成为所有站点的后门。
//
// 地址分量由 bindingAddr 按 scope 折算，可能为空串（BindScopeNone）。这里保留
// "host|addr" 的分隔符结构而不在 addr 为空时省略，是为了让不同 scope 产生的绑定串
// 天然互不相同：切换 scope 后旧凭证一律失效，不会出现一个按松粒度签发的凭证
// 在改回严粒度后仍然通过校验。
//
// 指纹缺失（客户端根本没带 User-Agent）时，地址分量不允许再被 scope 抹掉：
// 那样绑定串会塌成只剩 host，一条凭证对该域名下的所有客户端都有效，"要不要绑浏览器"
// 就变成了攻击者自己说了算（去掉 UA 即去掉全部绑定）。真实浏览器一定会带 UA，
// 所以这条兜底只作用于不带 UA 的脚本类客户端，不会误伤靠 scope=none 容忍漂移的真人。
func bindingID(host, ip, fp, scope string) string {
	addr := bindingAddr(ip, scope)
	if addr == "" && fp == "" {
		addr = bindingAddr(ip, BindScopeIP)
	}
	base := host + "|" + addr
	if fp == "" {
		return base
	}
	return base + "|" + fp
}

// ChallengeBindingFP 计算挑战凭证/票据绑定用的客户端指纹。
//
// 绑定指纹必须在"三种请求形态"下完全一致，否则签发和校验对不上会导致验证恒失败：
//  1. 内容请求（导航 GET，Tengine auth_request 子请求校验 Cookie）；
//  2. 挑战页请求（GET /edge-waf-challenge，签发票据）；
//  3. 验证提交（POST /__cc/verify，fetch，校验票据 + 签发 Cookie）。
//
// 这三种请求的 method、header 集合、顺序、sec-fetch-* 全都不同，因此绝不能用 JA4H
// （它的设计目的恰恰是刻画请求形态，跨这三种请求必然不同——历史上导致所有模式 403）。
// 这里改用请求形态无关的稳定量：User-Agent。UA 在同一浏览器的三种请求里保持一致，
// 又能提供"换浏览器即失效"的防复用穿透能力。ua 为空时返回空串，bindingID 退化为仅绑 IP。
//
// 注意：第三层 CC 指纹统计走的是另一条 X-Ja4h header 路径（用真实 method 的完整 JA4H），
// 与本绑定指纹互相独立，互不影响。
func ChallengeBindingFP(ua string) string {
	if ua == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(ua))
	return fmt.Sprintf("%x", sum[:])[:12]
}

// IssueChallengeCookie 为指定 域名+IP+指纹 签发一个带有效期的 HMAC 签名 Cookie。
// 无需服务端存储任何状态，同一部署的边缘节点用主控下发的同一把密钥独立签发和校验。
// 凭证绑定 host+ip+fp：换域名、换 IP 或换浏览器都会校验失败，防止 Cookie 被复用穿透。
//
// secure 表示当前站点是否以 HTTPS 提供服务：为 true 时给 Cookie 加 Secure 标志，
// 避免验证凭证在明文 HTTP 上被嗅探后重放。纯 HTTP 站点必须传 false，否则浏览器
// 根本不会回传该 Cookie，会导致验证通过后仍反复要求验证。
//
// 这是"完整证据链"档（ChallengeTierFull）的便捷入口；证据不足时改用 IssueChallengeCookieTier。
func IssueChallengeCookie(host, ip, fp string, secure bool, scope string) *http.Cookie {
	return IssueChallengeCookieTier(host, ip, fp, secure, scope, ChallengeTierFull)
}

// 凭证档位：区分"过了挑战并且拿到了浏览器环境证据"与"过了挑战但环境证据采不到"。
// 两者过去的待遇完全相同，于是 js 模式退化成"GET 一次挑战页 + POST 一次 verify"就能领到
// 30 分钟宽松配额凭证——零浏览器证据即可铸造，高级 CC 只要批量领好 Cookie 再打。
const (
	// ChallengeTierFull：票据、最小耗时、（可见模式）答案与环境证据齐备。
	ChallengeTierFull = ""
	// ChallengeTierWeak：主验证通过但 env 缺失/不可解。真实用户里确实有这一档
	// （老旧内核、隐私模式、缓存的旧挑战页），所以既不封禁也不再反复挑战，
	// 但不享受 verified_rps/verified_rpm 的宽松配额，有效期也从 30 分钟缩到 ticketTTL。
	ChallengeTierWeak = "w"
)

// IssueChallengeCookieTier 按档位签发凭证。
//
// 档位是签进 HMAC 输入里的，客户端改不动；全档的签名串与加档位之前逐字节一致，
// 所以滚动升级期间老节点签发的 Cookie 仍然被认，不会出现"升级即全站重新验证"。
func IssueChallengeCookieTier(host, ip, fp string, secure bool, scope, tier string) *http.Cookie {
	ttl := challengeTTL
	if tier == ChallengeTierWeak {
		ttl = ticketTTL
	}
	expiry := time.Now().Add(ttl).Unix()
	value := signChallenge(host, ip, fp, expiry, scope, tier)
	return &http.Cookie{
		Name:     challengeCookieName,
		Value:    value,
		Path:     "/",
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	}
}

// ChallengeCookieAbsent / ChallengeCookieMismatch 是 ChallengeCookieState 的两种取值。
const (
	ChallengeCookieAbsent   = "absent"
	ChallengeCookieMismatch = "mismatch"
)

// ChallengeCookieState 返回挑战 Cookie 在本次请求中的到达情况，仅用于发挑战时记日志排障。
//
// 反复收到验证页时，第一个要分清的问题是"浏览器根本没带 Cookie"还是"带了但绑定对不上"：
//   - absent：Cookie 没到边缘。方向是传输/属性问题——HTTP 站点却带了 Secure、
//     Path/域名不匹配、$http_cookie 没转发、浏览器禁用 Cookie。
//   - mismatch：Cookie 到了但签名校验失败。方向是绑定三元组 host|ip|fp 有分量在两次
//     请求之间变了——最常见的是双栈客户端在 IPv4/IPv6 之间切换导致 ip 变化。
//
// 两者的排查路径完全不同，不区分就只能靠猜。只在已判定需要挑战（校验未通过）时调用，
// 因此返回值只有这两种。
func ChallengeCookieState(cookieHeader string) string {
	if extractCookieValue(cookieHeader, challengeCookieName) == "" {
		return ChallengeCookieAbsent
	}
	return ChallengeCookieMismatch
}

// VerifyChallengeCookie 校验 Cookie 请求头中的挑战凭证对指定 域名+地址+指纹 是否有效且未过期。
// scope 必须与签发时使用的值一致（见 bindingAddr）。不区分档位，需要档位用 ChallengeCookieTier。
func VerifyChallengeCookie(host, ip, fp, cookieHeader, scope string) bool {
	_, ok := ChallengeCookieTier(host, ip, fp, cookieHeader, scope)
	return ok
}

// ChallengeCookieTier 返回凭证及其档位。
//
// 档位不是在 Cookie 里自带明文字段的：那样客户端可以自己写一个全档前缀领回宽松配额。
// 它进的是 HMAC 输入，所以这里对两个档位各算一次签名再比——每请求两次 HMAC-SHA256
// （输入不到 100 字节），相对这条路径上本来就要做的正则/WAF 判定可以忽略。
// 顺序是全档在前：绝大多数流量是全档，命中即返回。
func ChallengeCookieTier(host, ip, fp, cookieHeader, scope string) (string, bool) {
	if cookieHeader == "" {
		return ChallengeTierFull, false
	}
	value := extractCookieValue(cookieHeader, challengeCookieName)
	if value == "" {
		return ChallengeTierFull, false
	}
	parts := strings.SplitN(value, ".", 2)
	if len(parts) != 2 {
		return ChallengeTierFull, false
	}
	expiry, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return ChallengeTierFull, false
	}
	if time.Now().Unix() > expiry {
		return ChallengeTierFull, false
	}
	for _, tier := range []string{ChallengeTierFull, ChallengeTierWeak} {
		expected := signChallenge(host, ip, fp, expiry, scope, tier)
		if hmac.Equal([]byte(value), []byte(expected)) {
			return tier, true
		}
	}
	return ChallengeTierFull, false
}

func signChallenge(host, ip, fp string, expiry int64, scope, tier string) string {
	mac := hmac.New(sha256.New, challengeKeys.Load().cookie)
	// 全档的 HMAC 输入保持加档位之前的原样（bindingID|expiry），这样老节点/新版本互认，
	// 也让线上已经发出去的全档凭证不必重新签发。
	if tier == ChallengeTierFull {
		fmt.Fprintf(mac, "%s|%d", bindingID(host, ip, fp, scope), expiry)
	} else {
		fmt.Fprintf(mac, "%s|%s|%d", bindingID(host, ip, fp, scope), tier, expiry)
	}
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return strconv.FormatInt(expiry, 10) + "." + sig
}

// ── 验证票据 ─────────────────────────────────────────────────────────
// 票据是可见验证模式下，挑战页与提交验证之间传递的一次性无状态凭证。
// 格式：base64(payloadJSON) + "." + HMAC。payload 绑定 mode+host+ip+fp+签发时间+答案。

type challengeTicket struct {
	Mode     string `json:"m"`
	Binding  string `json:"b"` // host|ip|fp
	IssuedAt int64  `json:"t"` // 签发时间（Unix 秒）
	Answer   string `json:"a"` // text 模式的期望答案；其余模式为空
}

// IssueChallengeTicket 生成绑定 mode+host+地址+fp 的签名票据。answer 仅在 text 模式有意义。
// scope 决定地址分量的粒度，须与 VerifyChallengeTicket 一致。
func IssueChallengeTicket(mode, host, ip, fp, answer, scope string) string {
	t := challengeTicket{
		Mode:     mode,
		Binding:  bindingID(host, ip, fp, scope),
		IssuedAt: time.Now().Unix(),
		Answer:   answer,
	}
	payload, _ := json.Marshal(t)
	b64 := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, challengeKeys.Load().ticket)
	mac.Write([]byte(b64))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return b64 + "." + sig
}

// VerifyChallengeTicket 校验票据签名、绑定（mode/host/地址/fp）与有效期。
// 返回票据里记录的期望答案与签发时间，供调用方做答案校验与最小耗时判断。
// scope 必须与 IssueChallengeTicket 使用的值一致。
func VerifyChallengeTicket(ticket, mode, host, ip, fp, scope string) (answer string, issuedAt time.Time, ok bool) {
	parts := strings.SplitN(ticket, ".", 2)
	if len(parts) != 2 {
		return "", time.Time{}, false
	}
	mac := hmac.New(sha256.New, challengeKeys.Load().ticket)
	mac.Write([]byte(parts[0]))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(parts[1]), []byte(expectedSig)) {
		return "", time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", time.Time{}, false
	}
	var t challengeTicket
	if err := json.Unmarshal(payload, &t); err != nil {
		return "", time.Time{}, false
	}
	if t.Mode != mode || t.Binding != bindingID(host, ip, fp, scope) {
		return "", time.Time{}, false
	}
	issued := time.Unix(t.IssuedAt, 0)
	if time.Since(issued) > ticketTTL {
		return "", time.Time{}, false
	}
	return t.Answer, issued, true
}

// NewArithChallenge 生成一道简单加法算术题，返回题面与期望答案字符串。
func NewArithChallenge() (question, answer string) {
	a := randInt(10, 40)
	b := randInt(10, 40)
	return fmt.Sprintf("%d + %d = ?", a, b), strconv.Itoa(a + b)
}

// randInt 返回 [min, max] 区间内的随机整数（含端点）。crypto/rand 失败时回退到 min。
func randInt(min, max int) int {
	if max <= min {
		return min
	}
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max-min+1)))
	if err != nil {
		return min
	}
	return min + int(n.Int64())
}

// extractCookieValue 从原始 Cookie 请求头字符串中提取指定 name 的值（不依赖 *http.Request）。
func extractCookieValue(cookieHeader, name string) string {
	for _, part := range strings.Split(cookieHeader, ";") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 && kv[0] == name {
			return kv[1]
		}
	}
	return ""
}

// ChallengePageHTML 已废弃：旧版无感模式直接在服务端预发 Cookie + 纯跳转页，不采集环境，
// headless 浏览器能直接穿透。现在所有模式（含无感 js）统一由 InteractiveChallengePageHTML
// 渲染，采集环境并经 /__cc/verify 评分后才下发 Cookie。保留本函数仅为兼容旧调用方，
// 内部转调 InteractiveChallengePageHTML（ticket/question 由调用方另行提供时才有意义，
// 这里为空表示无法直接使用——请改调 InteractiveChallengePageHTML）。
//
// Deprecated: 使用 InteractiveChallengePageHTML。
func ChallengePageHTML(mode, redirectURL string) string {
	// 无 ticket 无法完成 verify 流程，返回一个纯跳转兜底页仅用于极端兼容场景。
	safeURL, err := json.Marshal(redirectURL)
	if err != nil {
		safeURL = []byte(`"/"`)
	}
	return `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Security Check</title></head>
<body>
<script>setTimeout(function(){ location.href = ` + string(safeURL) + `; }, 600);</script>
<noscript>Please enable JavaScript to continue.</noscript>
</body></html>`
}

// jsMinDwell 是无感 js 模式的最小耗时门槛。挑战页的收尾脚本固定 loadNextChunk(300, "")，
// 也就是真人最快也要 300ms + 两个单程网络才会提交；取 150ms 留出一半余量，
// 挡住"GET 挑战页拿到票据就立刻 POST"的批量脚本——那一条路径过去完全没有下限，
// 领一份 30 分钟宽松配额凭证的成本是两次 HTTP 往返。
const jsMinDwell = 150 * time.Millisecond

// MinDwellForMode 返回指定模式下从票据签发到提交验证之间必须经过的最小时长。
// default 分支覆盖无感 js 模式与未识别的模式取值（未识别时页面仍按 js 收尾，门槛一致）。
func MinDwellForMode(mode string) time.Duration {
	switch mode {
	case ChallengeModeShield:
		return shieldMinDwell
	case ChallengeModeSlider, ChallengeModeText:
		return interactiveMinDwell
	default:
		return jsMinDwell
	}
}

// InteractiveChallengePageHTML 渲染纯英文人机验证等待页（无皮肤上下文的历史签名）。
//
// 页面骨架、状态行文案、内联脚本都在 challenge_skin.go；这里保留旧签名，交给零值皮肤，
// 于是渲染为 gateway 家族 + 默认 verify 路径，与升级前的线上行为等价。
// 需要按域名皮肤自适应的调用方请改用 ChallengePageHTMLForSkin。
func InteractiveChallengePageHTML(mode, redirectURL, ticket, question string) string {
	return ChallengePageHTMLForSkin(config.GatewayProfile{}, mode, redirectURL, ticket, question)
}
