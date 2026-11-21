package waf

import (
	"encoding/json"
	"regexp"
	"strings"

	"cdn/internal/config"
)

// ── 皮肤自适应等待页 ──────────────────────────────────────────────
//
// 本文件负责把"CC 强检测触发 401 后下发的人机验证等待页"按当前域名的网关皮肤
// （config.GatewayProfile.Server）渲染成两种不同形态的纯英文页面：
//   - framework 家族（Vercel/Netlify/Render/Deno/Fly 等边缘运行时）：表现为现代前端应用
//     仍在初始化/hydration 的标准业务等待页，配对应的纯英文运行时状态行；
//   - gateway 家族（nginx/Apache/Caddy/HAProxy 与传统 CDN 边缘、安全设备）：表现为轻量的
//     上游连接/多路复用握手状态页。
//
// 页面里出现的每一个字节都是纯 ASCII 英文：不含中文、不含中文本地化字体栈、
// html lang 固定为 en。这是本模块对外的硬约束，改动模板后请用
// go test ./internal/waf/ -run TestChallengePage 自检。

// SkinFamily 是等待页的两种渲染家族。
const (
	SkinFamilyFramework = "framework"
	SkinFamilyGateway   = "gateway"
)

// frameworkRuntimeRe 识别"边缘运行时/PaaS"类皮肤名。命中即走 framework 家族，
// 其余（开源反代、传统 CDN、安全设备）走 gateway 家族。
//
// 这里只匹配皮肤名本身，不注入任何真实厂商的商标、框架名或静态资源路径：
// 页面"像现代前端应用在加载"靠的是骨架屏 + hydration 式状态行 + 内联 manifest 这些
// 通用形态，而不是把 /_next/ 这类真实路径写进 HTML —— 后者既构成对第三方品牌的冒名，
// 也会在浏览器真的去请求该路径时打回 origin，被 auth_request 再次拦成 401 形成回环。
var frameworkRuntimeRe = regexp.MustCompile(`(?i)\b(vercel|netlify|render|deno|fly\.io|workers\.dev|edge\.runtime)\b`)

// SkinFamily 返回该 Server 皮肤对应的渲染家族；未知/空皮肤归为 gateway。
func SkinFamily(server string) string {
	if frameworkRuntimeRe.MatchString(strings.TrimSpace(server)) {
		return SkinFamilyFramework
	}
	return SkinFamilyGateway
}

// gatewayProfileRe 从皮肤名里提取可展示的运行时标识（仅取展示安全的字符，其余丢弃），
// 用于页面上的运行时标注；皮肤名来自主控配置而非客户端输入，这里仍按不可信处理。
// 允许 `:` 是因为厂商 trace 值本身带冒号分隔（如 Cloudflare 的 id-FRA、Vercel 的 region::id），
// 而它只出现在 HTML 文本节点与 JSON 字符串值里，引号与尖括号已被剔除，无法借此逃出上下文。
var gatewayProfileRe = regexp.MustCompile(`[^A-Za-z0-9._+@/: -]`)

func sanitizeLabel(s string) string {
	s = gatewayProfileRe.ReplaceAllString(strings.TrimSpace(s), "")
	if len(s) > 48 {
		s = s[:48]
	}
	return s
}

// 等待期间依次展示的状态行（纯英文）。第一行同时作为 <noscript> 之外的首屏文案。
var frameworkBootSteps = []string{
	"Initializing web runtime context...",
	"Loading framework chunk dependency...",
	"Restoring hydration state...",
	"Finalizing client runtime...",
}

var gatewayBootSteps = []string{
	"Opening upstream connection...",
	"Negotiating multiplexed stream...",
	"Awaiting gateway handshake confirmation...",
	"Session ready...",
}

// bootUI 是各验证模式在页面主体里插入的交互块（纯英文）。
// js/shield 家族不额外插 UI：骨架屏/脉冲指示本身就是等待态视觉。
func bootUI(mode string) string {
	switch mode {
	case ChallengeModeSlider:
		return `<div class="cf-track" id="track"><div class="cf-handle" id="handle" aria-label="Slide to continue">&#8594;</div><div class="cf-track-hint" id="trackhint">Slide to the right</div></div>`
	case ChallengeModeText:
		return `<p class="cf-question" id="q">&nbsp;</p>
<input class="cf-input" id="ans" type="text" inputmode="numeric" autocomplete="off" aria-label="Answer" placeholder="Enter the result" />
<button class="cf-btn" id="submit" type="button">Continue</button>
<p class="cf-error" id="err" role="alert">&nbsp;</p>`
	default:
		return ""
	}
}

// bootSkeleton 只为 framework 家族产出骨架屏占位条——它是现代前端应用在 hydration 期间
// 最典型的视觉。gateway 家族返回空串：设备/反代状态页不会画骨架屏，画了就和 Server 皮肤自相矛盾。
func bootSkeleton(family string) string {
	if family != SkinFamilyFramework {
		return ""
	}
	return `<div class="cf-skel" aria-hidden="true"><i></i><i></i><i></i></div>`
}

// ChallengePageHTMLForSkin 按当前网关皮肤渲染人机验证等待页。
//
// mode 为空或未知时归一为无感 js（与历史行为一致）；ticket 已绑定 host+地址+指纹；
// question 仅 text 模式使用。verify 提交地址取自 profile.VerifyUrl。
//
// 容错（fail-open）：本函数在任何 panic 下都返回一个仍然可用的纯净等待页 —— 它照旧采集
// 并提交凭证，只是不带皮肤定制。注意 fail-open 的对象是"网关 worker 不能因为渲染异常而
// 卡住/500"，不是"把请求放行"：兜底页同样必须过一次 verify 才能拿到 Cookie。若这里改成
// 直接跳转 RESUME，等于给强检测开了一个"触发异常即绕过"的后门。
func ChallengePageHTMLForSkin(profile config.GatewayProfile, mode, redirectURL, ticket, question string) (page string) {
	// 兜底页先行赋值：defer  recover 命中时直接返回它，不依赖任何模板拼装成功。
	page = challengeFallbackPage(profile, redirectURL, ticket)
	defer func() {
		if r := recover(); r != nil {
			page = challengeFallbackPage(profile, redirectURL, ticket)
		}
	}()

	if mode == "" {
		mode = ChallengeModeJS
	}
	family := SkinFamily(profile.Server)
	steps := gatewayBootSteps
	if family == SkinFamilyFramework {
		steps = frameworkBootSteps
	}

	return strings.NewReplacer(
		"@@TITLE@@", bootTitle(family, mode),
		"@@RUNTIME@@", bootTitle(family, mode),
		"@@STATUS@@", bootTextLine(mode),
		"@@STEPS@@", jsonStringSlice(steps),
		"@@LABEL@@", sanitizeLabel(profile.Server),
		"@@TRACE_HDR@@", sanitizeLabel(profile.TraceHdr),
		"@@TRACE_VAL@@", sanitizeLabel(profile.TraceVal),
		"@@MANIFEST@@", bootManifestJSON(profile, family),
		"@@UI@@", bootUI(mode),
		"@@SKELETON@@", bootSkeleton(family),
		"@@CSS@@", bootCSS(family),
		"@@SCRIPT@@", bootScript(profile, mode, redirectURL, ticket, question),
		"@@NOSCRIPT@@", "Enable JavaScript in your browser to continue.",
	).Replace(skinPageSkeleton)
}

// bootTitle 是页面标题与主标。
//
// 这里必须按模式分档，而不是让四种模式共用一个"正在加载"的标题：js/shield 是无感或纯等待，
// 页面确实可以表现为运行时初始化；但 slider/text 天然要露出题目或滑块，
// 此时标题若还写"Loading / Establishing session"，页面就自相矛盾了——
// 自适应伪装只在无感与 3 秒盾两种模式下成立，这是形态本身的限制，不是实现没做到。
func bootTitle(family, mode string) string {
	if mode == ChallengeModeSlider || mode == ChallengeModeText {
		return "Confirm to continue"
	}
	if family == SkinFamilyFramework {
		return "Loading"
	}
	return "Establishing session"
}

// bootTextLine 是首屏静态文案：无感模式不承诺可见进度，text 模式直接让位于题目。
func bootTextLine(mode string) string {
	switch mode {
	case ChallengeModeText:
		return "Please answer the question to continue."
	case ChallengeModeSlider:
		return "Complete the verification to continue."
	default:
		return "Verifying your browser environment..."
	}
}

// bootManifestJSON 生成页面内联的运行时清单。
//
// 这块 JSON 只是给"读源码的人"看的形态信号：浏览器不会真的去请求里面的任何路径——
// 一旦页面里出现带 src/href 的假资源，请求会打回 origin 被 auth_request 再判一次 401，
// 形成资源加载回环并且白占 CC 额度。所以它必须与家族自洽：gateway 家族里不能出现
// hydration 这种框架术语，否则页面形态就自己跟自己矛盾。
// 所有取值都先过 sanitizeLabel（剔除尖括号与引号），因此无法从中逃出 script 上下文。
func bootManifestJSON(profile config.GatewayProfile, family string) string {
	manifest := map[string]string{
		"stage":    "session_init",
		"channel":  chunkBaseFor(profile, family),
		"upstream": sanitizeLabel(profile.Server),
	}
	if family == SkinFamilyFramework {
		manifest = map[string]string{
			"stage":   "hydration",
			"base":    chunkBaseFor(profile, family),
			"runtime": sanitizeLabel(profile.Server),
		}
	}
	b, err := json.Marshal(manifest)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// chunkBaseFor 取皮肤的挑战路径作为等待页 manifest 的展示 base。
//
// 这个字段现在身兼两职：模板里它是 401 内部跳转真正落的 location，页面里它只是 manifest 的
// 一个字符串值。两者取值一致才对得上——所以这里直接透传，不再另编一个"组件路径"。
// 零值皮肤（历史签名 shim）取不到合法值时按家族回落到中性展示路径。
func chunkBaseFor(profile config.GatewayProfile, family string) string {
	if config.IsSafeLocationPath(profile.ChallengeUrl) {
		return profile.ChallengeUrl
	}
	if family == SkinFamilyFramework {
		return "/static/runtime"
	}
	return "/edge/state"
}

// resolveVerifyURL 决定 JS 提交凭证的目标地址。
//
// 这个值必须与模板里 `location = {{ .GatewayProfile.VerifyUrl }}` 渲染出来的路径逐字相同，
// 否则 POST 落进 location / 被 auth_request 再判一次 401，用户做完验证也拿不到 Cookie。
// 两边现在共用 config.IsSafeLocationPath 判定、共用 config.DefaultVerifyPath 兜底，
// 不存在"一边写了默认值、另一边渲染成空串"的可能。零值皮肤（历史签名 shim）同样归到默认值。
func resolveVerifyURL(profile config.GatewayProfile) string {
	if config.IsSafeLocationPath(profile.VerifyUrl) {
		return profile.VerifyUrl
	}
	return config.DefaultVerifyPath
}

func challengeFallbackPage(profile config.GatewayProfile, redirectURL, ticket string) string {
	resume, err := json.Marshal(redirectURL)
	if err != nil {
		resume = []byte(`"/"`)
	}
	tk, err := json.Marshal(ticket)
	if err != nil {
		tk = []byte(`""`)
	}
	verify, err := json.Marshal(resolveVerifyURL(profile))
	if err != nil {
		verify = []byte(`"/__cc/verify"`)
	}
	return fallbackPageSkeleton + "\nvar RESUME=" + string(resume) +
		",HANDLE=" + string(tk) +
		",VERIFY_URL=" + string(verify) + ";" + fallbackInlineJS + "\n</script></body></html>"
}

const fallbackPageSkeleton = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>Loading</title>
<style>body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;background:#f5f7fa;color:#243049;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}.cf-card{background:#fff;border:1px solid #e3e8f0;border-radius:12px;padding:36px 44px;text-align:center;min-width:300px}.cf-dot{width:42px;height:42px;margin:0 auto 16px;border:3px solid #dfe7f3;border-top-color:#2f6fed;border-radius:50%;animation cf .8s linear infinite}@keyframes cf{to{transform:rotate(360deg)}}.cf-line{font-size:15px;color:#5a6a85}</style>
</head><body><div class="cf-card"><div class="cf-dot"></div><p class="cf-line">Verifying your browser environment...</p></div>
<script>`

// fallbackInlineJS 是兜底页的最小闭环：仍然采集凭证并提交，绝不因为渲染降级而放行。
// 与 bootScript 共用同一套 wire 字段名（ticket/env），服务端评分逻辑无需分叉。
const fallbackInlineJS = `
(function(){"use strict";
function env(){
  var e={webdriver:!!(navigator&&navigator.webdriver),ua_headless:/Headless/i.test(navigator.userAgent||""),
  sw:(screen&&screen.width)||0,sh:(screen&&screen.height)||0,ua:navigator.userAgent||"",
  elapsed:0,canvas:"",webgl_v:"",webgl_r:"",tz:"",mouse:0,kb:0,focus:true,plugins:0,languages:0,perms:""};
  try{return btoa(unescape(encodeURIComponent(JSON.stringify(e))));}catch(x){return "";}
}
setTimeout(function(){
  fetch(VERIFY_URL,{method:"POST",headers:{"Content-Type":"application/json"},credentials:"same-origin",
  body:JSON.stringify({ticket:HANDLE,answer:"",env:env()})}).then(function(r){
    if(r.ok){location.href=RESUME;return;}
    setTimeout(function(){location.reload();},1500);
  }).catch(function(){setTimeout(function(){location.reload();},1500);});
},400);})();`

// skinPageSkeleton 是两个家族共用的页面外壳；@@CSS@@/@@UI@@/@@SCRIPT@@ 决定差异表现。
const skinPageSkeleton = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title>@@TITLE@@</title>
<style>@@CSS@@</style>
</head>
<body>
<main class="cf-root">
<section class="cf-shell">
<div class="cf-mark" aria-hidden="true"></div>
<h1 class="cf-heading">@@RUNTIME@@</h1>
<p class="cf-status" id="status-line">@@STATUS@@</p>
@@SKELETON@@
<div class="cf-ui">@@UI@@</div>
<footer class="cf-meta"><span>runtime</span> <b>@@LABEL@@</b><span>ref</span> <b>@@TRACE_HDR@@=@@TRACE_VAL@@</b></footer>
</section>
</main>
<script type="application/json" id="runtime-manifest">@@MANIFEST@@</script>
<script>@@SCRIPT@@</script>
<noscript>@@NOSCRIPT@@</noscript>
</body>
</html>`

// bootCSS 按家族给出两套观感：framework 家族用骨架屏微光（现代应用加载中最典型的视觉），
// gateway 家族用单点脉冲 + 等宽状态（设备状态页的观感）。字体栈一律为国际通用栈，
// 不含 PingFang/Microsoft YaHei 之类中文本地化字体——那本身就是地域特征。
func bootCSS(family string) string {
	base := `*{box-sizing:border-box}
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif;background:#f5f7fa;color:#243049;min-height:100vh;display:flex;align-items:center;justify-content:center}
.cf-root{width:100%;max-width:520px;padding:24px}
.cf-shell{background:#fff;border:1px solid #e3e8f0;border-radius:14px;padding:38px 42px;box-shadow:0 10px 32px rgba(35,58,92,.07)}
.cf-heading{margin:0 0 10px;font-size:17px;font-weight:600;letter-spacing:-.01em;color:#1d2b45}
.cf-status{margin:0;font-size:14px;line-height:1.6;color:#65758f;min-height:20px}
.cf-meta{margin-top:26px;padding-top:14px;border-top:1px solid #eef2f7;display:flex;flex-wrap:wrap;gap:4px 10px;font-size:11px;color:#93a1b5;letter-spacing:.02em}
.cf-meta b{font-weight:500;font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;color:#7b8aa0;word-break:break-all}
.cf-ui{margin-top:22px}
.cf-track{position:relative;height:44px;background:#f2f6fd;border:1px solid #dfe8f6;border-radius:9px;overflow:hidden;user-select:none;touch-action:none}
.cf-handle{position:absolute;left:0;top:0;width:44px;height:44px;background:#2f6fed;color:#fff;border-radius:9px;display:flex;align-items:center;justify-content:center;cursor:grab;font-size:17px;z-index:2}
.cf-track-hint{position:absolute;inset:0;display:flex;align-items:center;justify-content:center;color:#98a6bc;font-size:13px}
.cf-question{margin:0 0 14px;font-size:20px;font-weight:600;color:#1f4fd0}
.cf-input{width:100%;padding:10px 12px;font-size:15px;text-align:center;border:1px solid #dfe8f6;border-radius:9px;outline:none;color:#243049;background:#fff}
.cf-input:focus{border-color:#2f6fed}
.cf-btn{margin-top:12px;width:100%;padding:11px;font-size:15px;border:0;border-radius:9px;background:#2f6fed;color:#fff;cursor:pointer}
.cf-btn:disabled{opacity:.6;cursor:progress}
.cf-error{margin:10px 0 0;font-size:13px;color:#c8322d;min-height:18px}`

	if family == SkinFamilyFramework {
		return base + `
.cf-mark{width:132px;height:12px;margin:0 auto 22px;border-radius:6px;background:linear-gradient(90deg,#e9eef7 25%,#f6f9fd 37%,#e9eef7 63%);background-size:400% 100%;animation cf-shimmer 1.4s ease-in-out infinite}
.cf-skel{margin:20px auto 0;display:flex;flex-direction:column;gap:10px;align-items:center}
.cf-skel i{display:block;height:9px;border-radius:5px;background:linear-gradient(90deg,#eef2f8 25%,#f8fafd 37%,#eef2f8 63%);background-size:400% 100%;animation cf-shimmer 1.6s ease-in-out infinite}
.cf-skel i:nth-child(1){width:70%}.cf-skel i:nth-child(2){width:52%}.cf-skel i:nth-child(3){width:62%}
@keyframes cf-shimmer{0%{background-position:100% 50%}100%{background-position:0 50%}}`
	}
	return base + `
.cf-mark{width:14px;height:14px;margin:0 0 18px;border-radius:50%;background:#2f6fed;box-shadow:0 0 0 0 rgba(47,111,237,.45);animation cf-pulse 1.6s ease-out infinite}
.cf-status{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
@keyframes cf-pulse{0%{box-shadow:0 0 0 0 rgba(47,111,237,.45)}70%{box-shadow:0 0 0 14px rgba(47,111,237,0)}100%{box-shadow:0 0 0 0 rgba(47,111,237,0)}}`
}

// jsonStringSlice 把状态行数组序列化成 JS 数组字面量（纯英文，走 encoding/json 保证转义）。
func jsonStringSlice(items []string) string {
	b, err := json.Marshal(items)
	if err != nil || len(b) == 0 {
		return `[]`
	}
	return string(b)
}

func jsonLiteral(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		return `""`
	}
	return string(b)
}

// bootScript 生成页面内联脚本：环境采集 + 皮肤自适应状态推进 + 按模式提交凭证。
//
// 关于"深度混淆"的边界，需要如实说明：改名只动 JS 的函数名/局部变量名，wire 上的三个
// JSON 字段名（ticket / answer / env）、env 内部的环境键名（webdriver、ua_headless、
// missing_chrome…）、Cookie 名 __cc_chk 和 verify 路径全部保持原样。原因是它们必须与
// internal/edgeapi/handler.go 的 body struct tag 和 internal/waf/shield_scorer.go 的
// ShieldEnv tag 逐字对齐，改一边就验不过。
//
// 而这几个恰恰才是逆向者一眼能读出来的东西：JS 局部名跑一次 prettier 就没了意义，
// env 是 base64(JSON)，抓包后一行解码就能看到整份自动化检测清单。要真去掉这些特征，
// 得三处一起改（前端键名 + handler tag + ShieldEnv tag + Cookie 名 + Tengine location），
// 并留一个版本窗口让旧页面继续可校验。那一版我可以接着做，但必须整套走。
func bootScript(profile config.GatewayProfile, mode, redirectURL, ticket, question string) string {
	family := SkinFamily(profile.Server)
	steps := gatewayBootSteps
	if family == SkinFamilyFramework {
		steps = frameworkBootSteps
	}
	return strings.NewReplacer(
		"@@VERIFY@@", jsonLiteral(resolveVerifyURL(profile)),
		"@@RESUME@@", jsonLiteral(redirectURL),
		"@@HANDLE@@", jsonLiteral(ticket),
		"@@PROMPT@@", jsonLiteral(question),
		"@@STEPS@@", jsonStringSlice(steps),
		"@@TRACE@@", jsonLiteral(bootTracePrefix(profile, family)),
		"@@RETRY@@", jsonLiteral("Connection interrupted, retrying..."),
		"@@BUSY@@", jsonLiteral("Validating session..."),
		"@@DRIVER@@", modeDriverJS(mode, family),
	).Replace(bootCoreJS)
}

// bootTracePrefix 给页面日志加一个与皮肤一致的标签前缀，
// 使其在控制台上读起来像运行时自身的启动日志。
func bootTracePrefix(profile config.GatewayProfile, family string) string {
	label := sanitizeLabel(profile.Server)
	if label == "" {
		label = "edge"
	}
	if family == SkinFamilyFramework {
		return "[" + label + " runtime]"
	}
	return "[" + label + "]"
}

// modeDriverJS 是各模式的收尾逻辑。这里的时序常量必须与服务端 MinDwellForMode 对齐：
// shield 3200ms > 服务端要求 3s；js 300ms > 服务端要求 150ms；slider/text 的真实交互耗时天然 > 800ms。
// 改这里的任何延时都必须同步看 MinDwellForMode：延时若小于服务端门槛，真人会被判"验证太快"反复打回。
func modeDriverJS(mode, family string) string {
	switch mode {
	case ChallengeModeSlider:
		return sliderDriverJS
	case ChallengeModeText:
		return textDriverJS
	case ChallengeModeShield:
		// 3 秒可见等待期内静默采集信号；这一步的耗时是服务端 dwell 校验的硬门槛。
		return "\nadvanceBootSteps();\nloadNextChunk(" + shieldDelayFor(family) + ", \"\");"
	default:
		// 无感模式：等一帧让 pointer/focus 等初始信号落进采集窗口再提交。
		return "\nloadNextChunk(300, \"\");"
	}
}

// shieldDelayFor：framework 家族的骨架屏进度走完约 3.2s；gateway 家族状态行短，
// 但 dwell 门槛相同，统一留 3200ms，不因皮肤不同而放松校验。
func shieldDelayFor(_ string) string { return "3200" }

const sliderDriverJS = `
(function(){
  var track=document.getElementById("track"),handle=document.getElementById("handle"),hint=document.getElementById("trackhint");
  if(!track||!handle){loadNextChunk(300,"");return;}
  var dragging=false,startX=0,maxX=0,locked=false;
  function xOf(e){return (e.touches&&e.touches[0]?e.touches[0].clientX:e.clientX);}
  function down(e){if(locked)return;dragging=true;startX=xOf(e)-handle.offsetLeft;maxX=track.clientWidth-handle.offsetWidth;}
  function move(e){
    if(!dragging||locked)return;
    var x=xOf(e)-startX;if(x<0)x=0;if(x>maxX)x=maxX;
    handle.style.left=x+"px";
    if(x>=maxX-2){
      locked=true;dragging=false;if(hint){hint.textContent=BUSY;}
      reportAnalyticsMetric("").catch(function(){locked=false;handle.style.left="0px";scheduleHydrationRetry();});
    }
  }
  function up(){dragging=false;if(!locked)handle.style.left="0px";}
  handle.addEventListener("mousedown",down);document.addEventListener("mousemove",move);document.addEventListener("mouseup",up);
  handle.addEventListener("touchstart",down,{passive:true});document.addEventListener("touchmove",move,{passive:false});document.addEventListener("touchend",up);
})();`

const textDriverJS = `
(function(){
  var q=document.getElementById("q"),btn=document.getElementById("submit"),inp=document.getElementById("ans"),err=document.getElementById("err");
  if(!q||!btn||!inp){loadNextChunk(300,"");return;}
  q.textContent=PROMPT;
  function go(){
    err.textContent="";btn.disabled=true;
    reportAnalyticsMetric((inp.value||"").trim()).catch(function(){
      err.textContent="Answer not accepted, try again.";btn.disabled=false;
    });
  }
  btn.addEventListener("click",go);
  inp.addEventListener("keydown",function(e){if(e.key==="Enter")go();});
})();`

// bootCoreJS 是采集与提交主体。命名一律采用埋点/性能/分包加载语义，
// 并且整体收在 IIFE 内——不再向 window 暴露 CC_* 全局，全局名本身也是可枚举的特征。
//
// 采集字段与语义与升级前完全一致（同一个 ShieldEnv 结构在评分），
// 只改了 JS 侧的可读标识；canvas 上的绘制文本也从原来带 emoji 转义的串换成纯 ASCII 标记。
const bootCoreJS = `
(function(){"use strict";
var VERIFY_URL=@@VERIFY@@;
var RESUME=@@RESUME@@;
var HANDLE=@@HANDLE@@;
var PROMPT=@@PROMPT@@;
var BUSY=@@BUSY@@;
var TRACE=@@TRACE@@;
var CHUNK_STEPS=@@STEPS@@;
var RETRY_MESSAGE=@@RETRY@@;
var bootStartedAt=Date.now();
var interaction={pointer:0,typing:0,focused:(document.hasFocus?document.hasFocus():true)};
window.addEventListener("mousemove",function(){interaction.pointer++;},{passive:true});
window.addEventListener("keydown",function(){interaction.typing++;},{passive:true});
window.addEventListener("focus",function(){interaction.focused=true;});
window.addEventListener("blur",function(){interaction.focused=false;});
function writeBootTrace(message){try{if(console&&console.log){console.log(TRACE+" "+message);}}catch(e){}}
function showBootStatus(message){
  var el=document.getElementById("status-line");
  if(el){el.textContent=message;}
  writeBootTrace(message);
}
function advanceBootSteps(){
  var i=0,dwell=Math.max(400,Math.floor(3200/Math.max(1,CHUNK_STEPS.length)));
  (function tick(){
    if(i<CHUNK_STEPS.length){showBootStatus(CHUNK_STEPS[i++]);setTimeout(tick,dwell);}
  })();
}
function measureRenderSignature(){
  try{
    var canvas=document.createElement("canvas");canvas.width=200;canvas.height=40;
    var ctx=canvas.getContext("2d");if(!ctx)return "";
    ctx.textBaseline="top";ctx.font="14px Arial";
    ctx.fillStyle="#f60";ctx.fillRect(0,0,200,40);
    ctx.fillStyle="#069";ctx.fillText("edge-telemetry-baseline",2,2);
    var data=canvas.toDataURL(),h=0;
    for(var i=0;i<data.length;i++){h=(h*31+data.charCodeAt(i))|0;}
    return (h>>>0).toString(16);
  }catch(e){return "";}
}
function readContextCapability(){
  try{
    var canvas=document.createElement("canvas");
    var gl=canvas.getContext("webgl")||canvas.getContext("experimental-webgl");
    if(!gl)return ["",""];
    var ext=gl.getExtension("WEBGL_debug_renderer_info");
    return ext?[gl.getParameter(ext.UNMASKED_VENDOR_WEBGL)||"",gl.getParameter(ext.UNMASKED_RENDERER_WEBGL)||""]:["",""];
  }catch(e){return ["",""];}
}
function buildTelemetryPayload(){
  var capability=readContextCapability();
  var sample={
    webdriver:!!(navigator&&navigator.webdriver),
    ua_headless:/HeadlessChrome|PhantomJS|Selenium|Puppeteer|Playwright/i.test(navigator.userAgent||""),
    missing_chrome:/Chrome\//.test(navigator.userAgent||"")&&typeof window.chrome==="undefined",
    plugins:(navigator.plugins&&navigator.plugins.length)||0,
    languages:(navigator.languages&&navigator.languages.length)||0,
    perms:"",
    sw:(screen&&screen.width)||0,
    sh:(screen&&screen.height)||0,
    canvas:measureRenderSignature(),
    webgl_v:capability[0],
    webgl_r:capability[1],
    tz:(Intl&&Intl.DateTimeFormat)?(Intl.DateTimeFormat().resolvedOptions().timeZone||""):"",
    mouse:interaction.pointer,
    kb:interaction.typing,
    focus:!!interaction.focused,
    elapsed:Date.now()-bootStartedAt,
    ua:navigator.userAgent||""
  };
  try{return btoa(unescape(encodeURIComponent(JSON.stringify(sample))));}catch(e){return "";}
}
function reportAnalyticsMetric(answer){
  return fetch(VERIFY_URL,{
    method:"POST",
    headers:{"Content-Type":"application/json"},
    credentials:"same-origin",
    body:JSON.stringify({ticket:HANDLE,answer:answer||"",env:buildTelemetryPayload()})
  }).then(function(response){
    if(response.ok){location.href=RESUME;return;}
    return response.text().then(function(text){throw new Error(text||("HTTP "+response.status));});
  });
}
function loadNextChunk(after,answer){
  setTimeout(function(){
    reportAnalyticsMetric(answer).catch(function(){scheduleHydrationRetry();});
  },after);
}
function scheduleHydrationRetry(){
  showBootStatus(RETRY_MESSAGE);
  setTimeout(function(){location.reload();},1500);
}
@@DRIVER@@
})();`
