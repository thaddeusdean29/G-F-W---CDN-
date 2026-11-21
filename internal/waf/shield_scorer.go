package waf

import (
	"encoding/base64"
	"encoding/json"
	"strings"
)

// ShieldEnv 是 3 秒盾期间由浏览器采集并回传的环境信号。
// 服务端不信任其中任何单一字段能证明"是真人"，但缺失/异常组合能高置信度地指向自动化框架。
// 只保留确定性信号（webdriver 全局、UA-Headless、屏幕 0×0、时区缺失、Canvas 空 hash 等），
// 不做浏览器传统"指纹熵"，避免误伤真实用户/隐私模式。
type ShieldEnv struct {
	// 直接暴露的自动化标记
	Webdriver     bool   `json:"webdriver"`      // navigator.webdriver === true
	UAHeadless    bool   `json:"ua_headless"`    // userAgent 包含 HeadlessChrome / PhantomJS / Selenium
	MissingChrome bool   `json:"missing_chrome"` // Chrome UA 但 window.chrome 缺失
	Plugins       int    `json:"plugins"`        // navigator.plugins.length（Headless 通常为 0）
	Languages     int    `json:"languages"`      // navigator.languages.length（Headless 常为 0/1）
	Perms         string `json:"perms"`          // Notification permission 与 permissions.query 结果异常时置 "mismatch"

	// 环境完整性
	ScreenW     int    `json:"sw"`
	ScreenH     int    `json:"sh"`
	CanvasHash  string `json:"canvas"` // 空串或全零 hash → 强信号
	WebGLVendor string `json:"webgl_v"`
	WebGLRender string `json:"webgl_r"`
	Timezone    string `json:"tz"`

	// 行为信号
	Mouse    int  `json:"mouse"` // mousemove 次数（3s 内 == 0 也不算强证据，但结合别的信号加分）
	Keyboard int  `json:"kb"`
	Focused  bool `json:"focus"`
	Elapsed  int  `json:"elapsed"` // 客户端自己统计的 dwell(ms)；<3000 强可疑

	// UA 从请求头也能拿，这里只做交叉校验
	UA string `json:"ua"`
}

// ShieldScore 单次评估结果。
//   - Score 越高越可疑（0=完全干净，>=100=确定拦截）。
//   - Reasons 用于日志与前端显示"为什么被拦"。
type ShieldScore struct {
	Score   int      `json:"score"`
	Suspect bool     `json:"suspect"`
	Reasons []string `json:"reasons,omitempty"`
}

// ShieldSuspectThreshold 是把请求判为 CC 攻击的阈值。任一"死信号"直接单项 100 触发。
const ShieldSuspectThreshold = 60

// DecodeShieldEnv 把 shield 前端塞进 answer 字段的 base64(JSON) 解回结构体。
// answer 为空或格式错误时返回零值 + ok=false，由调用方决定是否算作可疑。
func DecodeShieldEnv(answer string) (ShieldEnv, bool) {
	answer = strings.TrimSpace(answer)
	if answer == "" {
		return ShieldEnv{}, false
	}
	// base64 URL-safe 或 std 都接受；前端用 std，兼容 URL-safe 只是防御性。
	raw, err := base64.StdEncoding.DecodeString(answer)
	if err != nil {
		if raw, err = base64.URLEncoding.DecodeString(answer); err != nil {
			return ShieldEnv{}, false
		}
	}
	var env ShieldEnv
	if err := json.Unmarshal(raw, &env); err != nil {
		return ShieldEnv{}, false
	}
	return env, true
}

// ScoreShieldEnv 给一次 shield 采集打分。ua 是请求头里的 User-Agent（用于交叉校验）。
// 打分策略：
//   - 每个"确定性差异"给分而不是"熵"，避免误伤真实但少见的浏览器。
//   - 多个弱信号叠加才触发；单一"死信号"（webdriver=true / UA-Headless）直接顶到 100。
func ScoreShieldEnv(env ShieldEnv, headerUA string) ShieldScore {
	var s int
	var reasons []string

	add := func(delta int, reason string) {
		s += delta
		reasons = append(reasons, reason)
	}

	// 死信号：只要中一发就一票判定
	if env.Webdriver {
		add(100, "navigator.webdriver=true")
	}
	if env.UAHeadless {
		add(100, "UA contains headless marker")
	}

	uaLow := strings.ToLower(headerUA)
	if strings.Contains(uaLow, "headlesschrome") ||
		strings.Contains(uaLow, "phantomjs") ||
		strings.Contains(uaLow, "puppeteer") ||
		strings.Contains(uaLow, "playwright") {
		add(100, "server-side UA header contains headless marker")
	}

	// 环境完整性：Headless 常见"塌缩"特征。
	// screen 0×0 / Chrome-无-window.chrome / permission 不一致是较硬的塌缩信号——真实浏览器
	// （包括隐私/抗指纹浏览器）不会出现，因此正常加分。
	if env.ScreenW <= 0 || env.ScreenH <= 0 {
		add(40, "screen size is zero")
	}
	if env.Timezone == "" {
		add(20, "missing timezone")
	}
	if env.MissingChrome && strings.Contains(uaLow, "chrome") {
		add(20, "Chrome UA without window.chrome")
	}
	if env.Perms == "mismatch" {
		add(20, "permission state mismatch")
	}

	// 隐私可解释信号：canvas 空 / WebGL 禁用 / plugins 空 / languages 空。
	// 这些在 headless 里常见，但在 Brave、Firefox 抗指纹、Tor、隐私模式等真实浏览器里
	// 也会同时出现（多站点 + 多内核环境下不可忽视）。因此单独计入一个封顶 privacyCap 的
	// 子分池：它们叠加再多也无法独立过阈，必须搭配上面的硬塌缩信号或下面的时序/UA 证据
	// 才会判定可疑。这样既保留对 headless 的识别力，又不误伤抗指纹的真人。
	const privacyCap = 40
	privacy := 0
	if env.CanvasHash == "" || env.CanvasHash == "0" || env.CanvasHash == "00000000" {
		privacy += 25
		reasons = append(reasons, "canvas fingerprint empty")
	}
	if env.WebGLVendor == "" && env.WebGLRender == "" {
		privacy += 15
		reasons = append(reasons, "webgl unavailable")
	}
	if env.Plugins == 0 && !strings.Contains(uaLow, "firefox") && !strings.Contains(uaLow, "safari") {
		privacy += 10
		reasons = append(reasons, "no navigator.plugins")
	}
	if env.Languages == 0 {
		privacy += 15
		reasons = append(reasons, "navigator.languages empty")
	}
	if privacy > privacyCap {
		privacy = privacyCap
	}
	s += privacy

	// 交互与时序
	if env.Elapsed > 0 && env.Elapsed < 2800 {
		// 服务端有 3s 硬门槛；这里再看客户端自报，配脚本刻意 sleep 但没等够就下发的情况
		add(30, "dwell too short")
	}
	if env.Mouse == 0 && env.Keyboard == 0 && !env.Focused {
		add(10, "no user activity during dwell")
	}

	// UA header 与前端 UA 不一致 → 决定性证据：合法浏览器发出的 header UA 必然等于
	// navigator.userAgent，不一致说明脚本伪造了 header 却没同步 patch window.navigator。
	// 单条即达阈值（这条挑战只在流量已被判 CC 嫌疑时触发，误伤面极小）。
	if env.UA != "" && headerUA != "" && env.UA != headerUA {
		add(60, "UA header/navigator mismatch")
	}

	if s > 100 {
		s = 100
	}
	return ShieldScore{
		Score:   s,
		Suspect: s >= ShieldSuspectThreshold,
		Reasons: reasons,
	}
}
