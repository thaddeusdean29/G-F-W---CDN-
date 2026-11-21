package apiv2

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// 平台系统设置（品牌）：平台名称、Logo 文字、登录页副标题、登录页标语和功能卡片。
// 管理员在 /console/admin/settings 修改；GET /api/v2/branding 不需要登录，
// 登录页和代理控制台都用它显示平台名称。只放可公开展示的内容，不要往里加任何密钥。
// ---------------------------------------------------------------------------

const platformBrandingKey = "branding"

type platformBranding struct {
	PlatformName  string         `json:"platform_name"`
	LogoText      string         `json:"logo_text"`
	LoginSubtitle string         `json:"login_subtitle"`
	LoginSlogan   string         `json:"login_slogan"`
	LoginFeatures []loginFeature `json:"login_features"`
}

// loginFeature 是登录页左侧的一张功能卡片。Icon 只能取 loginFeatureIcons 里的名字，
// 前端按名字映射到内置图标组件，不接受任意图片地址或 HTML。
type loginFeature struct {
	Icon  string `json:"icon"`
	Title string `json:"title"`
	Desc  string `json:"desc"`
}

const (
	maxLoginFeatures = 6
	maxSloganLines   = 2
	maxSloganLen     = 40
	maxFeatureTitle  = 12
	maxFeatureDesc   = 32
)

// 和前端 vue/src/utils/featureIcons.ts 的列表保持一致。
var loginFeatureIcons = map[string]bool{
	"Connection": true, "Lightning": true, "Lock": true, "DataLine": true,
	"Monitor": true, "Cloudy": true, "Timer": true, "Odometer": true,
	"Histogram": true, "Key": true, "Promotion": true, "Aim": true,
	"Compass": true, "Cpu": true, "Position": true, "Guide": true,
	"Medal": true, "Trophy": true, "Service": true, "Location": true,
	"Link": true, "Coin": true, "Stopwatch": true, "Star": true,
}

// brandingView 是对外返回的品牌信息：保存的文字 + 网站图标地址（没上传时为空）。
// favicon_url 带内容摘要作版本号，换图标后浏览器不会继续用旧缓存。
type brandingView struct {
	platformBranding
	FaviconURL string `json:"favicon_url"`
}

func loadBrandingView(ctx context.Context, db *sql.DB) (brandingView, error) {
	b, err := loadBranding(ctx, db)
	if err != nil {
		return brandingView{platformBranding: b}, err
	}
	v := brandingView{platformBranding: b}
	sha, err := faviconSHA(ctx, db)
	if err != nil {
		return v, err
	}
	if sha != "" {
		v.FaviconURL = faviconPath + "?v=" + sha[:12]
	}
	return v, nil
}

func defaultBranding() platformBranding {
	return platformBranding{
		PlatformName:  "CDN 控制台",
		LogoText:      "CDN",
		LoginSubtitle: "欢迎回来，请登录你的账号",
		LoginSlogan:   "让每一次访问\n都更快、更安全",
		LoginFeatures: []loginFeature{
			{Icon: "Connection", Title: "全球边缘加速", Desc: "多节点就近接入，智能回源与缓存"},
			{Icon: "Lightning", Title: "XDP 四层防护", Desc: "内核态丢弃洪水与反射攻击"},
			{Icon: "Lock", Title: "CC / WAF 防御", Desc: "人机验证与规则引擎双层拦截"},
			{Icon: "DataLine", Title: "实时流量统计", Desc: "节点主动上报，攻击态势一目了然"},
		},
	}
}

func loadBranding(ctx context.Context, db *sql.DB) (platformBranding, error) {
	b := defaultBranding()
	var raw []byte
	err := db.QueryRowContext(ctx, `SELECT value FROM platform_settings WHERE name = ?`, platformBrandingKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return b, nil
	}
	if err != nil {
		return b, err
	}
	// LoginFeatures 用指针区分「从没设置过」（用默认卡片）和「设置成空列表」（不显示卡片）。
	var saved struct {
		PlatformName  string          `json:"platform_name"`
		LogoText      string          `json:"logo_text"`
		LoginSubtitle string          `json:"login_subtitle"`
		LoginSlogan   string          `json:"login_slogan"`
		LoginFeatures *[]loginFeature `json:"login_features"`
	}
	if err := json.Unmarshal(raw, &saved); err != nil {
		return b, err
	}
	// 某项留空则用默认值，避免页面上出现空标题。
	if saved.PlatformName != "" {
		b.PlatformName = saved.PlatformName
	}
	if saved.LogoText != "" {
		b.LogoText = saved.LogoText
	}
	if saved.LoginSubtitle != "" {
		b.LoginSubtitle = saved.LoginSubtitle
	}
	if saved.LoginSlogan != "" {
		b.LoginSlogan = saved.LoginSlogan
	}
	if saved.LoginFeatures != nil {
		b.LoginFeatures = *saved.LoginFeatures
	}
	return b, nil
}

// checkText 去掉首尾空白并检查长度（按字符数，中文算 1 个）和控制字符；出错时返回提示文字。
func checkText(s string, max int) (string, string) {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) > max {
		return "", "最长 " + strconv.Itoa(max) + " 个字符"
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return "", "不能包含控制字符或换行"
		}
	}
	return s, ""
}

func cleanText(field, s string, max int) (string, error) {
	s, msg := checkText(s, max)
	if msg != "" {
		return "", fieldError(field, msg)
	}
	return s, nil
}

// cleanSlogan 允许最多 maxSloganLines 行（用换行分行），每行按 checkText 的规则检查，总长不超过 max。
func cleanSlogan(s string, max int) (string, error) {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n"))
	if s == "" {
		return "", nil
	}
	lines := strings.Split(s, "\n")
	if len(lines) > maxSloganLines {
		return "", fieldError("login_slogan", "最多 "+strconv.Itoa(maxSloganLines)+" 行")
	}
	total := 0
	for i, line := range lines {
		clean, msg := checkText(line, max)
		if msg != "" {
			return "", fieldError("login_slogan", msg)
		}
		lines[i] = clean
		total += utf8.RuneCountInString(clean)
	}
	if total > max {
		return "", fieldError("login_slogan", "最长 "+strconv.Itoa(max)+" 个字符")
	}
	return strings.Join(lines, "\n"), nil
}

// parseLoginFeatures 严格解析功能卡片：出现未知字段、图标不在白名单、标题为空都拒绝。
func parseLoginFeatures(raw json.RawMessage) ([]loginFeature, error) {
	var in []loginFeature
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil || in == nil {
		return nil, fieldError("login_features", "功能卡片格式不正确")
	}
	if len(in) > maxLoginFeatures {
		return nil, fieldError("login_features", "最多 "+strconv.Itoa(maxLoginFeatures)+" 张卡片")
	}
	out := make([]loginFeature, 0, len(in))
	for i, f := range in {
		n := "第 " + strconv.Itoa(i+1) + " 张卡片"
		if !loginFeatureIcons[f.Icon] {
			return nil, fieldError("login_features", n+"的图标不可用")
		}
		title, msg := checkText(f.Title, maxFeatureTitle)
		if msg != "" {
			return nil, fieldError("login_features", n+"标题"+msg)
		}
		if title == "" {
			return nil, fieldError("login_features", n+"标题必填")
		}
		desc, msg := checkText(f.Desc, maxFeatureDesc)
		if msg != "" {
			return nil, fieldError("login_features", n+"说明"+msg)
		}
		out = append(out, loginFeature{Icon: f.Icon, Title: title, Desc: desc})
	}
	return out, nil
}

// brandingHandler 处理公开的 GET /api/v2/branding。
func brandingHandler(db *sql.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		b, err := loadBrandingView(r.Context(), db)
		if err != nil {
			WriteError(w, err)
			return
		}
		w.Header().Set("Cache-Control", "no-cache")
		writeJSON(w, http.StatusOK, b)
	}
}

// adminSettingsHandler 处理 GET/PUT /api/v2/admin/settings（需管理员会话 + CSRF）。
type adminSettingsHandler struct{ db *sql.DB }

func (h *adminSettingsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		b, err := loadBrandingView(r.Context(), h.db)
		if err != nil {
			WriteError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, b)
	case http.MethodPut:
		h.put(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// put 整体保存文字设置。不传 login_features 表示保留原有卡片；传 [] 表示不显示卡片。
// 所有校验都在碰数据库之前完成。
func (h *adminSettingsHandler) put(w http.ResponseWriter, r *http.Request) {
	body, fields, err := decodeKnownFields(r, []string{"platform_name", "logo_text", "login_subtitle", "login_slogan", "login_features"})
	if err != nil {
		WriteError(w, err)
		return
	}
	var req struct {
		PlatformName  string `json:"platform_name"`
		LogoText      string `json:"logo_text"`
		LoginSubtitle string `json:"login_subtitle"`
		LoginSlogan   string `json:"login_slogan"`
	}
	// login_features 不在这个结构体里，单独由 parseLoginFeatures 严格解析。
	if err := json.Unmarshal(body, &req); err != nil {
		WriteError(w, NewApiError("validation_failed", "字段类型不正确"))
		return
	}
	var b platformBranding
	if b.PlatformName, err = cleanText("platform_name", req.PlatformName, 32); err != nil {
		WriteError(w, err)
		return
	}
	if b.PlatformName == "" {
		WriteError(w, fieldError("platform_name", "平台名称必填"))
		return
	}
	if b.LogoText, err = cleanText("logo_text", req.LogoText, 6); err != nil {
		WriteError(w, err)
		return
	}
	if b.LoginSubtitle, err = cleanText("login_subtitle", req.LoginSubtitle, 64); err != nil {
		WriteError(w, err)
		return
	}
	if b.LoginSlogan, err = cleanSlogan(req.LoginSlogan, maxSloganLen); err != nil {
		WriteError(w, err)
		return
	}
	if raw, ok := fields["login_features"]; ok {
		if b.LoginFeatures, err = parseLoginFeatures(raw); err != nil {
			WriteError(w, err)
			return
		}
	} else {
		cur, err := loadBranding(r.Context(), h.db)
		if err != nil {
			WriteError(w, err)
			return
		}
		b.LoginFeatures = cur.LoginFeatures
	}
	raw, _ := json.Marshal(b)
	if _, err := h.db.ExecContext(r.Context(), `INSERT INTO platform_settings (name, value) VALUES (?, ?)
		ON DUPLICATE KEY UPDATE value = VALUES(value)`, platformBrandingKey, raw); err != nil {
		WriteError(w, err)
		return
	}
	out, err := loadBrandingView(r.Context(), h.db)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
