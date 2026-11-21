package apiv2

import (
	"bytes"
	"context"
	"crypto/rand"
	"database/sql"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"cdn/internal/secure"
)

// ---------------------------------------------------------------------------
// 公开首页：产品能力、套餐价格、常见问题、联系方式。首页内容由平台管理员在 /console/admin/homepage
// 编辑（GET/PUT /api/v2/admin/homepage），存在 platform_settings 的 homepage 键里；常见问题
// 单独保存（docs.go，/console/admin/faq）。
// 首页由服务端渲染、不运行任何脚本（CSP 只放行带 nonce 的内联样式），国内访问不依赖
// 任何外部字体或 CDN。只放可公开展示的内容。
// ---------------------------------------------------------------------------

const platformHomepageKey = "homepage"

const (
	maxHomeTitle        = 40
	maxHomeTitleLines   = 2
	maxHomeSubtitle     = 120
	maxHomeFeatures     = 9
	maxHomeFeatureTitle = 16
	maxHomeFeatureDesc  = 60
	maxHomeNote         = 80
	maxHomePlans        = 6
	maxHomePlanName     = 16
	maxHomePrice        = 16
	maxHomePeriod       = 8
	maxHomePlanDesc     = 60
	maxHomePlanItems    = 10
	maxHomePlanItem     = 30
	maxHomeContacts     = 8
	maxHomeContactLabel = 12
	maxHomeContactValue = 64
	maxHomeICP          = 40
	maxHomeFooter       = 100
)

type homepagePlan struct {
	Name      string   `json:"name"`
	Price     string   `json:"price"`
	Period    string   `json:"period"`
	Desc      string   `json:"desc"`
	PlanCode  string   `json:"plan_code"`
	Items     []string `json:"items"`
	Highlight bool     `json:"highlight"`
}

type homepageContact struct {
	Type  string `json:"type"`
	Label string `json:"label"`
	Value string `json:"value"`
}

type homepageConfig struct {
	Enabled      bool              `json:"enabled"`
	HeroTitle    string            `json:"hero_title"`
	HeroSubtitle string            `json:"hero_subtitle"`
	Features     []loginFeature    `json:"features"`
	PlansNote    string            `json:"plans_note"`
	Plans        []homepagePlan    `json:"plans"`
	ContactNote  string            `json:"contact_note"`
	Contacts     []homepageContact `json:"contacts"`
	ICP          string            `json:"icp"`
	FooterNote   string            `json:"footer_note"`
}

// homeContactKind 是联系方式类型：图标、默认显示名。链接只为能严格校验格式的类型生成。
type homeContactKind struct{ icon, label string }

var homeContactKinds = map[string]homeContactKind{
	"wechat":   {"ChatDotRound", "微信"},
	"qq":       {"ChatLineSquare", "QQ"},
	"telegram": {"Promotion", "Telegram"},
	"email":    {"Message", "邮箱"},
	"phone":    {"Phone", "电话"},
	"other":    {"Link", "联系方式"},
}

var (
	homeEmailRe    = regexp.MustCompile(`^[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(\.[A-Za-z0-9\-]+)*\.[A-Za-z]{2,}$`)
	homeTelegramRe = regexp.MustCompile(`^@?[A-Za-z0-9_]{5,32}$`)
	homePhoneRe    = regexp.MustCompile(`^\+?[0-9][0-9 \-]{4,19}$`)
	homeQQRe       = regexp.MustCompile(`^[1-9][0-9]{4,11}$`)
)

// planRow 是 plans 表里展示用的几列：首页套餐可以关联一个真实套餐，自动带出配额。
type planRow struct {
	Code        string `json:"code"`
	Name        string `json:"name"`
	MaxNodes    int    `json:"max_nodes"`
	MaxDomains  int    `json:"max_domains"`
	MaxClusters int    `json:"max_clusters"`
}

func loadPlanRows(ctx context.Context, db *sql.DB) ([]planRow, error) {
	rows, err := db.QueryContext(ctx, `SELECT code, name, max_nodes, max_domains, max_clusters FROM plans ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []planRow{}
	for rows.Next() {
		var p planRow
		if err := rows.Scan(&p.Code, &p.Name, &p.MaxNodes, &p.MaxDomains, &p.MaxClusters); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func defaultHomeFeatures() []loginFeature {
	return []loginFeature{
		{Icon: "Connection", Title: "多节点就近接入", Desc: "访客就近连到边缘节点；单个节点被打满时自动摘除解析，其余节点照常服务"},
		{Icon: "Lightning", Title: "XDP 四层防护", Desc: "在网卡驱动层丢弃 SYN、UDP、ACK 洪水与反射流量，不占用系统资源"},
		{Icon: "Lock", Title: "CC 人机验证", Desc: "按 IP 限速，可疑访问需要通过浏览器环境验证，攻击 IP 自动封禁"},
		{Icon: "Aim", Title: "WAF 规则拦截", Desc: "拦截 SQL 注入、漏洞扫描、恶意上传等常见 Web 攻击"},
		{Icon: "Cloudy", Title: "边缘缓存", Desc: "图片、脚本、字体和视频缓存在节点上，减少回源，加快访问"},
		{Icon: "Promotion", Title: "自动切换高防", Desc: "集群可用节点不足时自动切到高防线路，攻击结束并稳定后自动切回"},
	}
}

// defaultHomepage 是从未保存过时的首页：默认文案，套餐按 plans 表列出（价格显示「联系咨询」）。
func defaultHomepage(plans []planRow) homepageConfig {
	cfg := homepageConfig{
		Enabled:      true,
		HeroTitle:    "攻击停在边缘\n访问照常到达",
		HeroSubtitle: "高防 CDN：多节点就近接入，静态资源边缘缓存。XDP、CC、WAF 三层防护逐级拦截攻击流量，只把正常访问送回你的源站。",
		Features:     defaultHomeFeatures(),
		PlansNote:    "所有套餐都包含 XDP、CC、WAF 防护。",
		ContactNote:  "账号由平台开通。需要试用或购买，请通过以下方式联系我们。",
		Plans:        []homepagePlan{},
		Contacts:     []homepageContact{},
	}
	for _, p := range plans {
		cfg.Plans = append(cfg.Plans, homepagePlan{Name: p.Name, PlanCode: p.Code, Items: []string{}})
		if len(cfg.Plans) == maxHomePlans {
			break
		}
	}
	return cfg
}

// loadHomepage 返回首页配置以及是否保存过。没保存过时 plans 由调用方传入的套餐生成。
func loadHomepage(ctx context.Context, db *sql.DB, plans []planRow) (homepageConfig, bool, error) {
	var raw []byte
	err := db.QueryRowContext(ctx, `SELECT value FROM platform_settings WHERE name = ?`, platformHomepageKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return defaultHomepage(plans), false, nil
	}
	if err != nil {
		return homepageConfig{}, false, err
	}
	var cfg homepageConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return homepageConfig{}, false, err
	}
	return cfg, true, nil
}

// cleanMultiline 允许最多 lines 行（换行分隔），逐行按 checkText 规则检查，总字数不超过 max。
func cleanMultiline(field, s string, lines, max int) (string, error) {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n"))
	if s == "" {
		return "", nil
	}
	var out []string
	total := 0
	for _, line := range strings.Split(s, "\n") {
		clean, msg := checkText(line, max)
		if msg != "" {
			return "", fieldError(field, msg)
		}
		if clean == "" {
			continue
		}
		out = append(out, clean)
		total += utf8.RuneCountInString(clean)
	}
	if len(out) > lines {
		return "", fieldError(field, "最多 "+strconv.Itoa(lines)+" 行")
	}
	if total > max {
		return "", fieldError(field, "最长 "+strconv.Itoa(max)+" 个字符")
	}
	return strings.Join(out, "\n"), nil
}

// validateHomepage 严格解析并清理首页配置：未知字段、超长、图标或联系方式类型不在白名单都拒绝。
func validateHomepage(raw []byte) (homepageConfig, error) {
	var in homepageConfig
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return homepageConfig{}, NewApiError("validation_failed", "首页配置格式不正确")
	}
	var out homepageConfig
	var err error
	out.Enabled = in.Enabled
	if out.HeroTitle, err = cleanMultiline("hero_title", in.HeroTitle, maxHomeTitleLines, maxHomeTitle); err != nil {
		return out, err
	}
	if out.HeroTitle == "" {
		return out, fieldError("hero_title", "首屏标题必填")
	}
	if out.HeroSubtitle, err = cleanText("hero_subtitle", in.HeroSubtitle, maxHomeSubtitle); err != nil {
		return out, err
	}
	if out.PlansNote, err = cleanText("plans_note", in.PlansNote, maxHomeNote); err != nil {
		return out, err
	}
	if out.ContactNote, err = cleanText("contact_note", in.ContactNote, maxHomeNote); err != nil {
		return out, err
	}
	if out.ICP, err = cleanText("icp", in.ICP, maxHomeICP); err != nil {
		return out, err
	}
	if out.FooterNote, err = cleanText("footer_note", in.FooterNote, maxHomeFooter); err != nil {
		return out, err
	}

	if len(in.Features) > maxHomeFeatures {
		return out, fieldError("features", "最多 "+strconv.Itoa(maxHomeFeatures)+" 项产品能力")
	}
	out.Features = []loginFeature{}
	for i, f := range in.Features {
		n := "第 " + strconv.Itoa(i+1) + " 项产品能力"
		if !loginFeatureIcons[f.Icon] {
			return out, fieldError("features", n+"的图标不可用")
		}
		title, msg := checkText(f.Title, maxHomeFeatureTitle)
		if msg != "" {
			return out, fieldError("features", n+"标题"+msg)
		}
		if title == "" {
			return out, fieldError("features", n+"标题必填")
		}
		desc, msg := checkText(f.Desc, maxHomeFeatureDesc)
		if msg != "" {
			return out, fieldError("features", n+"说明"+msg)
		}
		out.Features = append(out.Features, loginFeature{Icon: f.Icon, Title: title, Desc: desc})
	}

	if len(in.Plans) > maxHomePlans {
		return out, fieldError("plans", "最多 "+strconv.Itoa(maxHomePlans)+" 个套餐")
	}
	out.Plans = []homepagePlan{}
	for i, p := range in.Plans {
		n := "第 " + strconv.Itoa(i+1) + " 个套餐"
		var c homepagePlan
		var msg string
		if c.Name, msg = checkText(p.Name, maxHomePlanName); msg != "" {
			return out, fieldError("plans", n+"名称"+msg)
		}
		if c.Name == "" {
			return out, fieldError("plans", n+"名称必填")
		}
		if c.Price, msg = checkText(p.Price, maxHomePrice); msg != "" {
			return out, fieldError("plans", n+"价格"+msg)
		}
		if c.Period, msg = checkText(p.Period, maxHomePeriod); msg != "" {
			return out, fieldError("plans", n+"计费周期"+msg)
		}
		if c.Desc, msg = checkText(p.Desc, maxHomePlanDesc); msg != "" {
			return out, fieldError("plans", n+"说明"+msg)
		}
		c.PlanCode = strings.TrimSpace(p.PlanCode)
		if c.PlanCode != "" && !validPlanCode(c.PlanCode) {
			return out, fieldError("plans", n+"关联的套餐编码不正确")
		}
		if len(p.Items) > maxHomePlanItems {
			return out, fieldError("plans", n+"最多 "+strconv.Itoa(maxHomePlanItems)+" 条说明")
		}
		c.Items = []string{}
		for _, it := range p.Items {
			item, msg := checkText(it, maxHomePlanItem)
			if msg != "" {
				return out, fieldError("plans", n+"的说明条目"+msg)
			}
			if item != "" {
				c.Items = append(c.Items, item)
			}
		}
		c.Highlight = p.Highlight
		out.Plans = append(out.Plans, c)
	}

	if len(in.Contacts) > maxHomeContacts {
		return out, fieldError("contacts", "最多 "+strconv.Itoa(maxHomeContacts)+" 个联系方式")
	}
	out.Contacts = []homepageContact{}
	for i, ct := range in.Contacts {
		n := "第 " + strconv.Itoa(i+1) + " 个联系方式"
		if _, ok := homeContactKinds[ct.Type]; !ok {
			return out, fieldError("contacts", n+"的类型不可用")
		}
		label, msg := checkText(ct.Label, maxHomeContactLabel)
		if msg != "" {
			return out, fieldError("contacts", n+"名称"+msg)
		}
		value, msg := checkText(ct.Value, maxHomeContactValue)
		if msg != "" {
			return out, fieldError("contacts", n+"内容"+msg)
		}
		if value == "" {
			return out, fieldError("contacts", n+"内容必填")
		}
		if err := checkContactValue(ct.Type, value); err != "" {
			return out, fieldError("contacts", n+err)
		}
		out.Contacts = append(out.Contacts, homepageContact{Type: ct.Type, Label: label, Value: value})
	}
	return out, nil
}

func checkContactValue(kind, v string) string {
	switch kind {
	case "email":
		if !homeEmailRe.MatchString(v) {
			return "不是有效的邮箱地址"
		}
	case "telegram":
		if !homeTelegramRe.MatchString(v) {
			return "应为 Telegram 用户名（5-32 位字母、数字或下划线，可带 @）"
		}
	case "phone":
		if !homePhoneRe.MatchString(v) {
			return "应为电话号码（数字，可带 + 和 -）"
		}
	case "qq":
		if !homeQQRe.MatchString(v) {
			return "应为 QQ 号（5-12 位数字）"
		}
	}
	return ""
}

// ── 管理员接口 ────────────────────────────────────────────────────────────────

type adminHomepageHandler struct{ db *sql.DB }

func (h *adminHomepageHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.respond(w, r)
	case http.MethodPut:
		raw, err := readBody(r)
		if err != nil {
			WriteError(w, err)
			return
		}
		cfg, err := validateHomepage(raw)
		if err != nil {
			WriteError(w, err)
			return
		}
		data, _ := json.Marshal(cfg)
		if _, err := h.db.ExecContext(r.Context(), `INSERT INTO platform_settings (name, value) VALUES (?, ?)
			ON DUPLICATE KEY UPDATE value = VALUES(value)`, platformHomepageKey, data); err != nil {
			WriteError(w, err)
			return
		}
		h.respond(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func (h *adminHomepageHandler) respond(w http.ResponseWriter, r *http.Request) {
	plans, err := loadPlanRows(r.Context(), h.db)
	if err != nil {
		WriteError(w, err)
		return
	}
	cfg, saved, err := loadHomepage(r.Context(), h.db, plans)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": cfg, "saved": saved, "plans": plans})
}

// ── 公开页面 ──────────────────────────────────────────────────────────────────

// site_layout.tmpl / homepage.tmpl 是开发态维护用的明文源文件，不再被直接嵌入。
// 编译期由 cmd/sealresource 生成同名 .enc，运行时解密后使用。

//go:embed site_layout.tmpl.enc
var siteLayoutTmplEnc []byte

//go:embed homepage.tmpl.enc
var homepageTmplEnc []byte

var homepageTmpl = template.Must(template.Must(template.New("layout").Parse(string(secure.MustDecrypt(siteLayoutTmplEnc)))).Parse(string(secure.MustDecrypt(homepageTmplEnc))))

type homeFeatureView struct {
	Icon        []string
	Title, Desc string
}

type homePlanView struct {
	Name, Price, Period, Desc string
	Limits, Items             []string
	Highlight                 bool
}

type homeContactView struct {
	Icon         []string
	Label, Value string
	Href         template.URL // 只为严格校验过格式的邮箱 / Telegram / 电话生成，其余为空
}

// homeNav 决定顶栏导航和各区块是否显示（没有内容的区块不显示，也不出现在导航里）。
type homeNav struct {
	Features, Plans, FAQ, Contact bool
}

type homeView struct {
	PageTitle   string
	Description string
	Nav         homeNav
	Brand       brandingView
	TitleLines  []string
	Subtitle    string
	Features    []homeFeatureView
	PlansNote   string
	Plans       []homePlanView
	ContactNote string
	Contacts    []homeContactView
	FAQIntro    string
	FAQGroups   []docGroupView
	ICP         string
	FooterNote  string
	Year        int
	Nonce       string
	CheckIcon   []string
	ChevronIcon []string
}

func buildHomeView(cfg homepageConfig, faq faqConfig, brand brandingView, plans []planRow) homeView {
	v := homeView{
		PageTitle:   brand.PlatformName,
		Description: cfg.HeroSubtitle,
		Brand:       brand,
		TitleLines:  strings.Split(cfg.HeroTitle, "\n"),
		Subtitle:    cfg.HeroSubtitle,
		PlansNote:   cfg.PlansNote,
		ContactNote: cfg.ContactNote,
		ICP:         cfg.ICP,
		FooterNote:  cfg.FooterNote,
		Year:        time.Now().Year(),
		CheckIcon:   homepageIconPaths["Check"],
		ChevronIcon: homepageIconPaths["ArrowDown"],
		FAQIntro:    faq.Intro,
		FAQGroups:   buildDocGroups(faq.Groups),
	}
	for _, f := range cfg.Features {
		if p, ok := homepageIconPaths[f.Icon]; ok {
			v.Features = append(v.Features, homeFeatureView{Icon: p, Title: f.Title, Desc: f.Desc})
		}
	}
	byCode := map[string]planRow{}
	for _, p := range plans {
		byCode[p.Code] = p
	}
	for _, p := range cfg.Plans {
		pv := homePlanView{Name: p.Name, Price: p.Price, Period: p.Period, Desc: p.Desc, Items: p.Items, Highlight: p.Highlight}
		if row, ok := byCode[p.PlanCode]; ok && p.PlanCode != "" {
			if row.MaxNodes > 0 {
				pv.Limits = append(pv.Limits, fmt.Sprintf("节点 %d 台", row.MaxNodes))
			}
			if row.MaxDomains > 0 {
				pv.Limits = append(pv.Limits, fmt.Sprintf("域名 %d 个", row.MaxDomains))
			}
			if row.MaxClusters > 0 {
				pv.Limits = append(pv.Limits, fmt.Sprintf("集群 %d 个", row.MaxClusters))
			}
		}
		v.Plans = append(v.Plans, pv)
	}
	for _, c := range cfg.Contacts {
		kind, ok := homeContactKinds[c.Type]
		if !ok {
			continue
		}
		cv := homeContactView{Icon: homepageIconPaths[kind.icon], Label: c.Label, Value: c.Value}
		if cv.Label == "" {
			cv.Label = kind.label
		}
		// 保存时已按类型校验过；渲染时再校验一次，库里的值被改过也不会生成异常链接。
		if checkContactValue(c.Type, c.Value) == "" {
			switch c.Type {
			case "email":
				cv.Href = template.URL("mailto:" + c.Value)
			case "telegram":
				cv.Href = template.URL("https://t.me/" + strings.TrimPrefix(c.Value, "@"))
			case "phone":
				cv.Href = template.URL("tel:" + strings.NewReplacer(" ", "", "-", "").Replace(c.Value))
			}
		}
		v.Contacts = append(v.Contacts, cv)
	}
	v.Nav = homeNav{
		Features: len(v.Features) > 0,
		Plans:    len(v.Plans) > 0,
		FAQ:      len(v.FAQGroups) > 0,
		Contact:  len(v.Contacts) > 0 || v.ContactNote != "",
	}
	return v
}

// HomepageHandler 渲染根路径 / 的公开首页。首页关闭或读库失败时直接进控制台。
func HomepageHandler(db *sql.DB) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		ctx := r.Context()
		plans, err := loadPlanRows(ctx, db)
		if err != nil {
			log.Printf("[apiv2 Homepage] load plans: %v", err)
			http.Redirect(w, r, "/console/", http.StatusFound)
			return
		}
		cfg, _, err := loadHomepage(ctx, db, plans)
		if err != nil {
			log.Printf("[apiv2 Homepage] load homepage: %v", err)
			http.Redirect(w, r, "/console/", http.StatusFound)
			return
		}
		if !cfg.Enabled {
			http.Redirect(w, r, "/console/", http.StatusFound)
			return
		}
		brand, err := loadBrandingView(ctx, db)
		if err != nil {
			log.Printf("[apiv2 Homepage] load branding: %v", err)
		}
		faq, _, err := loadFAQ(ctx, db)
		if err != nil {
			// 常见问题读不出来不影响首页其余内容，这一块不显示即可。
			log.Printf("[apiv2 Homepage] load faq: %v", err)
			faq = faqConfig{}
		}
		nonce := make([]byte, 16)
		if _, err := rand.Read(nonce); err != nil {
			WriteError(w, err)
			return
		}
		view := buildHomeView(cfg, faq, brand, plans)
		view.Nonce = base64.StdEncoding.EncodeToString(nonce)

		var buf bytes.Buffer
		if err := homepageTmpl.ExecuteTemplate(&buf, "page", view); err != nil {
			log.Printf("[apiv2 Homepage] render: %v", err)
			WriteError(w, err)
			return
		}
		hdr := w.Header()
		hdr.Set("Content-Type", "text/html; charset=utf-8")
		hdr.Set("Cache-Control", "no-cache")
		hdr.Set("X-Content-Type-Options", "nosniff")
		hdr.Set("X-Frame-Options", "DENY")
		hdr.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		hdr.Set("Content-Security-Policy", "default-src 'none'; style-src 'nonce-"+view.Nonce+"'; img-src 'self'; "+
			"base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
		_, _ = w.Write(buf.Bytes())
	})
}
