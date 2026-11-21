package apiv2

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// 首页「常见问题」：价格之后、联系我们之前的一个区块，按分类列出问题，点问题展开解答
// （原生 <details>，不需要脚本）。存在 platform_settings 的 faq 键里，与首页其余内容分开保存；
// 管理员在 /console/admin/faq 编辑（GET/PUT /api/v2/admin/faq）。
//
// 答案是纯文本，只认三种写法：空一行分段；以「- 」开头的行显示为列表；以「1. 」开头的行
// 显示为编号列表。不接受任何 HTML，渲染时全部转义。
// ---------------------------------------------------------------------------

const platformFAQKey = "faq"

const (
	maxDocsIntro      = 120
	maxDocGroups      = 10
	maxDocGroupTitle  = 16
	maxDocItems       = 100 // 全部分类合计
	maxDocQuestion    = 80
	maxDocAnswer      = 2000
	maxDocAnswerLines = 60
)

type docItem struct {
	Question string `json:"question"`
	Answer   string `json:"answer"`
}

type docGroup struct {
	Title string    `json:"title"`
	Items []docItem `json:"items"`
}

// faqConfig 是保存的常见问题。分类只有一个时首页不显示分类名。
type faqConfig struct {
	Intro  string     `json:"intro"`
	Groups []docGroup `json:"groups"`
}

func defaultFAQ() faqConfig {
	return faqConfig{Intro: "接入、防护和缓存方面大家常问的问题。点问题查看解答。", Groups: defaultDocs()}
}

// loadFAQ 返回常见问题以及是否保存过；从没保存过时是默认问答。
func loadFAQ(ctx context.Context, db *sql.DB) (faqConfig, bool, error) {
	var raw []byte
	err := db.QueryRowContext(ctx, `SELECT value FROM platform_settings WHERE name = ?`, platformFAQKey).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return defaultFAQ(), false, nil
	}
	if err != nil {
		return faqConfig{}, false, err
	}
	var cfg faqConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return faqConfig{}, false, err
	}
	if cfg.Groups == nil {
		cfg.Groups = []docGroup{}
	}
	return cfg, true, nil
}

// adminFAQHandler 处理 GET/PUT /api/v2/admin/faq（管理员会话 + CSRF）。
type adminFAQHandler struct{ db *sql.DB }

func (h *adminFAQHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
	case http.MethodPut:
		raw, err := readBody(r)
		if err != nil {
			WriteError(w, err)
			return
		}
		var in faqConfig
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil {
			WriteError(w, NewApiError("validation_failed", "常见问题格式不正确"))
			return
		}
		intro, groups, err := validateDocs(in.Intro, in.Groups)
		if err != nil {
			WriteError(w, err)
			return
		}
		data, _ := json.Marshal(faqConfig{Intro: intro, Groups: groups})
		if _, err := h.db.ExecContext(r.Context(), `INSERT INTO platform_settings (name, value) VALUES (?, ?)
			ON DUPLICATE KEY UPDATE value = VALUES(value)`, platformFAQKey, data); err != nil {
			WriteError(w, err)
			return
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	cfg, saved, err := loadFAQ(r.Context(), h.db)
	if err != nil {
		WriteError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"config": cfg, "saved": saved})
}

// defaultDocs 是从未保存过文档时的默认内容，按本平台实际的功能和规则写。
func defaultDocs() []docGroup {
	return []docGroup{
		{Title: "接入使用", Items: []docItem{
			{Question: "如何把网站接入？", Answer: "1. 联系我们开通账号，登录控制台。\n" +
				"2. 在「域名」页添加域名，填写源站地址。\n" +
				"3. 在域名设置里上传 HTTPS 证书。\n" +
				"4. 到你的 DNS 服务商，把域名的 CNAME 记录指向控制台显示的接入地址。\n" +
				"5. 等 DNS 生效后访问域名，确认网站正常打开。"},
			{Question: "必须使用 HTTPS 吗？", Answer: "是的。所有域名都强制使用 HTTPS，80 端口只负责跳转到 HTTPS。\n\n" +
				"没有上传证书的域名无法访问。在域名设置里上传证书，再点「重新同步」即可。"},
			{Question: "源站地址怎么填写？", Answer: "填写源站的 IP 或域名，可以带端口，例如 1.2.3.4:8080。\n\n" +
				"- 不写端口时，回源协议为 http 默认用 80 端口，https 默认用 443 端口。\n" +
				"- 回源协议选 https 时，源站必须在该端口提供 HTTPS 服务。\n" +
				"- 可以填写多个源站并设置权重，回源流量按权重分配。"},
			{Question: "修改配置后多久生效？", Answer: "保存后点「重新同步」，配置会下发到集群的全部节点，通常几秒内生效。\n\n" +
				"如果改动涉及 DNS 记录，还要等 DNS 缓存过期，一般需要几分钟。"},
		}},
		{Title: "安全防护", Items: []docItem{
			{Question: "包含哪些防护？", Answer: "所有套餐都包含三层防护：\n" +
				"- XDP 四层防护：在网卡驱动层丢弃 SYN、UDP、ACK 洪水和反射流量。\n" +
				"- CC 防护：按 IP 限速，可以开启人机验证，超限的 IP 自动封禁。\n" +
				"- WAF：拦截 SQL 注入、漏洞扫描、恶意上传等常见 Web 攻击。"},
			{Question: "正常访客被拦截了怎么办？", Answer: "在控制台「攻击列表」或「CC 防御」页找到该 IP，点解封，也可以把它加入白名单。\n\n" +
				"如果业务本身请求频率较高（例如接口轮询），可以在「CC 防御」里调高限速阈值。"},
			{Question: "遇到超大流量攻击会怎样？", Answer: "- 单台节点带宽持续打满时，会被暂时从解析中摘除，访客转到其他节点；带宽恢复后自动加回。\n" +
				"- 集群大部分节点不可用时，自动切换到高防线路；攻击结束并稳定 1 小时后自动切回。\n\n" +
				"自动切换高防需要先在集群或域名设置里填写高防 CNAME。"},
		}},
		{Title: "缓存", Items: []docItem{
			{Question: "哪些内容会被缓存？", Answer: "默认缓存图片、脚本、样式、字体、音视频和压缩包等静态文件。HTML 页面和接口请求不缓存。\n\n" +
				"可以在「缓存」页修改默认规则，也可以在单个域名的设置里单独配置。"},
			{Question: "更新了网站文件，访问到的还是旧内容？", Answer: "在「缓存」页找到该域名，点「清除全部」或「按路径清除」，然后刷新页面。"},
			{Question: "怎么确认缓存已经生效？", Answer: "用浏览器开发者工具查看静态资源的响应头 X-Cache-Status：\n" +
				"- HIT：命中缓存，直接由节点返回。\n" +
				"- MISS：本次回源获取，下次访问会命中缓存。"},
		}},
		{Title: "账号与套餐", Items: []docItem{
			{Question: "不同套餐有什么区别？", Answer: "套餐按可以使用的节点、域名、集群数量区分，防护能力完全相同。各套餐的具体配额见首页价格。"},
			{Question: "如何升级套餐？", Answer: "联系我们调整套餐。新的配额立即生效，原有的域名和配置不受影响。"},
		}},
	}
}

// cleanAnswer 清理答案文本：统一换行、去掉每行行尾空白和首尾空行、最多保留一个空行；
// 除换行外不允许控制字符（制表符换成空格）。
func cleanAnswer(s string) (string, string) {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	s = strings.ReplaceAll(s, "\t", "  ")
	for _, r := range s {
		if r != '\n' && unicode.IsControl(r) {
			return "", "不能包含控制字符"
		}
	}
	lines := strings.Split(s, "\n")
	out := make([]string, 0, len(lines))
	blank := false
	for _, l := range lines {
		l = strings.TrimRightFunc(l, unicode.IsSpace)
		if l == "" {
			blank = len(out) > 0
			continue
		}
		if blank {
			out = append(out, "")
			blank = false
		}
		out = append(out, l)
	}
	if len(out) > maxDocAnswerLines {
		return "", "最多 " + strconv.Itoa(maxDocAnswerLines) + " 行"
	}
	res := strings.Join(out, "\n")
	if utf8.RuneCountInString(res) > maxDocAnswer {
		return "", "最长 " + strconv.Itoa(maxDocAnswer) + " 个字符"
	}
	return res, ""
}

func validateDocs(intro string, groups []docGroup) (string, []docGroup, error) {
	intro, err := cleanText("intro", intro, maxDocsIntro)
	if err != nil {
		return "", nil, err
	}
	if len(groups) > maxDocGroups {
		return "", nil, fieldError("groups", "最多 "+strconv.Itoa(maxDocGroups)+" 个分类")
	}
	out := make([]docGroup, 0, len(groups))
	total := 0
	for gi, g := range groups {
		gn := "第 " + strconv.Itoa(gi+1) + " 个分类"
		title, msg := checkText(g.Title, maxDocGroupTitle)
		if msg != "" {
			return "", nil, fieldError("groups", gn+"名称"+msg)
		}
		if title == "" {
			return "", nil, fieldError("groups", gn+"名称必填")
		}
		if len(g.Items) == 0 {
			return "", nil, fieldError("groups", gn+"「"+title+"」至少要有一个问题")
		}
		cg := docGroup{Title: title, Items: make([]docItem, 0, len(g.Items))}
		for ii, it := range g.Items {
			total++
			if total > maxDocItems {
				return "", nil, fieldError("groups", "问题最多 "+strconv.Itoa(maxDocItems)+" 个")
			}
			n := gn + "「" + title + "」的第 " + strconv.Itoa(ii+1) + " 个问题"
			q, msg := checkText(it.Question, maxDocQuestion)
			if msg != "" {
				return "", nil, fieldError("groups", n+msg)
			}
			if q == "" {
				return "", nil, fieldError("groups", n+"没有填写问题")
			}
			a, msg := cleanAnswer(it.Answer)
			if msg != "" {
				return "", nil, fieldError("groups", n+"的解答"+msg)
			}
			if a == "" {
				return "", nil, fieldError("groups", n+"没有填写解答")
			}
			cg.Items = append(cg.Items, docItem{Question: q, Answer: a})
		}
		out = append(out, cg)
	}
	return intro, out, nil
}

// ── 渲染 ──────────────────────────────────────────────────────────────────────

// docBlock 是答案里的一段：p（段落，Lines 之间换行）、ul、ol。
type docBlock struct {
	Kind  string
	Lines []string
}

var (
	docULRe = regexp.MustCompile(`^\s*[-*•·]\s+`)
	docOLRe = regexp.MustCompile(`^\s*\d{1,3}[.、)）]\s*`)
)

// parseAnswer 把答案文本切成段落和列表。空行分段；一段里连续的列表行合成一个列表。
func parseAnswer(s string) []docBlock {
	var blocks []docBlock
	for _, chunk := range strings.Split(s, "\n\n") {
		var cur *docBlock
		for _, line := range strings.Split(chunk, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			kind, text := "p", strings.TrimSpace(line)
			if loc := docULRe.FindStringIndex(line); loc != nil {
				kind, text = "ul", strings.TrimSpace(line[loc[1]:])
			} else if loc := docOLRe.FindStringIndex(line); loc != nil {
				kind, text = "ol", strings.TrimSpace(line[loc[1]:])
			}
			if text == "" {
				continue
			}
			if cur == nil || cur.Kind != kind {
				blocks = append(blocks, docBlock{Kind: kind})
				cur = &blocks[len(blocks)-1]
			}
			cur.Lines = append(cur.Lines, text)
		}
	}
	return blocks
}

type docItemView struct {
	ID       string
	No       int
	Question string
	Blocks   []docBlock
}

type docGroupView struct {
	ID    string
	Title string
	Items []docItemView
}

func buildDocGroups(groups []docGroup) []docGroupView {
	var out []docGroupView
	no := 0
	for gi, g := range groups {
		gv := docGroupView{ID: "c" + strconv.Itoa(gi+1), Title: g.Title}
		for _, it := range g.Items {
			no++
			gv.Items = append(gv.Items, docItemView{ID: "q" + strconv.Itoa(no), No: no, Question: it.Question, Blocks: parseAnswer(it.Answer)})
		}
		if len(gv.Items) > 0 {
			out = append(out, gv)
		}
	}
	return out
}
