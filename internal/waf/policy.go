package waf

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"cdn/internal/secure"
)

// 托管规则的档位、模式与级别的取值。字符串是对外协议（面板/API/下发 payload），
// 改值等于改协议，只能加不能改。
const (
	ModeBlock   = "block"
	ModeObserve = "observe"

	LevelOff    = "off"
	LevelLow    = "low"
	LevelMedium = "medium"
	LevelHigh   = "high"
	LevelAttack = "attack"
)

// Policy 是一个代理的托管规则策略（面板下发到节点的那份）。
//
// 它是"按代理一份"而不是"按域名一份"：边缘的执行点在 auth_request 子请求里，
// 域名级配置要靠每条域名记录一起下发并逐域名查表，代价与收益不成比例；
// 级别/规则集/单条开关这些本来就是"这套代理想防到什么程度"的判断。
//
// Enabled 只关掉托管规则与级别。IP 名单（封禁表）、ACME 路径限速、UA 校验与
// 上传校验不受它控制 —— 理由见 Engine.CheckBase 的注释。
type Policy struct {
	Enabled bool            `json:"enabled"`
	Mode    string          `json:"mode"`  // block=拦截，observe=只记账不拦（灰度验证规则用）
	Level   string          `json:"level"` // off/low/medium/high/attack
	Sets    []string        `json:"sets"`  // 勾选的规则集 id（增量启用它覆盖的规则）
	Rules   map[string]bool `json:"rules"` // 单条规则的显式覆盖：true 强开，false 强关
	// RulesVersion 空串=跟随节点的 active 包；非空=固定到该版本（只能是 active 或 previous，
	// 用于单域验证之外的"整代理锁定旧包回滚"）。固定时灰度比例不生效。
	RulesVersion string `json:"rules_version"`
	GrayPercent  int    `json:"gray_percent"` // 0~99：按 Host 稳定哈希切到 previous 包的比例
}

// DefaultPolicy 是"从没在面板上保存过"时的执行档：全量内置包、拦截、中级别。
// 与升级前行为一致（升级前所有规则恒定执行且恒定拦截）。
func DefaultPolicy() Policy {
	return Policy{Enabled: true, Mode: ModeBlock, Level: LevelMedium}
}

func (p Policy) observe() bool { return p.Mode == ModeObserve }

// PolicyPatch 是下发给边缘的策略补丁：每个字段都是指针，用来区分
// "这个字段没出现"和"显式设为 false/0/空串"。
//
// 这不是讲究：整结构体 Decode 到 Policy 时，面板 payload 一旦漏掉 enabled，
// 边缘就会把托管规则全关 —— 与升级前"规则恒定执行"的行为完全相反，而且零报错。
// 内置 CC 配置的下发踩过同一个坑（见 edgeapi.updateCCConfig 的注释）。
type PolicyPatch struct {
	Enabled      *bool            `json:"enabled"`
	Mode         *string          `json:"mode"`
	Level        *string          `json:"level"`
	Sets         *[]string        `json:"sets"`
	Rules        *map[string]bool `json:"rules"`
	RulesVersion *string          `json:"rules_version"`
	GrayPercent  *int             `json:"gray_percent"`
}

// Apply 把补丁合进策略，随后归一化。
func (p *Policy) Apply(patch PolicyPatch) {
	if patch.Enabled != nil {
		p.Enabled = *patch.Enabled
	}
	if patch.Mode != nil {
		p.Mode = *patch.Mode
	}
	if patch.Level != nil {
		p.Level = *patch.Level
	}
	if patch.Sets != nil {
		p.Sets = ruleIDList(*patch.Sets)
	}
	if patch.Rules != nil {
		rules := make(map[string]bool, len(*patch.Rules))
		for id, on := range *patch.Rules {
			if id = strings.TrimSpace(id); id != "" {
				rules[id] = on
			}
		}
		p.Rules = rules
	}
	if patch.RulesVersion != nil {
		p.RulesVersion = strings.TrimSpace(*patch.RulesVersion)
	}
	if patch.GrayPercent != nil {
		p.GrayPercent = *patch.GrayPercent
	}
	p.Normalize()
}

// Normalize 把非法取值收回到安全档，而不是让它把防护整段关掉。
// 灰度越界收进 0~99；模式/级别不认识就回落到 block/medium；
// 规则 id 只留非空的。空 Rules 归一成非 nil map，序列化出来是 {} 而不是 null。
func (p *Policy) Normalize() {
	if p.Mode != ModeObserve {
		p.Mode = ModeBlock
	}
	switch p.Level {
	case LevelOff, LevelLow, LevelMedium, LevelHigh, LevelAttack:
	default:
		p.Level = LevelMedium
	}
	if p.GrayPercent < 0 {
		p.GrayPercent = 0
	}
	if p.GrayPercent > 99 {
		p.GrayPercent = 99
	}
	p.Sets = ruleIDList(p.Sets)
	if p.Rules == nil {
		p.Rules = map[string]bool{}
	}
}

// fingerprint 是策略的等值标识，用作生效规则集的缓存键的一段。
// 必须稳定：JSON map 序列化按键排序，slice 保留顺序（勾选顺序不影响集合语义，
// 所以先归一化再拼）。
func (p Policy) fingerprint() string {
	var sets bytes.Buffer
	for _, s := range ruleIDList(p.Sets) {
		sets.WriteString(s)
		sets.WriteByte(',')
	}
	ids := make([]string, 0, len(p.Rules))
	for id, on := range p.Rules {
		if on {
			ids = append(ids, "+"+id)
		} else {
			ids = append(ids, "-"+id)
		}
	}
	sort.Strings(ids)
	return fmt.Sprintf("%v|%s|%s|%s|%v|%d|%d",
		p.Enabled, p.Mode, p.Level, strings.TrimSuffix(sets.String(), ","),
		strings.Join(ids, ","), p.GrayPercent, len(p.Rules))
}

// Verdict 是一次托管规则判定结果。命中与处置分开返回，是因为"观察模式"要的正是
// 知道命中了什么但不拦截；如果在引擎里就把观察折成 Allow，面板就再也看不见证据。
type Verdict struct {
	Hit     bool   `json:"hit"`
	Rule    string `json:"rule"`    // 规则 id
	Name    string `json:"name"`    // 规则名称（日志与面板展示）
	Message string `json:"message"` // 命中的位置与摘要
	Observe bool   `json:"observe"` // true=本次只记账，应当放行
	Package string `json:"package"` // 本次判定用的规则包版本
	Reason  string `json:"reason,omitempty"`
}

// targets 缓存一次请求各作用域的待匹配文本：多条规则查同一个位置不该重复拼串，
// 请求体也只读一次（读完必须恢复，后面还要交给源站）。
//
// cache 是必须的，不是优化：一条规则有 4 个模式、15 条规则里 11 条看 url，
// 不缓存的话每个请求要重复拼十几次同一个串并各自分配一次内存。
type targets struct {
	r        *http.Request
	cache    map[string][]byte
	body     []byte
	bodyRead bool
}

func (t *targets) scope(s string) []byte {
	if v, ok := t.cache[s]; ok {
		return v
	}
	v := t.computeScope(s)
	if t.cache == nil {
		t.cache = make(map[string][]byte, 6)
	}
	t.cache[s] = v
	return v
}

func (t *targets) computeScope(s string) []byte {
	switch s {
	case ScopeURL:
		u := t.r.URL
		if u == nil {
			return nil
		}
		// Path 是解码后的，RawPath 只在两者不同时（即 URI 里有转义）才有值，
		// 两段都拼上等于同时拿到编码与解码两种形态。
		out := u.RawPath + u.Path
		if u.RawQuery != "" {
			out += "?" + u.RawQuery
			// 查询串默认只有原始那一形态，全编码的 payload（?q=%27union+select）
			// 就从 url 作用域漏掉。只有出现百分号时才补一次解码，常态请求零额外开销。
			if dec, err := url.QueryUnescape(u.RawQuery); err == nil && dec != u.RawQuery {
				out += "?" + dec
			}
		}
		return []byte(out)
	case ScopeUA:
		return []byte(t.r.Header.Get("User-Agent"))
	case ScopeReferer:
		return []byte(t.r.Header.Get("Referer"))
	case ScopeCookie:
		return []byte(t.r.Header.Get("Cookie"))
	case ScopeCT:
		return []byte(t.r.Header.Get("Content-Type"))
	case ScopeBody:
		return t.readBody()
	}
	return nil
}

// readBody 读请求体样本（前 64KB）并原样恢复 Body。
//
// multipart 不取样：那是文件上传，正文里大半是二进制，按文本匹配既误报又费 CPU；
// 更关键的是只恢复前 64KB 会把大文件截断，上传被 WAF 悄悄改坏比漏检严重得多。
// 上传本身的检查在内置段（CheckUpload：文件名、大小、魔术字节）。
//
// 另外要清楚：生产路径上这里基本读不到内容 —— 边缘 WAF 挂在 auth_request 子请求上，
// 模板是 proxy_pass_request_body off，子请求没有 body。所以 body 作用域的规则
// 只有在能看到请求体的部署里才真正执行。
func (t *targets) readBody() []byte {
	if t.bodyRead {
		return t.body
	}
	t.bodyRead = true
	if t.r.Body == nil {
		return nil
	}
	switch t.r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch:
	default:
		return nil
	}
	if strings.Contains(t.r.Header.Get("Content-Type"), "multipart/form-data") {
		return nil
	}
	data, err := io.ReadAll(io.LimitReader(t.r.Body, maxPackageBodySample))
	if err != nil || len(data) == 0 {
		return nil
	}
	t.r.Body = io.NopCloser(bytes.NewReader(data))
	t.body = data
	return data
}

// hitTracker 记托管规则的命中数：观察模式下"命中了但没拦"和拦截模式下"确实拦了"
// 必须分开计，否则切到观察模式灰度时，面板上会显示防护归零。
type hitTracker struct {
	mu           sync.Mutex
	perRule      map[string]*ruleHits
	totalObserve atomic.Uint64
	totalBlocked atomic.Uint64
}

type ruleHits struct {
	observe atomic.Uint64
	blocked atomic.Uint64
}

// HitRow 是一条规则的命中读数（面板 WAF 页与 /edge/waf/stats 共用）。
type HitRow struct {
	Rule    string `json:"rule"`
	Name    string `json:"name,omitempty"`
	Observe uint64 `json:"observe"`
	Blocked uint64 `json:"blocked"`
}

func newHitTracker() *hitTracker { return &hitTracker{perRule: map[string]*ruleHits{}} }

func (h *hitTracker) add(rule string, observe bool) {
	h.mu.Lock()
	rh := h.perRule[rule]
	if rh == nil {
		// 规则 id 来自管理员下发的包，条数在建包时就限死了（maxRulesPerPackage），
		// 所以这张表不需要像封禁表那样设上限：攻击者控制不了它长多少条目。
		rh = &ruleHits{}
		h.perRule[rule] = rh
	}
	h.mu.Unlock()
	if observe {
		rh.observe.Add(1)
		h.totalObserve.Add(1)
		return
	}
	rh.blocked.Add(1)
	h.totalBlocked.Add(1)
}

// snapshot 按总命中降序返回读数；nameOf 由 Engine 提供（规则名在包目录里）。
func (h *hitTracker) snapshot(nameOf func(string) string) []HitRow {
	h.mu.Lock()
	rows := make([]HitRow, 0, len(h.perRule))
	for id, rh := range h.perRule {
		rows = append(rows, HitRow{Rule: id, Name: nameOf(id), Observe: rh.observe.Load(), Blocked: rh.blocked.Load()})
	}
	h.mu.Unlock()
	sort.Slice(rows, func(i, j int) bool {
		si, sj := rows[i].Observe+rows[i].Blocked, rows[j].Observe+rows[j].Blocked
		if si != sj {
			return si > sj
		}
		return rows[i].Rule < rows[j].Rule
	})
	return rows
}

func (h *hitTracker) totals() (observe, blocked uint64) {
	return h.totalObserve.Load(), h.totalBlocked.Load()
}

// reset 在规则包换版时清空读数：旧包的命中数与包版本绑定，留在图上会让
// "新包是不是真的生效了"这个问题没法回答。
func (h *hitTracker) reset() {
	h.mu.Lock()
	h.perRule = map[string]*ruleHits{}
	h.mu.Unlock()
	h.totalObserve.Store(0)
	h.totalBlocked.Store(0)
}

func decryptRules(data []byte) ([]byte, error) {
	plain, err := secure.Decrypt(data)
	if err != nil {
		return nil, fmt.Errorf("规则包解密失败（密钥不一致或数据损坏）: %w", err)
	}
	return plain, nil
}
