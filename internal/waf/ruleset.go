package waf

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// 托管规则包（rules.enc / 面板下发的包 / 数据库里的包，三者同一种格式）。
//
// 规则必须是**声明式**的：只要有一条规则需要 Go 闭包，"管理员改完立刻下发到全网"就
// 不成立（下发的是数据，不是代码）。所以每条规则只允许「作用域 + 正则」两样东西，
// 引擎按包里的顺序逐条匹配。
//
// 作用域只能是边缘真的拿得到的位置。Tengine 的 auth_request 只把 method、URI、UA、
// Referer、Content-Type、Cookie 与客户端 IP 转给 cdnedge（见 site.conf.tmpl 里的
// proxy_set_header），所以这里没有"任意请求头"这一档 —— 想加必须先动模板，而模板改动
// 是节点级风险，不在本功能范围内。

// Scope 是托管规则的检测位置。
const (
	ScopeURL     = "url"     // 路径 + 查询串（RawPath+RawQuery+Path）
	ScopeBody    = "body"    // 请求体前 64KB（只查 POST/PUT/PATCH）
	ScopeUA      = "ua"      // User-Agent
	ScopeReferer = "referer" // Referer
	ScopeCookie  = "cookie"  // Cookie
	ScopeCT      = "ct"      // Content-Type
)

var validScopes = map[string]bool{
	ScopeURL: true, ScopeBody: true, ScopeUA: true,
	ScopeReferer: true, ScopeCookie: true, ScopeCT: true,
}

const (
	maxRulesPerPackage   = 256
	maxPatternsPerRule   = 32
	maxPatternLength     = 4096
	maxRuleNameLength    = 64
	maxRuleDescLength    = 200
	maxSetDescLength     = 400
	maxVersionLength     = 32
	maxPackageBodySample = 64 * 1024
)

// ManagedRule 是一条托管规则。
type ManagedRule struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Tier        int      `json:"tier"`
	Scopes      []string `json:"scopes"`
	Patterns    []string `json:"patterns"`
}

// RuleSet 是界面上的「规则集」卡片：勾选它等于启用它覆盖的规则（只增不减）。
type RuleSet struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Recommended bool     `json:"recommended"`
	Rules       []string `json:"rules"`
}

// RulePackage 是一个完整的规则包。
type RulePackage struct {
	Version   string        `json:"version"`
	UpdatedAt string        `json:"updated_at,omitempty"`
	Sets      []RuleSet     `json:"sets"`
	Rules     []ManagedRule `json:"rules"`
}

// compiledPattern 是一条已编译的正则及其作用域。
type compiledPattern struct {
	scope string
	re    *regexp.Regexp
}

type compiledRule struct {
	meta ManagedRule
	pats []compiledPattern
}

// Compiled 是编译好的规则包：匹配用的正则 + 给面板看的目录。
type Compiled struct {
	pkg   RulePackage
	order []*compiledRule
	byID  map[string]*compiledRule
	// rulesInSet 把「规则集 → 规则 id」反过来存一份：规则 id → 所属规则集 id。
	// 生效集合要按规则问"它属于哪个被勾选的集"，正着存每条规则都得扫一遍所有的集。
	rulesInSet map[string][]string
}

// CompilePackage 解析并编译规则包。任何一条正则编译失败都整体拒绝 ——
// 半套规则比旧规则更危险：面板以为新包生效了，实际只有一部分在跑。
func CompilePackage(data []byte) (*Compiled, error) {
	var pkg RulePackage
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("规则包不是合法 JSON: %w", err)
	}
	if err := validateVersion(pkg.Version); err != nil {
		return nil, err
	}
	if len(pkg.Rules) == 0 {
		return nil, fmt.Errorf("规则包里没有任何规则")
	}
	if len(pkg.Rules) > maxRulesPerPackage {
		return nil, fmt.Errorf("规则数量 %d 超过上限 %d", len(pkg.Rules), maxRulesPerPackage)
	}

	c := &Compiled{
		pkg:        pkg,
		byID:       make(map[string]*compiledRule, len(pkg.Rules)),
		rulesInSet: make(map[string][]string),
	}
	for i := range pkg.Rules {
		r := pkg.Rules[i]
		if err := validateRuleID(r.ID); err != nil {
			return nil, err
		}
		if _, dup := c.byID[r.ID]; dup {
			return nil, fmt.Errorf("规则 id 重复: %s", r.ID)
		}
		if len(r.Name) == 0 || len(r.Name) > maxRuleNameLength {
			return nil, fmt.Errorf("规则 %s 的 name 长度必须在 1~%d", r.ID, maxRuleNameLength)
		}
		if len(r.Description) > maxRuleDescLength {
			return nil, fmt.Errorf("规则 %s 的 description 长度不能超过 %d", r.ID, maxRuleDescLength)
		}
		if r.Tier < 1 || r.Tier > MaxTier {
			return nil, fmt.Errorf("规则 %s 的 tier 必须是 1~%d", r.ID, MaxTier)
		}
		if len(r.Scopes) == 0 {
			return nil, fmt.Errorf("规则 %s 没有任何作用域", r.ID)
		}
		for _, s := range r.Scopes {
			if !validScopes[s] {
				return nil, fmt.Errorf("规则 %s 的作用域 %q 不支持", r.ID, s)
			}
		}
		if len(r.Patterns) == 0 {
			return nil, fmt.Errorf("规则 %s 没有任何正则", r.ID)
		}
		if len(r.Patterns) > maxPatternsPerRule {
			return nil, fmt.Errorf("规则 %s 的正则数量 %d 超过上限 %d", r.ID, len(r.Patterns), maxPatternsPerRule)
		}
		cr := &compiledRule{meta: r}
		for _, p := range r.Patterns {
			if len(p) == 0 || len(p) > maxPatternLength {
				return nil, fmt.Errorf("规则 %s 有一条正则长度为 0 或超过 %d 字符", r.ID, maxPatternLength)
			}
			re, err := regexp.Compile(p)
			if err != nil {
				// RE2 不支持前后向断言，管理员手写时最容易撞这条，报错要说人话。
				return nil, fmt.Errorf("规则 %s 的正则编译失败（不支持前后向断言）: %v", r.ID, err)
			}
			for _, s := range r.Scopes {
				cr.pats = append(cr.pats, compiledPattern{scope: s, re: re})
			}
		}
		c.byID[r.ID] = cr
		c.order = append(c.order, cr)
	}

	for _, set := range pkg.Sets {
		if err := validateRuleID(set.ID); err != nil {
			return nil, fmt.Errorf("规则集: %w", err)
		}
		if len(set.Name) == 0 || len(set.Name) > maxRuleNameLength {
			return nil, fmt.Errorf("规则集 %s 的 name 长度必须在 1~%d", set.ID, maxRuleNameLength)
		}
		if len(set.Description) > maxSetDescLength {
			return nil, fmt.Errorf("规则集 %s 的 description 长度不能超过 %d", set.ID, maxSetDescLength)
		}
		for _, rid := range set.Rules {
			if c.byID[rid] == nil {
				return nil, fmt.Errorf("规则集 %s 引用了不存在的规则 %s", set.ID, rid)
			}
			c.rulesInSet[rid] = append(c.rulesInSet[rid], set.ID)
		}
	}
	// 规则集顺序按 id 稳定：面板卡片与"哪些规则被它覆盖"的读数在两次构建里必须一致。
	sort.Slice(c.pkg.Sets, func(i, j int) bool { return c.pkg.Sets[i].ID < c.pkg.Sets[j].ID })
	return c, nil
}

// CompilePackageEncrypted 解密并编译（下发的包与内置包都是 secure.Encrypt 的产物）。
func CompilePackageEncrypted(data []byte) (*Compiled, error) {
	plain, err := decryptRules(data)
	if err != nil {
		return nil, err
	}
	return CompilePackage(plain)
}

func (c *Compiled) Version() string { return c.pkg.Version }

// Package 返回目录视图（面板渲染卡片与单条规则用，不含正则本体）。
//
// 正则不外发是有意的：规则文本就是这台产品是自研的指纹，面板对客页面拿到 id/名称/
// 描述/档位/作用域已经足够勾选项了。
func (c *Compiled) Package() RulePackage {
	out := RulePackage{Version: c.pkg.Version, UpdatedAt: c.pkg.UpdatedAt}
	out.Sets = append([]RuleSet(nil), c.pkg.Sets...)
	out.Rules = make([]ManagedRule, 0, len(c.order))
	for _, cr := range c.order {
		out.Rules = append(out.Rules, ManagedRule{
			ID: cr.meta.ID, Name: cr.meta.Name, Description: cr.meta.Description,
			Tier: cr.meta.Tier, Scopes: append([]string(nil), cr.meta.Scopes...),
		})
	}
	return out
}

// RuleIDs 按包内声明顺序返回全部规则 id（匹配顺序，也是面板列表顺序）。
func (c *Compiled) RuleIDs() []string {
	ids := make([]string, 0, len(c.order))
	for _, cr := range c.order {
		ids = append(ids, cr.meta.ID)
	}
	return ids
}

func (c *Compiled) rule(id string) *compiledRule { return c.byID[id] }

func (c *Compiled) ruleCount() int { return len(c.order) }

func validateVersion(v string) error {
	if v == "" || len(v) > maxVersionLength {
		return fmt.Errorf("规则包 version 不能为空且长度不能超过 %d", maxVersionLength)
	}
	for i, r := range v {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' ||
			(r == '.' || r == '_' || r == '-') && i > 0) {
			return fmt.Errorf("规则包 version %q 含非法字符（只允许字母数字与 . _ -，且不能以符号开头）", v)
		}
	}
	return nil
}

// validateRuleID 同时用于规则 id 与规则集 id：两者都要当 map 键和界面 key 用。
func validateRuleID(id string) error {
	if id == "" || len(id) > maxVersionLength {
		return fmt.Errorf("id 不能为空且长度不能超过 %d: %q", maxVersionLength, id)
	}
	for i, r := range id {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r == '-' || r == '_' && i > 0) {
			return fmt.Errorf("id %q 含非法字符（只允许小写字母、数字、- 和 _，且不能以符号开头）", id)
		}
	}
	return nil
}

// MaxTier 是档位的上界：安全级别「攻击中」对应的就是这一档。
const MaxTier = 4

// tierByLevel 把面板的安全级别换成"执行到第几档"。
// 关闭 = 0 条，攻击中 = 全部（含误报面最大的 4 档：CRLF、LDAP、Java 反序列化）。
func tierByLevel(level string) int {
	switch level {
	case LevelOff:
		return 0
	case LevelLow:
		return 1
	case LevelMedium:
		return 2
	case LevelHigh:
		return 3
	case LevelAttack:
		return MaxTier
	}
	return 2 // 未知级别按「中」处理，而不是按 0 把防护关掉
}

// ruleIDList 去重并排序，给面板与下发 payload 用（保证同一份配置序列化出来字节一致）。
func ruleIDList(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}
