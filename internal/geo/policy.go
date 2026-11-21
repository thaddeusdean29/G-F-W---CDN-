package geo

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
)

// 这一份是「主控校验」「面板回显」「边缘判定」共用的唯一定义。
//
// 分成两套的后果本项目已经吃过一次：WAF 那边 normalize 静默改值，面板存了一份
// 节点其实不认的配置。所以这里只允许一处翻译，非法值一律当场拒绝而不是纠正。

const (
	ModeObserve = "observe" // 只记账，不拦。默认值：新开的区域规则先进观察，确认读数再开拦
	ModeBlock   = "block"   // 真的拦：七层 403，四层丢包
)

const (
	ActionDeny  = "deny"  // 拒绝 Countries 里这些国家，其余放行
	ActionAllow = "allow" // 只放行 Countries 里这些国家，其余拒绝
)

// Policy 是一条区域规则。同一个结构用在三个地方：
// 平台管理员的整节点策略（L4）、代理保存的默认策略、每个域名的策略（L7）。
// 字段语义完全一致，差别只有作用范围，所以判定与校验只写一遍。
type Policy struct {
	Enabled bool `json:"enabled"`
	// Mode 只在 Enabled 时有意义。关掉规则用 Enabled，不要靠往 Mode 里塞 "off"：
	// 那样会出现"enabled=true 且 mode=off"这种没人能解释的组合。
	Mode       string   `json:"mode"`
	Action     string   `json:"action"`
	Countries  []string `json:"countries"`
	Exceptions []string `json:"exceptions"` // 永远放行的 CIDR/IP：主控、节点互联、ACME 探测源
}

// DefaultPolicy 是「什么都没配」时面板与边缘各自持有的同一份初始值。
// 两边必须一致，否则新装节点上报的读数会和面板显示的不一样。
func DefaultPolicy() Policy {
	return Policy{Mode: ModeObserve, Action: ActionDeny, Countries: []string{}, Exceptions: []string{}}
}

// WithDefaults 补上"没写过"的那几个字段：存量域名的 geo_policy 是 {}，解出来 Mode/Action
// 都是空串，直接回显会给面板一份看起来非法的配置。补默认只用在读出与下发时，
// 不顺手写回库里——一次 GET 不该改别人的配置版本。
func (p Policy) WithDefaults() Policy {
	if p.Mode == "" {
		p.Mode = ModeObserve
	}
	if p.Action == "" {
		p.Action = ActionDeny
	}
	if p.Countries == nil {
		p.Countries = []string{}
	}
	if p.Exceptions == nil {
		p.Exceptions = []string{}
	}
	return p
}

// Normalize 排序去重、把国家码统一成大写、把 CIDR 归一成带掩码的写法。
// 只改「同义写法」，不改语义值：认不出的 mode/action 原样留着，交给 Validate 报错。
func (p *Policy) Normalize() {
	p.Countries = upperCodes(p.Countries)
	p.Exceptions = cleanNets(p.Exceptions)
}

// Wants 返回这条策略需要编译进去的国家码（已归一）。没启用就一条都不需要：
// 关着的规则不该往节点上塞几十万个前缀。
func (p Policy) Wants() []string {
	if !p.Enabled {
		return nil
	}
	return p.Countries
}

// ── 平台管理员那一份：能力开关 + 可选范围 + 整节点策略 ─────────────────────

// Scope 存在 platform_settings 里，键名 "geo_scope"。
type Scope struct {
	// Enabled 是能力总闸。关掉时租户侧照旧能保存自己的策略（不改掉别人的配置），
	// 但边缘判定直接跳过 —— 面板要显示"平台未开放"这个原因，不能装作规则在跑。
	Enabled bool `json:"enabled"`
	// Selectable 是允许租户选择的国家范围；空表示不限（任何合法两位码都能选）。
	// 它管的是"租户能挑哪些"，不管管理员自己的整节点策略。
	Selectable []string `json:"selectable"`
	Node       Policy   `json:"node"`
}

func DefaultScope() Scope {
	s := Scope{Selectable: []string{}, Node: DefaultPolicy()}
	// 整节点丢包一旦开拦就是全网一刀切，所以它的出厂默认是观察，且国家清单为空。
	s.Node.Mode = ModeObserve
	return s
}

func (s *Scope) Normalize() {
	s.Selectable = upperCodes(s.Selectable)
	s.Node.Normalize()
}

// CanSelect 判断某个国家码是否落在管理员开放的范围内。
// 域名策略保存时用它做拒绝依据；范围变化不会自动删掉别人已经配好的国家，
// 那种"顺手清理"会把租户的规则改得面目全非，改成保存时拒绝、页面上标出来。
func (s Scope) CanSelect(code string) bool {
	if len(s.Selectable) == 0 {
		return true
	}
	for _, c := range s.Selectable {
		if c == code {
			return true
		}
	}
	return false
}

// SelectableList 给面板用：空范围时返回 nil，前端据此显示"不限（全部国家可选）"。
func (s Scope) SelectableList() []string {
	if len(s.Selectable) == 0 {
		return nil
	}
	return s.Selectable
}

// ── 校验 ──────────────────────────────────────────────────────────────────

// FieldErrors 是「字段名 → 拒绝原因」。返回空表示通过。
// 用 map 而不是 error，是因为 API 层要一次把每个非法字段都说清楚（见 apiv2.geoValidationError）。
type FieldErrors map[string]string

func (f FieldErrors) OK() bool { return len(f) == 0 }

// ValidatePolicy 校验一条策略。selectable 为 nil 表示不受平台范围限制。
//
// Countries 为空必须拒绝（Enabled 时）：allow 配空清单等于拒绝所有来源，
// 而它看起来更像"还没配"，让人在页面上找不到自己那条规则。
func ValidatePolicy(p Policy, selectable []string) FieldErrors {
	out := FieldErrors{}
	switch p.Mode {
	case ModeObserve, ModeBlock:
	default:
		out["mode"] = "只能是 observe 或 block"
	}
	switch p.Action {
	case ActionDeny, ActionAllow:
	default:
		out["action"] = "只能是 deny（封禁所列国家）或 allow（只放行所列国家）"
	}
	for _, c := range p.Countries {
		if !validCode(c) {
			out["countries"] = fmt.Sprintf("国家码 %q 不合法：要用 ISO 3166-1 alpha-2 两位字母码", c)
			break
		}
	}
	if p.Enabled && len(p.Countries) == 0 {
		out["countries"] = "启用区域规则至少要选一个国家"
	}
	for _, c := range p.Countries {
		if selectable != nil && !inList(selectable, c) {
			out["countries"] = "以下国家不在平台开放的范围内：" + c
			break
		}
	}
	if bad := badNets(p.Exceptions); bad != "" {
		out["exceptions"] = "例外地址不合法：" + bad
	}
	return out
}

// ValidateScope 校验管理员那一份。整节点策略有两个额外限制：
//  1. 只允许 action=deny。四层看不到 HTTP host，也无法区分「这个 IP 属于允许清单」
//     和「这个 IP 库里根本没有归属」—— allow 语义要靠"归属未知也放行"才成立，
//     而 XDP 一旦做不到就只能把未知地址一起丢，那是静默扩权，所以直接拒绝。
//     需要 allow（只允许某些国家）请用在七层的域名策略上。
//  2. 例外清单不能是空：主控 IP、节点互联 IP 一旦落在封禁国家里，
//     丢包会让这台节点从集群里消失，而它自己不会报错。
func ValidateScope(s Scope) FieldErrors {
	out := FieldErrors{}
	for _, c := range s.Selectable {
		if !validCode(c) {
			out["selectable"] = fmt.Sprintf("国家码 %q 不合法：要用两位字母码，或留空表示不限", c)
			break
		}
	}
	// 整节点策略不受 Selectable 限制（那是给租户划的范围），但它自己必须能执行。
	in := out.add(ValidatePolicy(s.Node, nil), "")
	if s.Node.Enabled && s.Node.Action == ActionAllow {
		in["action"] = "整节点（四层丢包）只支持 deny：四层分不清「归属未知」和「不在允许清单」，" +
			"配 allow 会把未知归属的流量一起丢掉。要按国家只放行，请用在域名的七层规则上"
	}
	if s.Node.Enabled && len(s.Node.Exceptions) == 0 {
		in["exceptions"] = "整节点策略必须至少填一条例外 IP/CIDR（主控与节点互联地址），" +
			"否则封禁国家内的管理流量会一起被丢掉，节点会从集群里消失且不报错"
	}
	out = merge(out, in)
	return out
}

func (f FieldErrors) add(in FieldErrors, prefix string) FieldErrors {
	for k, v := range in {
		f[prefix+k] = v
	}
	return f
}

func merge(a, b FieldErrors) FieldErrors {
	for k, v := range b {
		if _, ok := a[k]; !ok {
			a[k] = v
		}
	}
	return a
}

func validCode(c string) bool {
	if len(c) != 2 {
		return false
	}
	for i := 0; i < 2; i++ {
		if c[i] < 'A' || c[i] > 'Z' {
			return false
		}
	}
	return true
}

func inList(list []string, v string) bool {
	for _, e := range list {
		if e == v {
			return true
		}
	}
	return false
}

func upperCodes(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, c := range in {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c == "" || seen[c] {
			continue
		}
		seen[c] = true
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// cleanNets 把例外清单归一：裸 IP 补成全主机掩码，非法项原样保留（由 badNets 拒绝），
// 免得校验一失败页面就显示空白，谁也看不出是哪一行写错了。
func cleanNets(in []string) []string {
	out := make([]string, 0, len(in))
	seen := map[string]bool{}
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if n := normalizeNet(s); n != "" {
			s = n
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func normalizeNet(s string) string {
	if strings.IndexByte(s, '/') < 0 {
		ip := net.ParseIP(s)
		if ip == nil {
			return ""
		}
		if ip.To4() != nil {
			return s + "/32"
		}
		return ip.String() + "/128"
	}
	_, nw, err := net.ParseCIDR(s)
	if err != nil {
		return ""
	}
	// ParseCIDR 返回的 nw.IP 已经按掩码对齐，ones 取实际前缀长度：
	// "10.1.2.3/8" 归一成 "10.0.0.0/8"，存库与下发的是同一串，页面上也就看得出一行。
	ones, _ := nw.Mask.Size()
	return nw.IP.String() + "/" + strconv.Itoa(ones)
}

func badNets(in []string) string {
	for _, s := range in {
		if _, _, err := net.ParseCIDR(s); err != nil {
			return s
		}
	}
	return ""
}

// ── 例外匹配 ──────────────────────────────────────────────────────────────

// ExceptionSet 是编译好的例外清单。例外只有几条到几十条，线性比掩码就够，
// 不值得为它再上一棵树——但它必须和封禁判定在同一份代码里算完，
// 否则两边各比一次会给出不同的放行结论。
type ExceptionSet struct {
	v4 []net4
	v6 []net6
}

type net4 struct {
	addr uint32
	mask uint32
	// ones 存的是同一条例外的前缀长度。装 LPM trie 要前缀长度、Contains 要掩码，
	// 两处都从 ParseCIDR 的同一个 ones 算出来，就不存在"七层认这条例外、四层不认"
	// 这种各推一次推出来的分歧。
	ones uint8
}

type net6 struct {
	addr [16]byte
	bits uint8
}

// CompileExceptions 解析 CIDR 清单。解析失败的那条直接返回 error：
// 例外少认一条，等于把一个本该放行的地址放到被封的位置上。
func CompileExceptions(in []string) (*ExceptionSet, error) {
	set := &ExceptionSet{}
	for _, s := range in {
		ip, nw, err := net.ParseCIDR(s)
		if err != nil {
			// 兼容裸 IP：面板上填一个地址不带掩码是很自然的写法。
			if single := net.ParseIP(s); single != nil {
				if single.To4() != nil {
					ip, nw, err = net.ParseCIDR(s + "/32")
				} else {
					ip, nw, err = net.ParseCIDR(single.String() + "/128")
				}
			}
			if err != nil {
				return nil, fmt.Errorf("例外 %q 不是合法的 IP 或 CIDR", s)
			}
		}
		_ = ip
		ones, bits := nw.Mask.Size()
		if bits == 32 {
			set.v4 = append(set.v4, net4{
				addr: binary32(nw.IP),
				mask: ^uint32(0) << uint(32-ones),
				ones: uint8(ones),
			})
			continue
		}
		var a [16]byte
		copy(a[:], nw.IP.To16())
		align6(&a, ones)
		set.v6 = append(set.v6, net6{addr: a, bits: uint8(ones)})
	}
	return set, nil
}

func binary32(ip net.IP) uint32 {
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return uint32(v4[0])<<24 | uint32(v4[1])<<16 | uint32(v4[2])<<8 | uint32(v4[3])
}

func (s *ExceptionSet) Contains(ip net.IP) bool {
	if s == nil || (len(s.v4) == 0 && len(s.v6) == 0) {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		a := binary32(v4)
		for _, n := range s.v4 {
			if a&n.mask == n.addr {
				return true
			}
		}
		return false
	}
	v6 := ip.To16()
	if v6 == nil {
		return false
	}
	var a [16]byte
	copy(a[:], v6)
	for _, n := range s.v6 {
		if samePrefix6(n.addr, a, n.bits) {
			return true
		}
	}
	return false
}

// ── 判定 ──────────────────────────────────────────────────────────────────

// List4 把例外清单摊成 v4 前缀记录，供四层装进 LPM trie。Country 留空：
// 例外不属于任何国家，装进 trie 后 C 侧也只看"命中/没命中"。
func (s *ExceptionSet) List4() []Entry4 {
	if s == nil {
		return nil
	}
	out := make([]Entry4, 0, len(s.v4))
	for _, n := range s.v4 {
		out = append(out, Entry4{Addr: n.addr, Bits: n.ones})
	}
	return out
}

// List6 同上，IPv6。
func (s *ExceptionSet) List6() []Entry6 {
	if s == nil {
		return nil
	}
	out := make([]Entry6, 0, len(s.v6))
	for _, n := range s.v6 {
		out = append(out, Entry6{Addr: n.addr, Bits: n.bits})
	}
	return out
}

// Why 是一次判决的来由。每个分支都要能被单独记账：把「归属未知」并进「放行」
// 或「拦截」都会让库没覆盖到的那部分流量在任何数字里消失。
type Why string

const (
	WhyOff       Why = "off"       // 规则没启用，或平台总闸关着
	WhyException Why = "exception" // 命中例外清单，放行
	WhyUnknown   Why = "unknown"   // 表里没有这个地址的归属，放行但单独计
	WhyPass      Why = "pass"      // 按名单判定应当放行
	WhyHit       Why = "hit"       // 命中名单：Mode=block 才真的拦
)

// Result 是一次判定的完整结论。Blocked 只在真拦的时候为 true，
// 观察模式下 WhyHit 依旧成立但 Blocked=false —— 页面据此显示"本应拦下 N 次"。
type Result struct {
	Why     Why
	Country string
	Blocked bool
}

func (r Result) String() string {
	if r.Country == "" {
		return string(r.Why)
	}
	return fmt.Sprintf("%s:%s", r.Why, r.Country)
}

// Decide 是唯一的判定入口：七层每个请求、四层装表前的自检都走它。
// scopeEnabled 传平台总闸；关掉时任何域名规则都不执行，但仍然返回 WhyOff，
// 让上报里能出现"因为平台没开而没执行"这件事，而不是悄悄什么都不记。
func Decide(p Policy, scopeEnabled bool, tbl *Table, ex *ExceptionSet, ip net.IP) Result {
	if !p.Enabled || !scopeEnabled {
		return Result{Why: WhyOff}
	}
	if ex.Contains(ip) {
		return Result{Why: WhyException}
	}
	if tbl == nil {
		// 表没就位：一条都不判。这一步必须是放行而不是拦，否则"库还没下下来"
		// 会变成"全网 403"。
		return Result{Why: WhyUnknown}
	}
	code, covered := tbl.Country(ip)
	if !covered {
		return Result{Why: WhyUnknown}
	}
	switch p.Action {
	case ActionAllow:
		if inList(p.Countries, code) {
			return Result{Why: WhyPass, Country: code}
		}
		return Result{Why: WhyHit, Country: code, Blocked: p.Mode == ModeBlock}
	default: // ActionDeny
		if inList(p.Countries, code) {
			return Result{Why: WhyHit, Country: code, Blocked: p.Mode == ModeBlock}
		}
		return Result{Why: WhyPass, Country: code}
	}
}

// CountriesFrom 汇总多条策略真正需要编译进表的国家：这是「表只装被引用的国家」
// 这条压缩率来源，也是"改一个域名的清单就要重推全网几十万个前缀"的避免办法。
// 结果里同时含整节点策略与各域名策略的国家，去重排序。
func CountriesFrom(policies ...Policy) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range policies {
		for _, c := range p.Wants() {
			if seen[c] {
				continue
			}
			seen[c] = true
			out = append(out, c)
		}
	}
	sort.Strings(out)
	return out
}
