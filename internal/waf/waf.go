package waf

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Action 定义 WAF 对请求的处置动作。
type Action int

const (
	Allow Action = iota
	Block
	// Challenge 表示请求命中了 CC 强检测（域名处于攻击态且未带有效验证凭证），
	// 需要先经过 JS 环境验证页确认是真实浏览器后才能放行。
	Challenge
)

// Result WAF 检测结果。
type Result struct {
	Action  Action
	Rule    string // 触发的规则名
	Message string // 日志描述
}

// Engine WAF 规则引擎（线程安全）。
//
// 执行分两段，这个划分是有意的：
//   - 内置段（CheckBase/CheckUpload）：IP 封禁表、ACME 路径限速、UA 校验、上传校验。
//     它们不来自规则包，也不受"启用 WAF 防护"开关控制 —— 封禁表是全节点共享的一份，
//     代理把开关关掉只是"我不想跑签名规则"，不该顺手把别人（或自己另一条域名）
//     已经生效的封禁清掉。
//   - 托管段（InspectManaged）：来自规则包的正则规则，受开关、级别、规则集、
//     单条覆盖与规则包版本/灰度控制。管理员能在面板上改的就是这一段。
type Engine struct {
	mu sync.RWMutex
	// active/previous 是两个已编译的规则包。面板下发成功后原子替换；
	// 内置包（go:embed 的 rules.enc）永远是启动时的 active，下发失败不会把它清掉。
	active   *Compiled
	previous *Compiled
	policy   Policy
	// allowCache 按「包版本|策略指纹」缓存生效规则集。热路径上每条请求都要问
	// "这条规则现在生效吗"，用级别+规则集+单条覆盖现算的话每请求要扫十几条规则与
	// 四个集；缓存之后变成一次 map 查。策略或包一变，键就变，自动重算。
	allowCache map[string]map[string]struct{}
	hits       *hitTracker

	ipBlock        *ipBlockList
	l4BlockHook    func(ip string, dur time.Duration) // 可选：把封禁同步到 L4（XDP）
	l4UnblockHook  func(ip string)                    // 可选：把解封同步到 L4（XDP）
	loginProtector *LoginBruteforceProtector          // 登录暴力破解防护（可选）
	fileValidator  *FileUploadValidator               // 文件上传验证器
	uaValidator    *UserAgentValidator                // User-Agent 验证器
	acmeLimiter    *ACMERateLimiter                   // ACME 路径速率限制器
	h2RapidReset   *HTTP2RapidResetDetector           // HTTP/2 Rapid Reset 检测器
	cacheBuster    *CacheBusterDetector               // 缓存绕过攻击检测器
}

// SetL4BlockHook 注册一个把 L7 封禁同步到 L4（XDP blocklist）的钩子。
// 由 cmd/cdnedge 在 XDP 加载成功后注入，waf 包本身不依赖 xdp 包，避免循环。
func (e *Engine) SetL4BlockHook(hook func(ip string, dur time.Duration)) {
	e.l4BlockHook = hook
}

// SetL4UnblockHook 注册解封钩子，与 SetL4BlockHook 配对。
// 少了它，解封只清 L7 封禁表，IP 仍留在 XDP blocklist 里被 DROP——
// 表现为「面板显示已解封，用户依然无法访问」，且这种残留无法从 L7 侧清掉。
func (e *Engine) SetL4UnblockHook(hook func(ip string)) {
	e.l4UnblockHook = hook
}

// EnableLoginBruteforceProtection 启用登录端点暴力破解防护。
// 应在初始化时调用，传入登录端点路径列表（如 []string{"/api/login", "/admin/login"}）。
func (e *Engine) EnableLoginBruteforceProtection(cfg LoginBruteforceConfig) {
	e.loginProtector = NewLoginBruteforceProtector(cfg, e)
}

// EnableHTTP2RapidResetDetection 启用 HTTP/2 Rapid Reset 攻击检测。
func (e *Engine) EnableHTTP2RapidResetDetection(cfg RapidResetConfig) {
	e.h2RapidReset = NewHTTP2RapidResetDetector(cfg)
}

// GetHTTP2RapidResetDetector 获取 HTTP/2 Rapid Reset 检测器（供边缘节点记录 RST_STREAM 帧）。
func (e *Engine) GetHTTP2RapidResetDetector() *HTTP2RapidResetDetector {
	return e.h2RapidReset
}

// GetLoginProtector 获取登录暴力破解防护器（供应用层调用 RecordFailure/RecordSuccess）。
func (e *Engine) GetLoginProtector() *LoginBruteforceProtector {
	return e.loginProtector
}

// builtinPackage 编译 go:embed 进来的内置规则包。它是兜底档：面板下发的包坏了、
// 或节点从没能连上主控，边缘至少带着出厂规则运行。
//
// 用 sync.Once + 全局变量而不是包级 init() panic：编译内置包的是每个 NewEngine
// （面板与边缘都会建引擎），一旦内置包有问题，让它在使用点报错比在 init 里把整台进程
// 拖死更好排查 —— 但结论仍然是"不许静默降级"，所以这里编译失败照样 panic。
var (
	builtinOnce   sync.Once
	builtinPkg    *Compiled
	builtinPkgErr error
)

func builtinPackage() *Compiled {
	builtinOnce.Do(func() {
		builtinPkg, builtinPkgErr = CompilePackageEncrypted(rulesEnc)
		if builtinPkgErr != nil {
			panic("waf: failed to compile built-in rule package: " + builtinPkgErr.Error())
		}
	})
	return builtinPkg
}

// NewEngine 创建带内置规则包、默认策略的 WAF 引擎。
func NewEngine() *Engine {
	e := &Engine{
		active:     builtinPackage(),
		policy:     DefaultPolicy(),
		allowCache: map[string]map[string]struct{}{},
		hits:       newHitTracker(),
		ipBlock:    newIPBlockList(),

		fileValidator: NewFileUploadValidator(32 << 20), // 32MB
		cacheBuster:   NewCacheBusterDetector(),
		uaValidator:   NewUserAgentValidator(),
		acmeLimiter:   NewACMERateLimiter(10, 20, time.Minute), // 每 IP 10次/分钟，每域名 20次/分钟
		h2RapidReset:  nil,                                     // HTTP/2 Rapid Reset 默认禁用，需显式启用
	}
	return e
}

// ── 内置段 ──────────────────────────────────────────────────────

// CheckBase 执行与规则包无关的前置内置检查：IP 封禁表、ACME 路径限速、UA 校验。
// 这三条不受托管规则开关控制，理由见 Engine 的注释。
func (e *Engine) CheckBase(r *http.Request) *Result {
	for _, check := range []func(*http.Request) *Result{e.checkIPBlocklist, e.checkACMELimit, e.checkUserAgent} {
		if res := check(r); res != nil && res.Action == Block {
			return res
		}
	}
	return &Result{Action: Allow}
}

// CheckUpload 执行上传校验（multipart 文件名与魔术字节）。放在托管段之后，
// 与升级前的顺序一致：托管规则先读走请求体样本，这里再解析 multipart。
func (e *Engine) CheckUpload(r *http.Request) *Result {
	if res := e.checkFileUpload(r); res != nil && res.Action == Block {
		return res
	}
	return &Result{Action: Allow}
}

// ── 托管段 ──────────────────────────────────────────────────────

// InspectManaged 按当前策略与该 Host 分流到的规则包匹配托管规则。
//
// 返回的 Verdict 里 Hit 表示"命中了某条生效规则"，Observe 表示这次命中该不该只记账。
// 判定与处置分开是为了让观察模式留下证据：把观察折成 Allow 的话，面板上灰度验证
// 就变成"什么都没发生"，那条开关就成了假功能。
//
// 每次命中都记账（含内置段之外的托管段），所以观察模式跑完之后切拦截，读数会连续。
func (e *Engine) InspectManaged(r *http.Request) Verdict {
	e.mu.RLock()
	pol := e.policy
	pkg := e.pickLocked(r.Host, pol)
	e.mu.RUnlock()

	if pkg == nil {
		// 两个包都没了：只在 NewEngine 之后被下发过坏数据才可能走到这里，
		// 而坏数据在 SetPackages 里已被拒收。留这条兜底是为了让判定永不 panic。
		return Verdict{Reason: "no-package"}
	}
	if !pol.Enabled {
		return Verdict{Package: pkg.Version(), Reason: "disabled"}
	}

	observe := pol.observe()
	allow := e.effective(pkg, pol)

	tg := &targets{r: r}
	for _, cr := range pkg.order {
		if _, on := allow[cr.meta.ID]; !on {
			continue
		}
		for _, p := range cr.pats {
			target := tg.scope(p.scope)
			if len(target) == 0 {
				continue
			}
			if !p.re.Match(target) {
				continue
			}
			e.hits.add(cr.meta.ID, observe)
			return Verdict{
				Hit: true, Rule: cr.meta.ID, Name: cr.meta.Name,
				Message: fmt.Sprintf("%s 命中 %s: %s", p.scope, cr.meta.ID, summarizeMatch(p.re, target)),
				Observe: observe, Package: pkg.Version(),
			}
		}
	}
	return Verdict{Package: pkg.Version()}
}

// summarizeMatch 给出命中片段的可读摘要（最多 80 字节，且不回显完整请求）。
// 日志与面板读数里落的是"哪一段像攻击"，不是整个请求体 —— 请求体里可能有用户数据。
func summarizeMatch(re *regexp.Regexp, target []byte) string {
	loc := re.Find(target)
	if len(loc) == 0 {
		return ""
	}
	s := string(loc)
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	// 控制字符直接写进日志会把一行拆成几行，攻击者还能用它伪造日志条目。
	return strings.ToValidUTF8(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, s), "?")
}

// pickLocked 选出这次请求用哪个规则包。调用方须持有读锁。
//
// 顺序：显式固定版本 > active。灰度只在"没固定版本"时生效 —— 固定版本的语义是
// "这条配置就要吃这一份"，再按 Host 分流等于把回滚按钮变成随机数。
func (e *Engine) pickLocked(host string, pol Policy) *Compiled {
	if pol.RulesVersion != "" {
		if e.active != nil && e.active.Version() == pol.RulesVersion {
			return e.active
		}
		if e.previous != nil && e.previous.Version() == pol.RulesVersion {
			return e.previous
		}
		// 节点上没有这个版本（多半是下发失败或包被删了）：退回 active 而不是放行，
		// 并在包读数里标出来，让面板看得见"这条代理想用的包不在节点上"。
		return e.active
	}
	if e.previous == nil || pol.GrayPercent <= 0 {
		return e.active
	}
	if hostGrayBucket(host) < pol.GrayPercent {
		return e.previous
	}
	return e.active
}

// hostGrayBucket 把 Host 映射到 0~99 的稳定桶。
// 用 FNV-1a 而不是随机数：同一个域名在每台节点上必须落进同一个桶，否则"10% 灰度"
// 会变成"每台节点各切 10% 的不同域名"，验证结果没法复现。
func hostGrayBucket(host string) int {
	h := strings.ToLower(strings.TrimSpace(host))
	if hp, _, err := net.SplitHostPort(h); err == nil {
		h = hp
	}
	if h == "" {
		return 0
	}
	var hash uint32 = 2166136261
	for i := 0; i < len(h); i++ {
		hash ^= uint32(h[i])
		hash *= 16777619
	}
	return int(hash % 100)
}

// EffectiveRules 返回给定策略与包下真正生效的规则 id（按包内声明顺序）。
//
// 面板回显与边缘执行必须用同一个函数：否则界面显示"这 14 条都开着"，
// 边缘实际按级别只跑 5 条 —— 灰度验证时没有任何人能解释为什么没命中。
func EffectiveRules(pkg *Compiled, pol Policy) []string {
	if pkg == nil || !pol.Enabled {
		return nil
	}
	tier := tierByLevel(pol.Level)
	setsOn := make(map[string]bool, len(pol.Sets))
	for _, id := range pol.Sets {
		setsOn[id] = true
	}
	out := make([]string, 0, len(pkg.order))
	for _, cr := range pkg.order {
		on := cr.meta.Tier <= tier
		if !on {
			for _, setID := range pkg.rulesInSet[cr.meta.ID] {
				if setsOn[setID] {
					on = true
					break
				}
			}
		}
		if want, explicit := pol.Rules[cr.meta.ID]; explicit {
			on = want
		}
		if on {
			out = append(out, cr.meta.ID)
		}
	}
	return out
}

// effective 带缓存地取生效规则集合。
//
// 热路径先只拿读锁查缓存；只有策略或包变了（键变了）才升级成写锁重算一次。
// 重算是幂等的：两个 goroutine 同时 miss 会各算一份、后写的覆盖先写的，结果一致。
// 返回的 map 之后绝不修改（缓存溢出时整张换新，旧 map 仍然只读有效），所以调用方
// 可以在锁外逐条查它。
func (e *Engine) effective(pkg *Compiled, pol Policy) map[string]struct{} {
	key := pkg.Version() + "|" + pol.fingerprint()

	e.mu.RLock()
	set, ok := e.allowCache[key]
	e.mu.RUnlock()
	if ok {
		return set
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if set, ok := e.allowCache[key]; ok {
		return set
	}
	set = map[string]struct{}{}
	for _, id := range EffectiveRules(pkg, pol) {
		set[id] = struct{}{}
	}
	// 键里含策略指纹，代理改一次配置就换一把键；不清旧键会让这张表随配置改动无限长。
	// 16 把够用（一个节点上的代理数量远小于此），超了整张重建而不是逐个淘汰——
	// 淘汰算法在这种规模下只会增加出错面。
	if len(e.allowCache) > 16 {
		e.allowCache = map[string]map[string]struct{}{}
	}
	e.allowCache[key] = set
	return set
}

// ── 规则包与策略的下发接口 ──────────────────────────────────────

// SetPackages 换上新的 active/previous 包（两者都已编译好）。传入 nil 表示保持原值。
//
// 换包时清空命中读数：旧包的命中数与包版本绑定，留在图上会让"新包到底生效了没有"
// 这个问题没法回答。
func (e *Engine) SetPackages(active, previous *Compiled) {
	e.mu.Lock()
	// 版本比较必须在锁内直接读字段：activeVersion/previousVersion 各自要拿读锁，
	// 在这里调它们等于拿着写锁再抢读锁 —— sync.RWMutex 不可重入，第一次下发就死锁。
	changed := (active != nil && active.Version() != versionOf(e.active)) ||
		(previous != nil && previous.Version() != versionOf(e.previous))
	if active != nil {
		e.active = active
	}
	if previous != nil {
		e.previous = previous
	}
	e.allowCache = map[string]map[string]struct{}{}
	e.mu.Unlock()

	if changed {
		e.hits.reset()
	}
}

func versionOf(c *Compiled) string {
	if c == nil {
		return ""
	}
	return c.Version()
}

// UpdatePolicy 应用面板下发的策略。缺失字段按"保持原值"处理，所以调用方传的是
// 逐字段 patch（见 edgeapi.updateWAFConfig），而不是一把 nil 就归零的结构体。
func (e *Engine) UpdatePolicy(patch PolicyPatch) Policy {
	e.mu.Lock()
	next := e.policy
	next.Apply(patch)
	e.policy = next
	e.mu.Unlock()
	return next
}

// GetPolicy 返回当前策略（值拷贝；Rules map 只读，改它请走 UpdatePolicy）。
func (e *Engine) GetPolicy() Policy {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.policy
}

// Effective 返回本节点"当前策略 + 当前 active 包"下真正生效的规则 id。
// 面板回显与边缘执行走的是同一个 EffectiveRules，界面显示的和节点实跑的一致。
func (e *Engine) Effective() []string {
	e.mu.RLock()
	pol, pkg := e.policy, e.active
	e.mu.RUnlock()
	return EffectiveRules(pkg, pol)
}

// PackageReadings 是本节点规则包的实际装载情况，供面板回答"这条代理现在吃的是哪份包"。
type PackageReadings struct {
	Active     string `json:"active"`
	Previous   string `json:"previous"`
	Builtin    string `json:"builtin"`
	Pinned     string `json:"pinned,omitempty"`
	PinMissing bool   `json:"pin_missing,omitempty"`
}

// Packages 返回装载读数。PinMissing 在"策略固定了一个本节点没有的版本"时为 true——
// 这种情况下执行回落到 active，必须让面板看见，不能悄悄降级。
func (e *Engine) Packages() PackageReadings {
	e.mu.RLock()
	defer e.mu.RUnlock()
	r := PackageReadings{Pinned: e.policy.RulesVersion}
	if e.active != nil {
		r.Active = e.active.Version()
	}
	if e.previous != nil {
		r.Previous = e.previous.Version()
	}
	if b := builtinPackage(); b != nil {
		r.Builtin = b.Version()
	}
	if r.Pinned != "" && r.Pinned != r.Active && r.Pinned != r.Previous {
		r.PinMissing = true
	}
	return r
}

// Catalog 返回当前 active 包的目录（规则集与单条规则的元数据）。
// 面板渲染配置界面时用的就是它，正则本体不外发（见 Compiled.Package 的注释）。
func (e *Engine) Catalog() RulePackage {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.active == nil {
		return RulePackage{}
	}
	return e.active.Package()
}

// CatalogVersion 返回指定版本（active/previous/内置）的目录，供面板展示旧包内容。
// version 空串 = active。
func (e *Engine) CatalogVersion(version string) (RulePackage, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, pkg := range []*Compiled{e.active, e.previous, builtinPackage()} {
		if pkg != nil && (version == "" || pkg.Version() == version) {
			return pkg.Package(), true
		}
	}
	return RulePackage{}, false
}

// RuleName 供命中读数回填规则名。
func (e *Engine) RuleName(id string) string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	for _, pkg := range []*Compiled{e.active, e.previous, builtinPackage()} {
		if pkg == nil {
			continue
		}
		if cr := pkg.byID[id]; cr != nil {
			return cr.meta.Name
		}
	}
	return ""
}

// Hits 返回托管规则命中读数与总数（面板 WAF 页 / 边缘 stats 端点共用）。
func (e *Engine) Hits() (rows []HitRow, observe, blocked uint64) {
	observe, blocked = e.hits.totals()
	return e.hits.snapshot(e.RuleName), observe, blocked
}

// SetPolicy 整体替换策略（启动时从本地存档恢复用；面板下发走 UpdatePolicy）。
func (e *Engine) SetPolicy(pol Policy) {
	if pol.Mode == "" {
		pol.Mode = ModeBlock
	}
	if pol.Level == "" {
		pol.Level = LevelMedium
	}
	if pol.Rules == nil {
		pol.Rules = map[string]bool{}
	}
	e.mu.Lock()
	e.policy = pol
	e.allowCache = map[string]map[string]struct{}{}
	e.mu.Unlock()
}

// BlockIP 动态封禁 IP（带过期时间）。同步推送到 L4 blocklist（若注入了 hook），
// 让下一波包在 XDP 层就 DROP，不再进入 Tengine/内核栈。
func (e *Engine) BlockIP(ip string, dur time.Duration) {
	e.ipBlock.block(ip, time.Now().Add(dur))
	if e.l4BlockHook != nil {
		e.l4BlockHook(ip, dur)
	}
}

// BlockIPUntil 用于跨节点同步：只在 until 晚于现有封禁时写入（不缩短、不自行延长），
// 写入后同样下沉到 L4。返回是否写入。
func (e *Engine) BlockIPUntil(ip string, until time.Time) bool {
	if !e.ipBlock.blockUntil(ip, until) {
		return false
	}
	if e.l4BlockHook != nil {
		e.l4BlockHook(ip, time.Until(until))
	}
	return true
}

// SetL4ExpireHook 注册封禁「自然到期」回调，与 SetL4BlockHook 配对。
//
// 少了它，WAF/CC 下沉到 XDP 的封禁在 L7 到期后仍留在 blocklist 里（XDP 不知道过期
// 时刻），效果等于永久封禁 —— 被误封的 NAT 出口永远进不来，且 L7 面板显示已无封禁。
func (e *Engine) SetL4ExpireHook(hook func(ip string)) {
	if hook == nil {
		e.ipBlock.onExpire.Store(nil)
		return
	}
	e.ipBlock.onExpire.Store(&hook)
}

// UnblockIP 立即从封禁表中删除 IP，并同步从 L4（XDP blocklist）摘除。
func (e *Engine) UnblockIP(ip string) {
	e.ipBlock.remove(ip)
	if e.l4UnblockHook != nil {
		e.l4UnblockHook(ip)
	}
}

// GetBannedIPs 返回当前所有有效封禁 IP 的列表
func (e *Engine) GetBannedIPs() []string {
	return e.ipBlock.GetBannedIPs()
}

// IsBanned 返回指定 IP 当前是否处于有效封禁状态。
func (e *Engine) IsBanned(ip string) bool {
	return e.ipBlock.isBlocked(ip)
}

// BanCapacity 返回封禁表的占用与退化情况。表打满时走的是"回收/腾位"而不是"停收"，
// 但退化必须可观测：early_unbanned 与 dropped 不为 0 就说明封禁额度已经被攻击用尽。
func (e *Engine) BanCapacity() CapacityPressure {
	return e.ipBlock.capacity()
}

// CapacityPressure 是一张有界表在某一时刻的占用与退化读数。封禁表和 CC 的三张追踪表
// 共用同一个形状：它们打满之后走的都是"先回收闲置、再提前解除、最后才放弃"，
// 运维要能看见走到了哪一步——降级运行和防线失效在面板上必须长得不一样。
type CapacityPressure struct {
	Size  int `json:"size"`  // 当前条目数
	Limit int `json:"limit"` // 硬上限；达到后不是拒收，而是先回收再腾位

	// Reclaimed 是为腾位提前回收的已过期/闲置条目数。它们本来也会被周期性清理掉，
	// 这个计数只说明"清理来不及，额度被僵尸条目占过"。
	Reclaimed uint64 `json:"reclaimed"`
	// EarlyUnbanned 是提前解除的仍生效条目数：封禁表里是未到期的封禁，CC 追踪表里是
	// 仍在冷却/拦截态的域名或指纹。不为 0 就说明额度真的被攻击用尽了。
	EarlyUnbanned uint64 `json:"early_unbanned"`
	// Dropped 是一个空位都腾不出来、被迫放弃的次数（新封禁被丢弃 / 新 IP 不做跨请求统计）。
	Dropped uint64 `json:"dropped"`
}

// Add 把另一个节点的读数并进来。额度是每台节点各自持有的，所以容量和占用都按求和汇总；
// 三档退化计数是累计事件，同样求和。
func (p *CapacityPressure) Add(other CapacityPressure) {
	p.Size += other.Size
	p.Limit += other.Limit
	p.Reclaimed += other.Reclaimed
	p.EarlyUnbanned += other.EarlyUnbanned
	p.Dropped += other.Dropped
}

// Degraded 表示这张表是否发生过"牺牲防护换来的腾位"：提前解除仍生效的条目，
// 或者干脆放弃一次追踪/封禁。面板用它把"降级运行"这件事顶到眼前。
func (p CapacityPressure) Degraded() bool {
	return p.EarlyUnbanned > 0 || p.Dropped > 0
}

// pressureCounters 汇总一张表的三档退化计数。各档语义见 CapacityPressure。
// 只有打满时才会写，因此原子计数足够，不必给热路径再加锁。
type pressureCounters struct {
	reclaims  atomic.Uint64
	evictions atomic.Uint64
	drops     atomic.Uint64
	limit     int
}

// snapshot 汇成对外读数；size 由持有该计数器的表在自己锁内读好后传进来。
func (p *pressureCounters) snapshot(size int) CapacityPressure {
	return CapacityPressure{
		Size: size, Limit: p.limit,
		Reclaimed: p.reclaims.Load(), EarlyUnbanned: p.evictions.Load(), Dropped: p.drops.Load(),
	}
}

// SnapshotBans 导出当前所有未过期封禁的「IP → 过期时间」，供调用方落盘。
// GetBannedIPs 只给 IP 列表，丢掉过期时间，重启后无法还原剩余时长。
func (e *Engine) SnapshotBans() map[string]time.Time {
	return e.ipBlock.snapshot()
}

// RestoreBans 按快照恢复封禁，跳过已过期的条目。
// 不触发 l4BlockHook：恢复发生在进程启动阶段，此时 XDP 可能还没加载完；
// 且主控侧根本没有本地 XDP。真正的 L4 下发由封禁广播/同步轮询负责。
// 返回实际恢复的条数（已过期的不计）。
func (e *Engine) RestoreBans(snap map[string]time.Time) int {
	now := time.Now()
	n := 0
	for ip, exp := range snap {
		if exp.After(now) {
			e.ipBlock.block(ip, exp)
			n++
		}
	}
	return n
}

func (e *Engine) checkIPBlocklist(r *http.Request) *Result {
	ip := clientIP(r)
	if e.ipBlock.isBlocked(ip) {
		return &Result{Action: Block, Rule: "ip-blocklist", Message: "IP " + ip + " is blocked"}
	}
	return nil
}

// checkUserAgent 检测异常或恶意 User-Agent。
func (e *Engine) checkUserAgent(r *http.Request) *Result {
	if e.uaValidator == nil {
		return nil
	}

	// 白名单：已知合法爬虫不拦截
	ua := r.Header.Get("User-Agent")
	if e.uaValidator.IsWhitelistedBot(ua) {
		return nil
	}

	return e.uaValidator.ValidateUserAgent(r)
}

// checkACMELimit 检查 ACME 验证路径的速率限制。
func (e *Engine) checkACMELimit(r *http.Request) *Result {
	if e.acmeLimiter == nil {
		return nil
	}
	return e.acmeLimiter.CheckACMERequest(r)
}

// checkFileUpload 验证文件上传请求的魔术字节。
func (e *Engine) checkFileUpload(r *http.Request) *Result {
	if e.fileValidator == nil {
		return nil
	}

	// 只检查 POST/PUT/PATCH 请求
	if r.Method != http.MethodPost && r.Method != http.MethodPut && r.Method != http.MethodPatch {
		return nil
	}

	return e.fileValidator.ValidateUpload(r)
}

// ── 托管规则 ──────────────────────────────────────────────────────
//
// 签名规则不再在这里逐条写 Go 函数：规则本体（id/名称/描述/档位/作用域/正则）全部
// 声明在 internal/waf/rules.json，由 ruleset.go 编译，匹配逻辑集中在 InspectManaged。
// 这样"管理员改一条正则并立刻下发全网"才成立 —— 下发的是数据，不是需要重编的闭包。
//
// 规则文本以加密形式内置（internal/waf/rules.enc，由 rules.json 通过
// cmd/sealresource 加密生成），运行时解密后编译，避免明文规则出现在二进制中。
//
// 历史上按 URL 后缀拦截 .php/.jsp 的做法已被废弃：后端用什么语言是业务的自由，
// 正常访问 login.php 不该被 WAF 误杀。真正要防的"上传可执行脚本"由上传校验
// （CheckUpload → FileUploadValidator 按 filename 与魔术字节）负责。
// 已知 webshell 落地文件名（/shell.php、/c99.php 等）由 scanner 规则覆盖。

// ── IP 封禁列表 ────────────────────────────────────────────────────

// maxBlockedIPs 是 IP 封禁列表的数量上限。IP 可被伪造（XFF），
// 若不设上限会被用来放大内存占用。
//
// 打满后的策略不是"停收新封禁"而是"先回收、再腾位"：表被打满本身就是攻击进行中的
// 标志，此时停收等于对后续所有攻击 IP 免检——最不能失效的时刻失效了。详见 makeRoomLocked。
const maxBlockedIPs = 100000

// ipBlockGCInterval 是过期封禁的回收周期，同时决定「到期 → 从 XDP 摘除」的最大延迟。
// 以前是 5 分钟且到期时不通知任何人：WAF/CC 下沉到 XDP 的封禁在 L7 到期后仍留在
// blocklist 里，而 XDP 那边不知道过期时刻 —— 下沉的封禁实际上变成了永久封禁。
const ipBlockGCInterval = 30 * time.Second

type ipBlockList struct {
	mu      sync.RWMutex
	blocked map[string]time.Time // ip → 过期时间
	// onExpire 在封禁到期被回收时调用（锁外），用于把到期同步到 L4。
	onExpire atomic.Pointer[func(ip string)]

	// 容量压力计数：打满后走的是退化而不是停摆，但退化成什么样必须让运维看得见。
	// 三档语义见 CapacityPressure。
	pressure pressureCounters
}

func newIPBlockList() *ipBlockList {
	bl := &ipBlockList{blocked: make(map[string]time.Time)}
	bl.pressure.limit = maxBlockedIPs
	go bl.gc()
	return bl
}

// capacity 返回封禁表的占用与压力计数，供状态接口与面板展示"是否正在退化运行"。
func (bl *ipBlockList) capacity() CapacityPressure {
	bl.mu.RLock()
	size := len(bl.blocked)
	bl.mu.RUnlock()
	return bl.pressure.snapshot(size)
}

// makeRoomLocked 在表已满时尽力腾出空位，返回需要从 L4 同步摘除的 IP（调用方须锁外回调）。
//
// 回收顺序按"代价从小到大"：
//  1. 先删已过期的条目。它们本来就会被 sweep 删掉，只是 sweep 最快 30 秒才跑一次；
//     表满时这些僵尸条目正在白占额度，而且它们还挂在 XDP blocklist 上没人摘。
//  2. 全是未到期条目且 evictLive=true 时，提前解除"最快到期"的那一条。它离自然解封
//     最近，代价最小；换来的是一个正在攻击的 IP 被封住。反过来（拒收新封禁）会让
//     后续攻击者全部免检——而表满恰恰只在攻击进行中才会发生。
//
// evictLive=false 用于跨节点同步路径：本节点检测出来的封禁不能被远端消息挤掉，
// 那种场景宁可放弃这条同步记录。
//
// 两条路径都必须把 IP 交回 onExpire 回调：L7 删了而 L4 没删，等于把到期封禁变成永久封禁。
func (bl *ipBlockList) makeRoomLocked(now time.Time, evictLive bool) []string {
	var removed []string
	for victim, exp := range bl.blocked {
		if now.After(exp) {
			delete(bl.blocked, victim)
			removed = append(removed, victim)
		}
	}
	if n := len(removed); n > 0 {
		bl.pressure.reclaims.Add(uint64(n))
	}
	if len(bl.blocked) < maxBlockedIPs || !evictLive {
		return removed
	}

	soonest, best := "", time.Time{}
	for candidate, exp := range bl.blocked {
		if best.IsZero() || exp.Before(best) {
			soonest, best = candidate, exp
		}
	}
	if soonest != "" {
		delete(bl.blocked, soonest)
		bl.pressure.evictions.Add(1)
		removed = append(removed, soonest)
	}
	return removed
}

func (bl *ipBlockList) block(ip string, until time.Time) {
	bl.mu.Lock()
	var released []string
	if _, exists := bl.blocked[ip]; !exists && len(bl.blocked) >= maxBlockedIPs {
		released = bl.makeRoomLocked(time.Now(), true)
	}
	bl.blocked[ip] = until
	bl.mu.Unlock()

	// 与 sweep 同构：回调必须在锁外，里面是 XDP syscall。
	bl.notifyUnblock(released)
}

// notifyUnblock 把被回收/腾位的封禁同步到 L4（与 sweep 一致：回调里是 XDP syscall，
// 必须在锁外调用）。逐个再确认仍未处于封禁期，避免与并发 block 竞争把刚续上的封禁摘掉。
func (bl *ipBlockList) notifyUnblock(ips []string) {
	fn := bl.onExpire.Load()
	if fn == nil {
		return
	}
	for _, ip := range ips {
		if !bl.isBlocked(ip) {
			(*fn)(ip)
		}
	}
}

// blockUntil 只在新的过期时刻晚于现有封禁时写入，返回是否写入。
// 用于跨节点同步：同步只能「补齐」，绝不能把别处更长的封禁缩短，也不能自己延长。
// 表满时只回收已到期条目、不提前解除任何未到期封禁——本节点的封禁不能被远端消息挤掉。
func (bl *ipBlockList) blockUntil(ip string, until time.Time) bool {
	if !until.After(time.Now()) {
		return false
	}
	bl.mu.Lock()
	cur, exists := bl.blocked[ip]
	if exists && !until.After(cur) {
		bl.mu.Unlock()
		return false
	}
	var released []string
	if !exists && len(bl.blocked) >= maxBlockedIPs {
		released = bl.makeRoomLocked(time.Now(), false)
		if len(bl.blocked) >= maxBlockedIPs {
			bl.pressure.drops.Add(1)
			bl.mu.Unlock()
			bl.notifyUnblock(released)
			return false
		}
	}
	bl.blocked[ip] = until
	bl.mu.Unlock()
	bl.notifyUnblock(released)
	return true
}

func (bl *ipBlockList) remove(ip string) {
	bl.mu.Lock()
	delete(bl.blocked, ip)
	bl.mu.Unlock()
}

func (bl *ipBlockList) isBlocked(ip string) bool {
	bl.mu.RLock()
	exp, ok := bl.blocked[ip]
	bl.mu.RUnlock()
	return ok && time.Now().Before(exp)
}

func (bl *ipBlockList) gc() {
	ticker := time.NewTicker(ipBlockGCInterval)
	defer ticker.Stop()
	for range ticker.C {
		bl.sweep(time.Now())
	}
}

// sweep 删除 now 时已过期的封禁并逐个回调 onExpire（锁外调用：回调里是 XDP syscall）。
// 回调前再确认一次仍未被重新封禁，避免与并发的 block 竞争把刚续上的封禁从 L4 摘掉。
func (bl *ipBlockList) sweep(now time.Time) []string {
	bl.mu.Lock()
	var expired []string
	for ip, exp := range bl.blocked {
		if now.After(exp) {
			delete(bl.blocked, ip)
			expired = append(expired, ip)
		}
	}
	bl.mu.Unlock()
	if fn := bl.onExpire.Load(); fn != nil {
		for _, ip := range expired {
			if !bl.isBlocked(ip) {
				(*fn)(ip)
			}
		}
	}
	return expired
}

// snapshot 返回未过期封禁的副本（ip → 过期时间）。
func (bl *ipBlockList) snapshot() map[string]time.Time {
	now := time.Now()
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	out := make(map[string]time.Time, len(bl.blocked))
	for ip, exp := range bl.blocked {
		if now.Before(exp) {
			out[ip] = exp
		}
	}
	return out
}

// GetBannedIPs 返回当前所有有效封禁 IP 的列表
func (bl *ipBlockList) GetBannedIPs() []string {
	bl.mu.RLock()
	defer bl.mu.RUnlock()
	var ips []string
	for ip, exp := range bl.blocked {
		if time.Now().Before(exp) {
			ips = append(ips, ip)
		}
	}
	return ips
}

// BlockIPDirect 直接封禁 IP（无需 Engine）
func (bl *ipBlockList) BlockIPDirect(ip string, dur time.Duration) {
	bl.mu.Lock()
	bl.blocked[ip] = time.Now().Add(dur)
	bl.mu.Unlock()
}

// UnblockIPDirect 直接解除封禁 IP（无需 Engine）
func (bl *ipBlockList) UnblockIPDirect(ip string) {
	bl.mu.Lock()
	delete(bl.blocked, ip)
	bl.mu.Unlock()
}

// ── 辅助函数 ──────────────────────────────────────────────────────

func clientIP(r *http.Request) string {
	// 取 X-Forwarded-For 最右边的值（Tengine 追加的真实 IP，不可被客户端伪造）
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return normalizeIP(strings.TrimSpace(parts[len(parts)-1]))
	}
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return normalizeIP(strings.TrimSpace(xri))
	}
	return normalizeIP(stripPort(r.RemoteAddr))
}

// NormalizeClientIP 把外部传入的客户端地址（可能带端口、带方括号、或是 IPv6 的等价写法）
// 归一成与 clientIP 完全一致的键。
//
// 挑战 Cookie / 票据绑定的 IP 必须与 CC 限速使用的键来自同一套归一化：签发端（wafChallenge、
// wafVerify）直接读 X-Waf-Client-IP，校验端（CCDefense.Check → clientIP）走归一化，两边
// 只要对同一个 IPv6 地址得出不同字符串，VerifyChallengeCookie 就恒失败 —— 表现为真人反复
// 收到验证页却永远进不去（无限挑战循环）。
func NormalizeClientIP(addr string) string {
	return normalizeIP(stripPort(addr))
}

// stripPort 去掉 "host:port" 里的端口，兼容 IPv6。
//
// 不能用 strings.LastIndex(s, ":") 切：裸 IPv6 地址（"2001:db8::1"）本身就含冒号，
// 按最后一个冒号切会得到 "2001:db8:" 这种畸形串。后果不只是日志难看——限速统计、
// 封禁表、挑战 Cookie 绑定全都以这个字符串为键，畸形键会让同一个 IPv6 客户端的
// 计数挂在错误的键上，且 BlockIP 写进去的键永远无法被 net.ParseIP 还原成地址，
// L4 hook 那边也就下沉不到 XDP blocklist。
func stripPort(addr string) string {
	if addr == "" {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr); err == nil {
		return host
	}
	// 没有端口（或格式不合法）时原样返回：可能是裸 IP，交给 normalizeIP 收尾。
	return addr
}

// normalizeIP 把地址串归一成 net.IP 的标准写法，取不出地址时原样返回。
//
// 归一化的意义是让同一个客户端在各处只有一个键。同一个 IPv6 地址有多种等价写法
// （"2001:DB8::0:1" / "2001:db8::1"），Tengine 与 Go 侧、不同请求之间未必一致；
// 若不归一，限速计数会被拆散到多个键上，等于按写法给攻击者放大配额。
// IPv4-mapped（"::ffff:192.0.2.5"）一并折叠成点分十进制，与 XDP 侧的 IPv4 键一致。
func normalizeIP(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	// Tengine 在某些配置下会把 IPv6 的 $remote_addr 带上方括号转发。
	if len(s) > 1 && s[0] == '[' && s[len(s)-1] == ']' {
		s = s[1 : len(s)-1]
	}
	ip := net.ParseIP(s)
	if ip == nil {
		// 不是合法 IP（可能是 unix socket 路径或被污染的头），原样返回由调用方按不透明键处理。
		return s
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	return ip.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
