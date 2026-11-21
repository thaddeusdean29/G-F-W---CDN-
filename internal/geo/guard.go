package geo

// Guard 是边缘节点上的区域规则运行时：当前装的是哪张表、平台总闸与整节点策略是什么、
// 以及每种判决来由各发生了多少次。
//
// 判定本体仍是 Decide（无状态，主控装表前的自检也用它），这里只加运行时状态。
// 表与策略都靠原子指针整体替换：区域判定发生在每个请求上，请求路径上一把锁都不加，
// 否则"封某个国家"会变成全站请求排队过一把全局锁。

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type Guard struct {
	cfg   atomic.Pointer[ConfigPayload]
	table atomic.Pointer[Table]
	ex    atomic.Pointer[ExceptionSet]
	meta  atomic.Pointer[tableMeta]

	// 七类来由各自一个计数器。分开放是因为它们各自对应一个不同的处置结论：
	// 并进"放行"就再也看不出"库没覆盖到的流量"和"名单里该放行的流量"差在哪。
	off       atomic.Uint64
	exception atomic.Uint64
	unknown   atomic.Uint64
	noTable   atomic.Uint64
	pass      atomic.Uint64
	observe   atomic.Uint64
	blocked   atomic.Uint64

	rows sync.Map // 国家码 -> *countRow；国家数被表本身限制在 255 以内，不需要淘汰
	// logged sync.Map 只用于观察日志的按国家限速：观察模式开着时命中量可以是每秒几千条，
	// 逐条打会把节点日志刷没，而"这个国家有流量经过"这件事一行就够说清。
	logged sync.Map // 国家码 -> int64（unix 秒）

	// l4Reader 由边缘在启动时注入，把"这张网卡上的 trie 到底装没装"读进上报。
	// 为 nil 时上报按"未装载"写——宁可显示没装，也不要面板以为四层在丢包。
	l4Reader func() L4State
}

type tableMeta struct {
	Fingerprint string
	Countries   []string
	Total       int
	Built       string
	Applied     string
}

type countRow struct {
	observe atomic.Uint64
	blocked atomic.Uint64
	pass    atomic.Uint64
}

func NewGuard() *Guard { return &Guard{} }

// SetL4Reader 注入四层读数来源。必须在对外服务之前调用。
func (g *Guard) SetL4Reader(f func() L4State) { g.l4Reader = f }

// ── 配置 ──────────────────────────────────────────────────────────────────

// SetConfig 换上平台总闸 + 整节点策略，并把例外清单编译好。
//
// 例外编译失败时整份拒绝、保持原配置继续跑：例外少认一条，等于把一个本该放行的地址
// 放到被封的位置上——主控 IP 一旦落进那个位置，这台节点就从集群里消失且不报错。
func (g *Guard) SetConfig(in ConfigPayload) error {
	in.Node = in.Node.WithDefaults()
	in.Node.Normalize()
	ex, err := CompileExceptions(in.Node.Exceptions)
	if err != nil {
		return err
	}
	cp := in
	g.cfg.Store(&cp)
	g.ex.Store(ex)
	return nil
}

// Config 返回当前生效的配置。没收到过推送时返回默认值：总闸关着、策略不启用，
// 与升级前"没有区域规则"的行为一致。
func (g *Guard) Config() ConfigPayload {
	if cp := g.cfg.Load(); cp != nil {
		return *cp
	}
	return ConfigPayload{Node: DefaultPolicy()}
}

// Configured 报告主控有没有下发过配置。判定路径用它决定是否进来看一眼：
// 一个从没配过区域规则的节点，不该在每个请求上多读一遍原子指针再得出"关着"。
func (g *Guard) Configured() bool { return g.cfg.Load() != nil }

func (g *Guard) ScopeEnabled() bool {
	cp := g.cfg.Load()
	return cp != nil && cp.ScopeEnabled
}

// Active 是"这个节点现在真的会判区域规则吗"。总闸关着、或两条策略都没启用时返回 false。
func (g *Guard) Active() bool {
	cp := g.cfg.Load()
	if cp == nil || !cp.ScopeEnabled {
		return false
	}
	return cp.Node.Enabled
}

// ── 表 ────────────────────────────────────────────────────────────────────

// SetTablePayload 装载主控下发的表：解 base64、gunzip、Decode、核对指纹。
//
// 指纹必须和下发体一致，不一致就直接报错：Decode 自己算的是"我解出来的这份"的指纹，
// 两边不同意味着传输或编译环节对不上，而这张表马上就要用来决定谁能访问。
func (g *Guard) SetTablePayload(p TablePayload) (*Table, error) {
	if p.GzipB64 == "" {
		return nil, fmt.Errorf("表内容为空")
	}
	raw, err := base64.StdEncoding.DecodeString(p.GzipB64)
	if err != nil {
		return nil, fmt.Errorf("表 base64: %w", err)
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("表 gzip: %w", err)
	}
	defer zr.Close()
	buf, err := io.ReadAll(zr)
	if err != nil {
		return nil, fmt.Errorf("表解压失败: %w", err)
	}
	tbl, err := Decode(buf)
	if err != nil {
		return nil, err
	}
	if p.Fingerprint != "" && p.Fingerprint != tbl.Fingerprint {
		return nil, fmt.Errorf("指纹不符：下发 %s，节点解出 %s", p.Fingerprint, tbl.Fingerprint)
	}
	g.StoreTable(tbl, p.Built)
	return tbl, nil
}

// StoreTable 原子换表并记下这张表的身份。built 是主控算表的时刻，applied 是本地换上的时刻：
// 面板要能分别回答"这张表几点编的"和"这台节点几点吃到的"。
func (g *Guard) StoreTable(tbl *Table, built string) {
	g.table.Store(tbl)
	m := &tableMeta{
		Fingerprint: tbl.Fingerprint,
		Countries:   append([]string{}, tbl.Countries...),
		Total:       tbl.Total(),
		Built:       built,
		Applied:     time.Now().UTC().Format(time.RFC3339),
	}
	g.meta.Store(m)
}

// ClearTable 撤下当前这张表。
//
// 关规则不撤表的话，节点会一直带着几十万条前缀跑，而它一条也不会执行——
// 内存回不来，读数里那张"已装载"的表还会让面板显示成规则在跑。
func (g *Guard) ClearTable() {
	g.table.Store(nil)
	g.meta.Store(nil)
}

func (g *Guard) Table() *Table { return g.table.Load() }

// Exceptions 给装表前的自检用：四层要按同一份例外清单核对一遍结论。
func (g *Guard) Exceptions() *ExceptionSet { return g.ex.Load() }

// ── 判定 ──────────────────────────────────────────────────────────────────

// Check 判一次请求：域名规则与整节点规则都算，取更严的结论，只记一笔。
//
// 为什么两条都要判：管理员那条是"这个节点不欢迎哪些国家"，不因为某个域名配了自己的
// 规则就消失；域名那条是"这个站点只放行/拒绝哪些国家"。两条规则同时成立时，能拦住的那条
// 才算数——只判域名那条会让管理员的策略被一个代理改动就绕过。
// 为什么只记一笔：两个国家清单重叠的部分如果各记一次，读数里的总量就大于真实请求数，
// "拦了多少次"回答不了了。要按规则分别看，得每条规则各自一份表，那是另一件事。
func (g *Guard) Check(dom Policy, ip net.IP) Result {
	cp := g.cfg.Load()
	if cp == nil {
		// 主控从没下发过配置：这里不记账。节点没被配置过和"被配置成不拦"是两件事，
		// 前者由读数里那句"还没收到过配置"说明，不该在 Off 里冒出天文数字。
		return Result{Why: WhyOff}
	}
	if !cp.ScopeEnabled || (!dom.Enabled && !cp.Node.Enabled) {
		g.off.Add(1)
		return Result{Why: WhyOff}
	}
	tbl := g.table.Load()
	ex := g.ex.Load()
	best := Result{Why: WhyOff}
	if dom.Enabled {
		if r := Decide(dom.WithDefaults(), true, tbl, ex, ip); severity(r) > severity(best) {
			best = r
		}
	}
	if cp.Node.Enabled {
		if r := Decide(cp.Node, true, tbl, ex, ip); severity(r) > severity(best) {
			best = r
		}
	}
	g.record(best, tbl)
	return best
}

func severity(r Result) int {
	switch r.Why {
	case WhyException:
		return 1
	case WhyUnknown:
		return 2
	case WhyPass:
		return 3
	case WhyHit:
		if r.Blocked {
			return 5
		}
		return 4
	default:
		return 0
	}
}

func (g *Guard) record(r Result, tbl *Table) {
	switch r.Why {
	case WhyOff:
		g.off.Add(1)
	case WhyException:
		g.exception.Add(1)
	case WhyUnknown:
		// 没表 && 有启用的规则：那是"规则在跑但一张表都没装上"，和"表里查不到这个地址"
		// 必须分开记。前者要去查下发，后者本来就是私网/保留段/库未覆盖。
		if tbl == nil {
			g.noTable.Add(1)
		} else {
			g.unknown.Add(1)
		}
	case WhyPass:
		g.pass.Add(1)
		if r.Country != "" {
			g.row(r.Country).pass.Add(1)
		}
	case WhyHit:
		row := g.row(r.Country)
		if r.Blocked {
			g.blocked.Add(1)
			row.blocked.Add(1)
			return
		}
		g.observe.Add(1)
		row.observe.Add(1)
	}
}

func (g *Guard) row(code string) *countRow {
	if v, ok := g.rows.Load(code); ok {
		return v.(*countRow)
	}
	r := &countRow{}
	actual, _ := g.rows.LoadOrStore(code, r)
	return actual.(*countRow)
}

// LogOnce 每个国家在 window 内只放行一条日志。
// 判定为"应当拦截但处于观察模式"是要留证据的，但不能按请求留。
func (g *Guard) LogOnce(code string, window time.Duration) bool {
	key := code
	if key == "" {
		key = "-"
	}
	now := time.Now().Unix()
	if v, ok := g.logged.Load(key); ok {
		if now-v.(int64) < int64(window.Seconds()) {
			return false
		}
	}
	g.logged.Store(key, now)
	return true
}

// ── 读数 ──────────────────────────────────────────────────────────────────

// Stats 是本节点的完整区域判定读数，同时用于 GET /edge/geo/stats 和周期上报。
//
// 上报必须把"没装载表""平台没开""观察模式命中但没拦"分别说清：主控不回连边缘取数，
// 这里少说一项，面板上就少一个能自证的地方。
func (g *Guard) Stats() Readings {
	cfg := g.Config()
	r := Readings{
		At:           time.Now().UTC().Format(time.RFC3339),
		ScopeEnabled: cfg.ScopeEnabled,
		Node:         cfg.Node,
		Table:        g.tableState(cfg),
		L4:           g.l4State(cfg),
		Counters: Counters{
			Observe:   g.observe.Load(),
			Blocked:   g.blocked.Load(),
			Pass:      g.pass.Load(),
			Unknown:   g.unknown.Load(),
			Exception: g.exception.Load(),
			Off:       g.off.Load(),
			NoTable:   g.noTable.Load(),
		},
	}
	var countries []CountryCount
	g.rows.Range(func(k, v any) bool {
		row := v.(*countRow)
		countries = append(countries, CountryCount{
			Country: k.(string),
			Observe: row.observe.Load(),
			Blocked: row.blocked.Load(),
			Pass:    row.pass.Load(),
		})
		return true
	})
	sort.Slice(countries, func(i, j int) bool { return countries[i].Country < countries[j].Country })
	if countries == nil {
		countries = []CountryCount{}
	}
	r.Countries = countries
	return r
}

func (g *Guard) tableState(cfg ConfigPayload) TableState {
	if m := g.meta.Load(); m != nil {
		return TableState{
			Loaded:      true,
			Fingerprint: m.Fingerprint,
			Countries:   m.Countries,
			Total:       m.Total,
		}
	}
	st := TableState{}
	switch {
	case g.cfg.Load() == nil:
		// "没被配置过"和"配置成不拦"是两件事：前者要去看主控有没有下发过，
		// 后者是正常状态。把它写成 Off 计数会让人以为规则在跑，所以单独给一句原因。
		st.Error = "主控还没向本节点下发过区域规则配置（新节点接入或管理员保存后会自动补发）"
	case g.Active():
		// 规则要跑但没有表：这是会被记进 NoTable 的那种状态，读数必须把它写成原因，
		// 而不是只显示"未装载"让人去猜是不是本来就不需要表。
		st.Error = "有启用中的区域规则，但本节点还没装载前缀表：现在所有来源都按未知放行"
	}
	return st
}

func (g *Guard) l4State(cfg ConfigPayload) L4State {
	if g.l4Reader != nil {
		s := g.l4Reader()
		s.Want = cfg.L4Enabled
		return s
	}
	// 没注入读数来源（XDP 管理器未创建的老部署）：如实报未装载。
	// 想要四层丢包必须看得见"没挂上"这件事，不能让 ConfigPayload.L4Enabled 单独撑场。
	return L4State{
		Armed: false,
		Want:  cfg.L4Enabled,
		Error: "本节点未接入四层丢包读数（XDP 未加载或未提供）",
	}
}
