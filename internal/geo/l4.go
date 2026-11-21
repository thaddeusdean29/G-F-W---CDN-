package geo

// 这一份是"七层那张表"到"网卡上那两棵树"之间的唯一翻译处。
//
// 放在 geo 而不是放在 xdp 里：该不该进四层是**策略语义**（观察模式不能丢包、allow 四层
// 做不到、只有整节点规则进四层），不是 eBPF 细节。xdp 只负责把交给它的前缀写进 trie，
// 并且如实报告写了多少条、有没有写满。
//
// 也放在这里而不是边缘各写一遍：判定顺序一旦分叉，面板上"封了这个国家"和网卡上实际丢的
// 包就是两件事，而这正是本项目最忌讳的那类失效。

// L4Install 是交给四层装进网卡的那一份区域规则。
//
// 只包含**整节点策略**里 mode=block + action=deny 的那些国家的前缀：四层看不到 HTTP host，
// 域名级规则进了四层就会把"这个域名封 US"变成"整台节点封 US"——那比不拦更糟。
type L4Install struct {
	Block4 []Entry4
	Block6 []Entry6
	Exc4   []Entry4
	Exc6   []Entry6
	// Fingerprint 是这些前缀来自哪张表。四层装完要把它报回主控，
	// 否则"面板那张表"和"网卡那张表"只能靠"我下发成功过"来推断。
	Fingerprint string
	// Skip 非空表示"这一轮一棵树都不装，全清掉"，内容就是要显示给面板看的原因。
	// 装了东西时为空；空安装但没原因是说不通的状态，BuildL4Install 不会产出它。
	Skip string
}

// Empty 报告这份下发是不是"什么都不装"。
func (in L4Install) Empty() bool {
	return in.Skip != "" || (len(in.Block4) == 0 && len(in.Block6) == 0)
}

// BuildL4Install 按当前配置与当前表算出四层该装什么。
//
// 判定顺序与 Decide 一致：先看总闸，再看这条规则本身该不该执行，最后才去动那张表。
// 任何一条不满足都返回 Skip，让 xdp 把 trie 清空——留着上一次的树等于用一份已经不成立的
// 策略继续丢包，而且从读数上看和"在生效"一模一样。
//
// 主控那个 L4Enabled 意愿位放在最后判，而不是最前：它是 allow / 观察 / 表没编出来等好几件事
// 合起来的结论，一进门就撞上它的话，报出来的原因永远是那句笼统的"主控没让装"，
// 运维还得自己回到面板去猜究竟是哪一件。具体条件先判完，剩下的那一条才真的是"表没编出来"。
func (g *Guard) BuildL4Install() L4Install {
	cfg := g.Config()
	tbl := g.table.Load()
	ex := g.ex.Load()

	switch {
	case !cfg.ScopeEnabled:
		return L4Install{Skip: "平台总闸没开：四层不装区域表"}
	case !cfg.Node.Enabled:
		return L4Install{Skip: "整节点区域规则没启用：四层不装区域表"}
	case cfg.Node.Mode != ModeBlock:
		return L4Install{Skip: "整节点规则是观察模式：四层只有丢包这一种动作，一条都不装"}
	case cfg.Node.Action != ActionDeny:
		return L4Install{Skip: "四层分不清表里没有这个地址究竟是未知还是该拒：只放行某些国家只能由七层做"}
	case tbl == nil:
		return L4Install{Skip: "本节点还没装载前缀表：四层无表可装"}
	case len(cfg.Node.Countries) == 0:
		return L4Install{Skip: "整节点规则的国家清单是空的：四层不装区域表"}
	case !cfg.L4Enabled:
		// 前面几条都过了而主控却不肯让四层装：那是主控这一侧编不出表（国家级地理库没就位，
		// 或选中的国家一个都解析不出前缀）。这里必须拦住，否则节点会拿一份过期表往网卡上装，
		// 面板显示"四层已生效"而主控认为四层根本不该动。
		return L4Install{Skip: "主控没让四层装载区域表（多半是这张表在主控侧没编出来，比如国家级地理库没就位）：本地这份表不作为四层依据"}
	}

	want := make(map[string]bool, len(cfg.Node.Countries))
	for _, c := range upperCodes(cfg.Node.Countries) {
		want[c] = true
	}
	in := L4Install{Fingerprint: tbl.Fingerprint}
	for _, e := range tbl.List4() {
		if want[e.Country] {
			in.Block4 = append(in.Block4, e)
		}
	}
	for _, e := range tbl.List6() {
		if want[e.Country] {
			in.Block6 = append(in.Block6, e)
		}
	}
	if len(in.Block4) == 0 && len(in.Block6) == 0 {
		// 表里一条都没有而策略却是开着的：这张表不是按这些国家编的（主控编译用的国家清单
		// 与节点策略对不上），装下去只会得到一个"看起来开了、其实一条都不丢"的节点。
		return L4Install{Skip: "这张前缀表里没有整节点策略选的任何国家：表与策略对不上，四层不装"}
	}
	// 例外与七层用同一份编译结果，且只在真的要拦时才进 trie：装了例外而不装封禁，
	// 读数里会出现"例外若干条、封禁零条"这种没人能解释的形状。
	in.Exc4 = ex.List4()
	in.Exc6 = ex.List6()
	return in
}
