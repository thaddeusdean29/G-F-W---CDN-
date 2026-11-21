//go:build linux

package xdp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/cilium/ebpf"

	"cdn/internal/geo"
)

// 这一份是区域封禁在四层（XDP）的落地：把"整节点 deny 哪些国家"翻译成网卡上的
// 四棵 LPM trie，让被封国家的包在驱动层就被丢掉，而不是走到 Tengine 才被 403。
//
// 为什么值得单独做一层：七层判定要先把包变成 skb、走完协议栈、解析 HTTP header 才知道
// 来源国家。一场按国家打的洪水足以把 CPU 打满，而"这个国家一概不进内核"在 XDP 里
// 只是一次 trie 查找。所以七层负责精确（能分域名、能分 host、能只记账），四层负责挡量。
//
// 四棵树都是**整表替换**：每次换表重算一遍该装什么。装不进去（超过 map 容量、内核内存
// 不够）时一律清空并把原因写进 GeoState().Error，绝不留半棵树——半棵树在面板上就是
// "这个国家封了一半"，而且没有任何读数能看出差别。
//
// 清空带来的短暂"只有七层在拦"不是漏洞：Guard.Check 在七层同样按整节点策略判，表和策略
// 都在，请求照样 403。四层挡的是量，不是唯一的执行点。

// geoMissingObj 是旧 .o 的读数文案。三条编译路径（install.sh、面板按钮、远程部署）编的
// 都是同一份内嵌源码，所以出现这句话基本等于"这台节点升级了二进制，XDP 还是上一次编译
// 留下的那份"。
const geoMissingObj = "cdn_xdp.o 里没有 geo_block4/geo_block6/geo_exc4/geo_exc6 这四张表：" +
	"这份 .o 早于区域封禁功能，重新编译并重装 XDP（面板 XDP 页有重装入口）后四层才会按国家丢包"

// geoTrieNames / geoKeySizes 按下标一一对应，四棵树的遍历顺序在整份文件里只有这一处定义。
// 顺序必须与 C 侧语义、与 installedGeo.keys 同时一致，所以不做成 map（遍历顺序不定）。
const geoTrieCount = 4

var geoTrieNames = [geoTrieCount]string{"geo_block4", "geo_block6", "geo_exc4", "geo_exc6"}

var geoKeySizes = [geoTrieCount]int{geoKeySize4, geoKeySize6, geoKeySize4, geoKeySize6}

// hasGeoMaps 判断这份 spec 新到带不带区域表。按 spec 实况决定装哪个结构体，而不是
// 先按全量装、失败之后再靠错误文本猜缺的是哪张表。
func hasGeoMaps(spec *ebpf.CollectionSpec) bool {
	for _, n := range geoTrieNames {
		if spec.Maps[n] == nil {
			return false
		}
	}
	return true
}

// ── 键 ────────────────────────────────────────────────────────────────────

const (
	geoKeySize4 = 8  // __u32 prefixlen + 4 字节地址
	geoKeySize6 = 20 // __u32 prefixlen + 16 字节地址
)

// putGeoKey4 写一条 v4 键：前缀长度是内核按主机字节序 __u32 读的前 4 字节，地址是后 4
// 字节且**逐字节网络序**。Entry4.Addr 是 binary.BigEndian.Uint32 出来的数值，所以这里
// 必须用 BigEndian 写回；直接 binary.Write 一个 uint32 会按小端铺字节，键就成了反着的
// 地址——表照样装得进去，一条也匹配不上，而面板上一切正常。
func putGeoKey4(dst []byte, e geo.Entry4) {
	binary.LittleEndian.PutUint32(dst, uint32(e.Bits))
	binary.BigEndian.PutUint32(dst[4:], e.Addr)
}

func putGeoKey6(dst []byte, e geo.Entry6) {
	binary.LittleEndian.PutUint32(dst, uint32(e.Bits))
	copy(dst[4:], e.Addr[:])
}

// geoKeys 是一批 LPM 键连续存放的缓冲，按键的字节序排好且去掉重复。
//
// 排序有两个用处：换表时一次归并就能算出"上次装了、这次不该留"的那些键；删除时不必
// 再维护第二份集合。
//
// 记的是"我们写进去的那批键"，而不是"遍历 trie 边遍历边删"：cilium/ebpf 的文档明确写着
// 边迭代边删不安全、可能重复看到同一个键。把要删的东西写死在用户态，比赌内核遍历语义稳。
type geoKeys struct {
	size uint32
	buf  []byte
}

func (g geoKeys) count() int {
	if g.size == 0 {
		return 0
	}
	return len(g.buf) / int(g.size)
}

func (g geoKeys) at(i int) []byte {
	return g.buf[i*int(g.size) : (i+1)*int(g.size)]
}

// encodeGeoKeys 把长度固定为 size 的若干条键编码进一个缓冲（put 负责写第 i 条），
// 然后排序去重。整段只用两次分配：一次装输入，一次装输出。
func encodeGeoKeys(size int, n int, put func(dst []byte, i int)) geoKeys {
	if n == 0 {
		return geoKeys{size: uint32(size)}
	}
	raw := make([]byte, n*size)
	for i := 0; i < n; i++ {
		put(raw[i*size:], i)
	}
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	sort.Slice(order, func(a, b int) bool {
		return bytes.Compare(raw[order[a]*size:(order[a]+1)*size],
			raw[order[b]*size:(order[b]+1)*size]) < 0
	})
	out := make([]byte, 0, n*size)
	for _, i := range order {
		k := raw[i*size : (i+1)*size]
		// 排好序后重复键必然相邻，只跟上一个人比就够。
		if len(out) >= size && bytes.Equal(out[len(out)-size:], k) {
			continue
		}
		out = append(out, k...)
	}
	return geoKeys{size: uint32(size), buf: out}
}

func buildGeoKeys4(entries []geo.Entry4) geoKeys {
	return encodeGeoKeys(geoKeySize4, len(entries), func(dst []byte, i int) {
		putGeoKey4(dst, entries[i])
	})
}

func buildGeoKeys6(entries []geo.Entry6) geoKeys {
	return encodeGeoKeys(geoKeySize6, len(entries), func(dst []byte, i int) {
		putGeoKey6(dst, entries[i])
	})
}

// ── 单棵 trie 的一轮工作 ──────────────────────────────────────────────────

// geoTriePlan 是一棵树这一轮要做的事：prev 是上一轮真写进去的键，next 是这一轮要装的键。
// 两个都留着，才谈得上"删掉该删的"和"出问题全清掉"。
type geoTriePlan struct {
	name string
	m    *ebpf.Map
	prev geoKeys
	next geoKeys
}

// write 装入 next。value 只是占位：C 侧只看命中/没命中，国家标签留在用户态，
// 内核不该为了显示名字去猜下标。
func (p *geoTriePlan) write() error {
	if p.m == nil {
		return nil
	}
	val := []byte{1}
	for i := 0; i < p.next.count(); i++ {
		// UpdateAny：next 里相邻两轮都出现过的键这一轮是覆盖，用 UpdateNoExist 会当场报错。
		if err := p.m.Update(p.next.at(i), val, ebpf.UpdateAny); err != nil {
			return fmt.Errorf("%s 第 %d/%d 条: %w", p.name, i, p.next.count(), err)
		}
	}
	return nil
}

// dropStale 删掉 prev 里没出现在 next 里的键。next 已经先装进去了，所以换国家清单
// 的过程中不会出现"新旧两边都不拦"的窗口。
//
// prev/next 都按键字节序排好，归并一遍即可；键删不掉算成功——要的是"它不在树里了"。
func (p *geoTriePlan) dropStale() error {
	if p.m == nil {
		return nil
	}
	var firstErr error
	del := func(i int) {
		if err := p.m.Delete(p.prev.at(i)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) && firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", p.name, err)
		}
	}
	i, j := 0, 0
	for i < p.prev.count() && j < p.next.count() {
		switch bytes.Compare(p.prev.at(i), p.next.at(j)) {
		case 0:
			i++
			j++
		case -1:
			// prev 的这一项比 next 当前项小，而 next 往后只会更大：它不在 next 里。
			del(i)
			i++
		default:
			j++
		}
	}
	for ; i < p.prev.count(); i++ {
		del(i)
	}
	return firstErr
}

// wipe 倒空这棵树涉及的每一把键：上一轮装的、这一轮刚写进去的都要。
// 出问题回滚时只删 prev 是不够的——写失败的那棵树里，失败点之前已经进去的那批键没人认领。
func (p *geoTriePlan) wipe() error {
	if p.m == nil {
		return nil
	}
	var firstErr error
	for _, keys := range []geoKeys{p.prev, p.next} {
		for i := 0; i < keys.count(); i++ {
			if err := p.m.Delete(keys.at(i)); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) && firstErr == nil {
				firstErr = fmt.Errorf("%s: %w", p.name, err)
			}
		}
	}
	return firstErr
}

// ── 装表 ──────────────────────────────────────────────────────────────────

// installedGeo 是四棵树各自实际装进去的键，下标与 geoTrieNames 对齐。
type installedGeo struct {
	keys [geoTrieCount]geoKeys
}

// geoMaps 按 geoTrieNames 的顺序取出四棵树的句柄。旧 .o 时它们是 nil，
// 但那条路在 ApplyGeo 入口就被 available 挡掉了，这里只保证顺序对得上。
func (m *Manager) geoMaps() [geoTrieCount]*ebpf.Map {
	return [geoTrieCount]*ebpf.Map{m.objs.GeoBlock4, m.objs.GeoBlock6, m.objs.GeoExc4, m.objs.GeoExc6}
}

// geoPlans 按"这一轮要装的 next"拼出四棵树的工作计划，prev 从上一轮的记录里取。
// 记录为空（首轮、或上一轮刚整体清空过）时 prev 就是空键集，尺寸仍按树来，
// 免得到处判断 nil。
func (m *Manager) geoPlans(next [geoTrieCount]geoKeys) []*geoTriePlan {
	plans := make([]*geoTriePlan, geoTrieCount)
	for i := 0; i < geoTrieCount; i++ {
		p := &geoTriePlan{name: geoTrieNames[i], next: next[i]}
		p.m = m.geoMaps()[i]
		if m.geo.installed != nil {
			p.prev = m.geo.installed.keys[i]
		} else {
			p.prev = geoKeys{size: uint32(geoKeySizes[i])}
		}
		plans[i] = p
	}
	return plans
}

// clearAndFail 是唯一的失败出口：把这一轮涉及的键全删干净，再把"四层现在不可信"的原因
// 记下并返回错误。
//
// 顺序很要紧——先删键，再清记账。反过来写的话 installed 已经是 nil，删除时拿到的 prev
// 是空集，回滚就成了"报错说清了、树里还剩半张表"，那正是最难查的那种不一致。
func (m *Manager) clearAndFail(plans []*geoTriePlan, msg string) error {
	var delErr error
	for _, p := range plans {
		if err := p.wipe(); err != nil && delErr == nil {
			delErr = err
		}
	}
	m.geo.installed = nil
	m.geo.fingerprint = ""
	m.geo.reason = ""
	m.geo.applied = time.Now().UTC()
	if delErr != nil {
		m.geo.err = fmt.Sprintf("%s；而且清空 trie 也失败: %v（下面的读数不再可信，重装 XDP 或重启本节点才能对上）", msg, delErr)
	} else {
		m.geo.err = msg
	}
	return errors.New(m.geo.err)
}

// ApplyGeo 把一份区域规则装进网卡上的四棵 trie。
//
// in.Skip 非空表示"这轮什么都不该装"（观察模式、allow、总闸关着、表与策略对不上……）：
// 清空并把原因记下来，让 GeoState 说得出四层为什么没在丢包。
//
// 调用时机只有四个：换表、换节点策略、重启从存档恢复、XDP 热安装成功。它每次都是整表重装，
// 没有"增量补几条"那条路——增量会留下"上一次装了什么"这个第二真相。
func (m *Manager) ApplyGeo(in geo.L4Install) error {
	m.geoMu.Lock()
	defer m.geoMu.Unlock()

	if m.objs == nil {
		return errors.New("xdp not loaded")
	}
	if !m.geo.available {
		return errors.New(geoMissingObj)
	}

	if in.Empty() {
		plans := m.geoPlans([geoTrieCount]geoKeys{})
		var delErr error
		for _, p := range plans {
			if err := p.wipe(); err != nil && delErr == nil {
				delErr = err
			}
		}
		m.geo.installed = nil
		m.geo.fingerprint = ""
		m.geo.applied = time.Now().UTC()
		if delErr != nil {
			m.geo.err = fmt.Sprintf("清空区域 trie 失败: %v（下面的读数不再可信，重装 XDP 或重启本节点才能对上）", delErr)
			return delErr
		}
		// 清空是成功路径：err 必须一并抹掉，否则上一轮"装不进去"的报错会一直挂在这儿，
		// 面板上看着像这个问题还没修。
		m.geo.err = ""
		m.geo.reason = in.Skip
		if m.geo.reason == "" {
			m.geo.reason = "整节点策略选的国家在这张表里一条前缀都没有：四层没装任何区域前缀"
		}
		return nil
	}

	next := [geoTrieCount]geoKeys{
		buildGeoKeys4(in.Block4),
		buildGeoKeys6(in.Block6),
		buildGeoKeys4(in.Exc4),
		buildGeoKeys6(in.Exc6),
	}

	plans := m.geoPlans(next)

	// 容量先于写入：几十万次 Update 打到一半才发现装不下，中间那几十万个包是按半张表
	// 丢的。上限取 map 自己的 MaxEntries，不是用户态猜的常数——.o 一改常数就错了。
	for i, p := range plans {
		if p.m == nil {
			continue
		}
		if max := int(p.m.MaxEntries()); p.next.count() > max {
			return m.clearAndFail(plans, fmt.Sprintf(
				"%s 要装 %d 条前缀，超过这张 map 的上限 %d：四层已停用并清空，"+
					"七层照常按整节点策略拦。少选几个国家，或重新编译一份上限更大的 cdn_xdp.o",
				geoTrieNames[i], p.next.count(), max))
		}
	}

	// 先装新的、再删旧的：换清单期间最坏情况是多拦一会儿，不是漏拦。
	for _, p := range plans {
		if err := p.write(); err != nil {
			return m.clearAndFail(plans, fmt.Sprintf(
				"写区域 trie 失败: %v；四层已停用并清空，请重新下发区域规则", err))
		}
	}
	for _, p := range plans {
		if err := p.dropStale(); err != nil {
			// 新表已经在树里了，但上一轮的残留删不掉：残留的键可能正在丢一个
			// 已经不该封的国家的包，那比"暂时只由七层拦"更糟，所以整表清空重来。
			return m.clearAndFail(plans, fmt.Sprintf(
				"清理上一轮残留前缀失败: %v；四层已停用并清空，请重新下发区域规则", err))
		}
	}

	inst := &installedGeo{}
	for i, p := range plans {
		inst.keys[i] = p.next
	}
	m.geo.installed = inst
	m.geo.fingerprint = in.Fingerprint
	m.geo.reason = ""
	m.geo.err = ""
	m.geo.applied = time.Now().UTC()
	return nil
}

// GeoState 把四层区域丢包的现状写成上报的形状。
//
// 每个"没在生效"都配一句能照着修的话：只给 armed=false，面板上就是一个灰点，
// 运维看不出到底该重装 XDP、该改策略、还是表根本没下来。
func (m *Manager) GeoState() geo.L4State {
	st := geo.L4State{
		Mode:       m.Mode(),
		Program:    "cdn_xdp_filter",
		NotInstall: !m.Loaded(),
	}
	if !m.Loaded() {
		st.Error = "XDP 没加载：四层不会丢任何包"
		return st
	}
	m.geoMu.Lock()
	defer m.geoMu.Unlock()
	if !m.geo.available {
		st.Error = geoMissingObj
		return st
	}
	st.Fingerprint = m.geo.fingerprint
	if !m.geo.applied.IsZero() {
		st.Applied = m.geo.applied.Format(time.RFC3339)
	}
	if m.geo.err != "" {
		st.Error = m.geo.err
		return st
	}
	if m.geo.installed == nil {
		st.Error = m.geo.reason
		return st
	}
	st.EntriesV4 = m.geo.installed.keys[0].count()
	st.EntriesV6 = m.geo.installed.keys[1].count()
	if st.EntriesV4+st.EntriesV6 == 0 {
		// 只有例外、一条封禁都没有：trie 里不会有任何丢包，armed 必须是 false。
		st.Error = m.geo.reason
		if st.Error == "" {
			st.Error = "四棵区域 trie 是空的：四层没有要丢的地址"
		}
		return st
	}
	st.Armed = true
	// 例外树条数不进读数：它只解释"为什么这些地址没被丢"，面板按国家显示时会被
	// 当成封禁条数误读。它的大小在 clearAndFail 的报错里能看到，够用。
	if s, err := m.GetStats(); err != nil {
		// armed 留着：包照样在丢，只是读不到数。但必须把"这个 0 是没读到"写出来，
		// 否则面板显示"已生效、丢包 0"，看起来就像这个国家根本没人来过。
		st.Error = "dropped_geo 读数失败，丢包总数暂不可信: " + err.Error()
	} else {
		st.Dropped = s.DroppedGeo
	}
	return st
}
