package geo

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
)

// 前缀表是"面板算出来的那张表"的唯一形态：定长记录、按地址排序、前缀互不嵌套
// （mmdb 的叶子网络本身就是地址空间的不重叠划分，取子集后仍成立）。
// 互不嵌套让查找只需一次二分：找最后一条 addr ≤ ip 的记录，它要么包含 ip，要么没人包含。
type Table struct {
	Fingerprint string   // 编码内容的 sha256 前 16 位；节点装载核对就比这个串
	Countries   []string // 下标 +1 等于记录里的 cidx，0 表示"表里没有这条地址"
	V4          []pref4
	V6          []pref6

	enc []byte // 编码结果缓存：下发与落盘比的是字节，重算指纹会自证不一致
}

type pref4 struct {
	addr uint32
	bits uint8
	cidx uint16
}

type pref6 struct {
	addr [16]byte
	bits uint8
	cidx uint16
}

const (
	geoMagic    = "GEOT1"
	geoMaxCount = 4_000_000 // 全库实测 59.7 万条；上限给足，同时拒绝明显是坏数据的长度
)

func less4(a, b pref4) bool {
	if a.addr != b.addr {
		return a.addr < b.addr
	}
	return a.bits < b.bits
}

func less6(a, b pref6) bool {
	c := bytes.Compare(a.addr[:], b.addr[:])
	if c != 0 {
		return c < 0
	}
	return a.bits < b.bits
}

// align4/align6 把地址抹到前缀边界上。库里存在未对齐的条目（实测有 /24 记成 x.y.z.5），
// 而"末地址 = 首地址 + 2^(32-前缀) - 1"这套算法只有在对齐时成立：不对齐会把包含判定
// 放宽到前缀外面，面板上就表现为"封了这个国家，结果邻国的 IP 也被拦"。
func align4(addr uint32, bits int) uint32 {
	switch {
	case bits <= 0:
		return 0
	case bits >= 32:
		return addr
	}
	return addr &^ uint32(1<<(32-bits)-1)
}

func align6(a *[16]byte, bits int) {
	for i := bits; i < 128; i++ {
		a[i/8] &^= 1 << uint(7-i%8)
	}
}

func unaligned4(addr uint32, bits uint8) bool {
	return align4(addr, int(bits)) != addr
}

func unaligned6(a [16]byte, bits uint8) bool {
	var b [16]byte
	copy(b[:], a[:])
	align6(&b, int(bits))
	return b != a
}

// Encode 序列化成下发/落盘的字节。记录定长、无字符串表之外内容，是为了让节点端解码
// 不依赖任何映射表，也便于 gzip（相邻同国家的段地址连续，压缩率实测很好）。
func (t *Table) Encode() []byte {
	if t.enc != nil {
		return t.enc
	}
	var b bytes.Buffer
	b.WriteString(geoMagic)
	b.WriteByte(0)
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], uint32(len(t.V4)))
	b.Write(u32[:])
	binary.BigEndian.PutUint32(u32[:], uint32(len(t.V6)))
	b.Write(u32[:])
	var u16 [2]byte
	binary.BigEndian.PutUint16(u16[:], uint16(len(t.Countries)))
	b.Write(u16[:])
	for _, c := range t.Countries {
		b.WriteString(c)
	}
	var rec [7]byte
	for _, p := range t.V4 {
		binary.BigEndian.PutUint32(rec[:4], p.addr)
		rec[4] = p.bits
		binary.BigEndian.PutUint16(rec[5:], p.cidx)
		b.Write(rec[:])
	}
	var rec6 [19]byte
	for _, p := range t.V6 {
		copy(rec6[:16], p.addr[:])
		rec6[16] = p.bits
		binary.BigEndian.PutUint16(rec6[17:], p.cidx)
		b.Write(rec6[:])
	}
	t.enc = b.Bytes()
	return t.enc
}

func (t *Table) Bytes() []byte { return t.Encode() }

// Decode 解开一张表，同时校验魔数、条数上限、前缀长度与 cidx 越界。
// 校验不过就直接拒收：半张表比没表更糟——它会让人觉得这个国家只封了一半。
func Decode(raw []byte) (*Table, error) {
	if len(raw) < len(geoMagic)+1+4+4+2 {
		return nil, fmt.Errorf("表内容太短(%d 字节)", len(raw))
	}
	if string(raw[:len(geoMagic)]) != geoMagic {
		return nil, fmt.Errorf("不是前缀表（魔数 %q）", raw[:len(geoMagic)])
	}
	r := raw[len(geoMagic):]
	_ = r[0] // flags，当前恒 0
	r = r[1:]
	n4 := int(binary.BigEndian.Uint32(r[:4]))
	n6 := int(binary.BigEndian.Uint32(r[4:8]))
	r = r[8:]
	if n4 > geoMaxCount || n6 > geoMaxCount {
		return nil, fmt.Errorf("条数异常 v4=%d v6=%d", n4, n6)
	}
	if len(r) < 2 {
		return nil, fmt.Errorf("国家清单被截断")
	}
	nc := int(binary.BigEndian.Uint16(r[:2]))
	r = r[2:]
	if nc <= 0 || nc > 255 {
		return nil, fmt.Errorf("国家数异常 %d", nc)
	}
	if len(r) < nc*2 {
		return nil, fmt.Errorf("国家清单被截断")
	}
	t := &Table{Countries: make([]string, 0, nc)}
	for i := 0; i < nc; i++ {
		t.Countries = append(t.Countries, string(r[i*2:i*2+2]))
	}
	r = r[nc*2:]
	if len(r) < n4*7+n6*19 {
		return nil, fmt.Errorf("表被截断：需要 %d 字节，只有 %d", n4*7+n6*19, len(r))
	}
	t.V4 = make([]pref4, 0, n4)
	for i := 0; i < n4; i++ {
		p := pref4{addr: binary.BigEndian.Uint32(r[:4]), bits: r[4], cidx: binary.BigEndian.Uint16(r[5:7])}
		r = r[7:]
		if p.bits > 32 || p.cidx == 0 || int(p.cidx) > nc {
			return nil, fmt.Errorf("v4 第 %d 条不合法（前缀 /%d 或国家下标 %d）", i, p.bits, p.cidx)
		}
		if unaligned4(p.addr, p.bits) {
			return nil, fmt.Errorf("v4 第 %d 条 %d.%d.%d.%d/%d 未对齐到前缀边界，拒收", i,
				p.addr>>24, p.addr>>16&0xff, p.addr>>8&0xff, p.addr&0xff, p.bits)
		}
		if i > 0 && !less4(t.V4[i-1], p) && t.V4[i-1] != p {
			return nil, fmt.Errorf("v4 第 %d 条未按地址升序，二分找不到正确的段", i)
		}
		t.V4 = append(t.V4, p)
	}
	t.V6 = make([]pref6, 0, n6)
	for i := 0; i < n6; i++ {
		var p pref6
		copy(p.addr[:], r[:16])
		p.bits = r[16]
		p.cidx = binary.BigEndian.Uint16(r[17:19])
		r = r[19:]
		if p.bits > 128 || p.cidx == 0 || int(p.cidx) > nc {
			return nil, fmt.Errorf("v6 第 %d 条不合法（前缀 /%d 或国家下标 %d）", i, p.bits, p.cidx)
		}
		if unaligned6(p.addr, p.bits) {
			return nil, fmt.Errorf("v6 第 %d 条未对齐到 /%d 边界，拒收", i, p.bits)
		}
		if i > 0 && !less6(t.V6[i-1], p) && t.V6[i-1] != p {
			return nil, fmt.Errorf("v6 第 %d 条未按地址升序", i)
		}
		t.V6 = append(t.V6, p)
	}
	t.Fingerprint = fingerprint(t)
	return t, nil
}

func fingerprint(t *Table) string {
	sum := sha256.Sum256(t.Encode())
	return hex.EncodeToString(sum[:8])
}

// ── 查找 ──────────────────────────────────────────────────────────────────

// Country 查一个地址属于表里哪个国家。第二个返回值 false 表示这张表没有覆盖它
// （私网、保留段、库里没有，或它属于一个没被选进表的国家）——那是"未知"，
// 不是"某个国家"，判定层必须单独记账，不能把它算成任何一种结果。
func (t *Table) Country(ip net.IP) (string, bool) {
	if t == nil {
		return "", false
	}
	if v4 := ip.To4(); v4 != nil {
		return t.country4(binary.BigEndian.Uint32(v4))
	}
	v6 := ip.To16()
	if v6 == nil {
		return "", false
	}
	var a [16]byte
	copy(a[:], v6)
	return t.country6(a)
}

func (t *Table) country4(addr uint32) (string, bool) {
	i := sort.Search(len(t.V4), func(k int) bool { return t.V4[k].addr > addr }) - 1
	if i < 0 {
		return "", false
	}
	p := t.V4[i]
	// 包含它的前缀里，首地址最大的那条一定最长（两条包含同一地址的前缀必然互相嵌套），
	// 而排序把更长的一条放在后面，所以落在 i 就是最长匹配。
	code := t.Countries[p.cidx-1]
	if p.bits == 0 {
		return code, true // /0 覆盖整个 v4 空间，参与减法会移位溢出
	}
	if addr-p.addr >= uint32(1)<<(32-p.bits) {
		return "", false
	}
	return code, true
}

func (t *Table) country6(a [16]byte) (string, bool) {
	i := sort.Search(len(t.V6), func(k int) bool { return bytes.Compare(t.V6[k].addr[:], a[:]) > 0 }) - 1
	if i < 0 {
		return "", false
	}
	p := t.V6[i]
	if !samePrefix6(p.addr, a, p.bits) {
		return "", false
	}
	return t.Countries[p.cidx-1], true
}

func samePrefix6(a, b [16]byte, bits uint8) bool {
	full := int(bits) / 8
	for i := 0; i < full; i++ {
		if a[i] != b[i] {
			return false
		}
	}
	if rest := int(bits) % 8; rest != 0 {
		mask := byte(0xff) << (8 - rest)
		if a[full]&mask != b[full]&mask {
			return false
		}
	}
	return true
}

// Counts 给面板与节点读数用：每个国家进了多少条，以及总量。
func (t *Table) Counts() map[string]int {
	out := map[string]int{}
	for _, c := range t.Countries {
		out[c] = 0
	}
	for _, p := range t.V4 {
		out[t.Countries[p.cidx-1]]++
	}
	for _, p := range t.V6 {
		out[t.Countries[p.cidx-1]]++
	}
	return out
}

func (t *Table) Total() int {
	if t == nil {
		return 0
	}
	return len(t.V4) + len(t.V6)
}

// ── L4 安装 ───────────────────────────────────────────────────────────────

// Entry4 是一条能直接写进 LPM trie 的 v4 记录。国家用两位码原样带上：
// eBPF 侧只需要"命中/未命中"，标签留给面板读数，不该让内核去猜下标。
type Entry4 struct {
	Addr    uint32
	Bits    uint8
	Country string
}

type Entry6 struct {
	Addr    [16]byte
	Bits    uint8
	Country string
}

func (t *Table) List4() []Entry4 {
	out := make([]Entry4, 0, len(t.V4))
	for _, p := range t.V4 {
		out = append(out, Entry4{Addr: p.addr, Bits: p.bits, Country: t.Countries[p.cidx-1]})
	}
	return out
}

func (t *Table) List6() []Entry6 {
	out := make([]Entry6, 0, len(t.V6))
	for _, p := range t.V6 {
		out = append(out, Entry6{Addr: p.addr, Bits: p.bits, Country: t.Countries[p.cidx-1]})
	}
	return out
}
