// Package geo 把「国家」翻译成边缘能直接执行的 IP 前缀表。
//
// 为什么不让节点自己查库：DB-IP Country Lite 一次全库扫描实测 139ms / 596,718 条网络，
// 而区域规则的判定必须在每个请求上发生。所以由面板算一次「策略里真正用到的那几个国家」
// 的前缀表（CN 约 8k 段、US 15.1 万段），编成定长记录下发，节点只做一次二分。
// L4 用的 LPM trie 也从同一张表装，保证「面板显示的那张表」和「网卡上生效的那张表」
// 是同一份内容，靠 fingerprint 核对而不是靠人相信。
//
// 许可与 internal/geoip 一致：DB-IP 是 CC BY 4.0，用了它的结果就必须在展示页署名回链。
package geo

import (
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/oschwald/maxminddb-golang"

	"cdn/internal/geoip"
)

// 库文件名固定；面板按 geoip.DefaultDirs 的同一套顺序找它们。
const (
	FileIPv4 = "dbip-country-ipv4.mmdb"
	FileIPv6 = "dbip-country-ipv6.mmdb"
)

// DB 是已打开的两个国家级库。缺库不算错误：区域规则必须能说清"没库所以没算出表"，
// 而不是算出一张空表让节点以为"这个国家没有 IP"。
type DB struct {
	v4, v6  *maxminddb.Reader
	Loaded  []string
	Missing []string

	// 国家目录的缓存（见 CountryCodes）。地理库文件在进程生命周期内不会变，
	// 所以这个缓存没有失效路径，也不需要锁在每次调用上。
	codesOnce sync.Once
	codes     []string
	codesErr  string
}

// Open 在 dirs 里找两个库文件，每个取第一个能打开的路径。
func Open(dirs ...string) *DB {
	if len(dirs) == 0 {
		dirs = geoip.DefaultDirs("")
	}
	d := &DB{}
	d.v4 = d.open(FileIPv4, dirs)
	d.v6 = d.open(FileIPv6, dirs)
	return d
}

func (d *DB) open(file string, dirs []string) *maxminddb.Reader {
	var failures []string
	for _, dir := range dirs {
		if strings.TrimSpace(dir) == "" {
			continue
		}
		p := filepath.Join(dir, file)
		st, err := os.Stat(p)
		if err != nil || st.IsDir() || st.Size() == 0 {
			continue
		}
		r, err := maxminddb.Open(p)
		if err != nil {
			failures = append(failures, p+": "+err.Error())
			continue
		}
		d.Loaded = append(d.Loaded, p)
		return r
	}
	if len(failures) > 0 {
		d.Missing = append(d.Missing, file+" 打开失败 —— "+strings.Join(failures, "; "))
		return nil
	}
	d.Missing = append(d.Missing, file+" 未找到，搜索过："+strings.Join(nonEmpty(dirs), " | "))
	return nil
}

// Ready 表示至少有一个家族可查；两个都缺时编译一定失败，界面要显示这个原因。
func (d *DB) Ready() bool { return d != nil && (d.v4 != nil || d.v6 != nil) }

// Available 报告各家族是否就位，供面板在保存配置时就拒绝，而不是下发一张半张表。
func (d *DB) Available() (v4, v6 bool) {
	if d == nil {
		return false, false
	}
	return d.v4 != nil, d.v6 != nil
}

func nonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

// ── 国家目录 ──────────────────────────────────────────────────────────────

// CountryCodes 列出两个库里真正出现过的国家码，给管理员划"租户可选范围"用。
//
// 全库扫描实测 139ms，所以只在第一次调用时扫，结果缓存进 DB：面板的配置页会被反复打开，
// 每次点进去都扫一遍库等于给主控加了个 0.1 秒的固定开销。缓存不清（同一个进程生命周期里
// 地理库文件不会变；换库要重启面板，这本来也是 install.sh 的动作）。
func (d *DB) CountryCodes() []string {
	if d == nil {
		return nil
	}
	d.codesOnce.Do(func() {
		seen := map[string]bool{}
		var rec countryRecord
		for _, pair := range []struct {
			r    *maxminddb.Reader
			name string
		}{{d.v4, FileIPv4}, {d.v6, FileIPv6}} {
			if pair.r == nil {
				continue
			}
			ns := pair.r.Networks(maxminddb.SkipAliasedNetworks)
			for ns.Next() {
				if _, err := ns.Network(&rec); err != nil {
					d.codesErr = pair.name + " 条目读取失败: " + err.Error()
					return
				}
				c := strings.ToUpper(strings.TrimSpace(rec.CountryCode))
				if len(c) == 2 {
					seen[c] = true
				}
			}
			if err := ns.Err(); err != nil {
				d.codesErr = pair.name + " 遍历失败: " + err.Error()
				return
			}
		}
		out := make([]string, 0, len(seen))
		for c := range seen {
			out = append(out, c)
		}
		sort.Strings(out)
		d.codes = out
	})
	return d.codes
}

// CountryCodesErr 是目录扫描失败的原因。没失败时为空串。
// 必须能问出来：目录空着和目录扫挂了在面板上是两种完全不同的处置。
func (d *DB) CountryCodesErr() string {
	if d == nil {
		return ""
	}
	_ = d.CountryCodes()
	return d.codesErr
}

// ── 编译 ──────────────────────────────────────────────────────────────────

type countryRecord struct {
	CountryCode string `maxminddb:"country_code"`
}

// Compile 扫库，取 want 里这些国家的全部网络，编成一张前缀表。
//
// 只编译被引用的国家，是这张表能小到几百 KB 的原因："只允许 CN" 只需要 CN 的段，
// 别人的国家一条都不进表。查不到归属（私网、保留段、库未覆盖）在表里表现为"无记录"，
// 由判定侧单独记账——它是区域规则唯一放行的口子，必须可见。
func (d *DB) Compile(want []string) (*Table, error) {
	if !d.Ready() {
		return nil, fmt.Errorf("地理库未就位：%s", strings.Join(d.Missing, "; "))
	}
	idx := map[string]int{}
	var codes []string
	for _, c := range want {
		c = strings.ToUpper(strings.TrimSpace(c))
		if c == "" {
			continue
		}
		if len(c) != 2 {
			return nil, fmt.Errorf("国家码 %q 不合法（要用 ISO 3166-1 alpha-2 两位码）", c)
		}
		if _, ok := idx[c]; ok {
			continue
		}
		idx[c] = len(codes) + 1 // 0 号留给"未覆盖"，不能做国家下标
		codes = append(codes, c)
	}
	if len(codes) == 0 {
		return nil, fmt.Errorf("没有选定任何国家")
	}
	sort.Strings(codes)
	for i, c := range codes {
		idx[c] = i + 1
	}

	t := &Table{Countries: codes}
	if err := t.scan(d.v4, idx, false); err != nil {
		return nil, err
	}
	if err := t.scan(d.v6, idx, true); err != nil {
		return nil, err
	}
	if len(t.V4) == 0 && len(t.V6) == 0 {
		return nil, fmt.Errorf("选定的国家 %v 在库里一条网络都没有", codes)
	}
	sort.Slice(t.V4, func(i, j int) bool { return less4(t.V4[i], t.V4[j]) })
	sort.Slice(t.V6, func(i, j int) bool { return less6(t.V6[i], t.V6[j]) })
	if err := t.canonicalize(); err != nil {
		return nil, err
	}
	t.Fingerprint = fingerprint(t)
	return t, nil
}

// canonicalize 去掉对齐后重复的条目，并把"同一条前缀被库判给两个国家"当成错误报出来。
// 这种冲突只能出现，不能默默挑一个：挑错了面板上显示的国别和实际拦的就不是同一回事。
func (t *Table) canonicalize() error {
	out := t.V4[:0]
	for i, p := range t.V4 {
		if i > 0 && t.V4[i-1] == p {
			continue
		}
		if i > 0 && t.V4[i-1].addr == p.addr && t.V4[i-1].bits == p.bits {
			return fmt.Errorf("库自相矛盾：%s 与 %s 都主张同一条 v4 前缀", t.Countries[t.V4[i-1].cidx-1], t.Countries[p.cidx-1])
		}
		out = append(out, p)
	}
	t.V4 = out
	out6 := t.V6[:0]
	for i, p := range t.V6 {
		if i > 0 && t.V6[i-1] == p {
			continue
		}
		if i > 0 && t.V6[i-1].addr == p.addr && t.V6[i-1].bits == p.bits {
			return fmt.Errorf("库自相矛盾：%s 与 %s 都主张同一条 v6 前缀", t.Countries[t.V6[i-1].cidx-1], t.Countries[p.cidx-1])
		}
		out6 = append(out6, p)
	}
	t.V6 = out6
	return nil
}

func (t *Table) scan(r *maxminddb.Reader, idx map[string]int, v6 bool) error {
	if r == nil {
		return nil
	}
	// SkipAliasedNetworks：v6 库把整段 IPv4 空间别名进 v6 树，不跳过会把 v4 重复编一遍，
	// 于是同一个地址在表里出现两次、判定结果取决于二分落在哪条。
	ns := r.Networks(maxminddb.SkipAliasedNetworks)
	for ns.Next() {
		var rec countryRecord
		nw, err := ns.Network(&rec)
		if err != nil {
			return fmt.Errorf("遍历库失败: %w", err)
		}
		id, ok := idx[strings.ToUpper(rec.CountryCode)]
		if !ok {
			continue
		}
		ones, _ := nw.Mask.Size()
		if !v6 {
			ip := nw.IP.To4()
			if ip == nil {
				continue
			}
			t.V4 = append(t.V4, pref4{addr: align4(binary.BigEndian.Uint32(ip), ones), bits: uint8(ones), cidx: uint16(id)})
			continue
		}
		ip := nw.IP.To16()
		if ip == nil {
			continue
		}
		var a [16]byte
		copy(a[:], ip)
		align6(&a, ones)
		t.V6 = append(t.V6, pref6{addr: a, bits: uint8(ones), cidx: uint16(id)})
	}
	return ns.Err()
}
