// Package geoip 把来源 IP 翻成归属地文字，数据是 DB-IP City Edition Lite 的 mmdb。
//
// 为什么不用 GeoLite2：它的再分发许可要求付费 Commercial GeoLite License，而这里是
// 随安装包交付库文件；DB-IP City Lite 是 CC BY 4.0，代价是必须在使用它的页面上署名
// 回链（见 internal/apiv2/security.go 的 geoip 块与 vue/src/views/TrafficView.vue）。
package geoip

import (
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/oschwald/maxminddb-golang"
)

// 库文件名固定，部署侧按这两个名字把文件放对目录即可。
const (
	FileIPv4 = "dbip-city-ipv4.mmdb"
	FileIPv6 = "dbip-city-ipv6.mmdb"
)

// Record 是页面要展示的归属地。字段取自 mmdb 实测的 country_code / state1 / city；
// DB-IP Lite 的 languages 为空，只有 ISO 国家码，没有国家或城市的中文名。
type Record struct {
	Country string `json:"country"`
	Region  string `json:"region"`
	City    string `json:"city"`
}

// Locator 持有已打开的库。缺库不当成错误，而是把"找了哪些目录、差在哪"原样交给 API：
// 页面要能明说地理库未就位，而不是让归属地列凭空一片空白（静默降级）。
type Locator struct {
	v4, v6  *maxminddb.Reader
	Loaded  []string // 真正打开的文件绝对路径
	Missing []string // 缺失或打不开的库，各带一条原因
}

// Open 在 dirs 里依次找两个库文件，每个库取第一个能成功打开的路径。某目录里的文件打不开
// （截断、不是 mmdb）就继续试下一个目录，并把失败原因记进 Missing。
func Open(dirs []string) *Locator {
	l := &Locator{}
	dirs = nonEmpty(dirs)
	l.v4 = l.open(FileIPv4, dirs)
	l.v6 = l.open(FileIPv6, dirs)
	return l
}

func (l *Locator) open(file string, dirs []string) *maxminddb.Reader {
	var failures []string
	for _, d := range dirs {
		p := filepath.Join(d, file)
		if !fileExists(p) {
			continue
		}
		r, err := maxminddb.Open(p)
		if err != nil {
			failures = append(failures, p+": "+err.Error())
			continue
		}
		l.Loaded = append(l.Loaded, p)
		return r
	}
	if len(failures) > 0 {
		l.Missing = append(l.Missing, file+" 打开失败 —— "+strings.Join(failures, "; "))
		return nil
	}
	l.Missing = append(l.Missing, file+" 未找到，搜索过："+strings.Join(dirs, " | "))
	return nil
}

// Ready 表示至少有一个库可查。两个都缺时 API 会把 Missing 透给前端。
// 允许 l 为 nil：调用方（handler）不必为"没传库"再写一层判空。
func (l *Locator) Ready() bool { return l != nil && (l.v4 != nil || l.v6 != nil) }

// Lookup 查一个 IP。IPv4-mapped IPv6（::ffff:1.2.3.4）在 v6 库里查不到（实测），
// 所以先按 To4() 分流。查不到——私网、保留段、库未覆盖、l 为 nil——返回 false。
func (l *Locator) Lookup(addr string) (Record, bool) {
	if l == nil {
		return Record{}, false
	}
	ip := net.ParseIP(addr)
	if ip == nil {
		return Record{}, false
	}
	r := l.v6
	if ip.To4() != nil {
		r = l.v4
	}
	if r == nil {
		return Record{}, false
	}
	var rec struct {
		CountryCode string `maxminddb:"country_code"`
		State1      string `maxminddb:"state1"`
		City        string `maxminddb:"city"`
	}
	if err := r.Lookup(ip, &rec); err != nil {
		return Record{}, false
	}
	if rec.CountryCode == "" && rec.City == "" {
		return Record{}, false
	}
	return Record{Country: rec.CountryCode, Region: rec.State1, City: rec.City}, true
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir() && st.Size() > 0
}

func nonEmpty(in []string) []string {
	out := make([]string, 0, len(in))
	for _, d := range in {
		if strings.TrimSpace(d) != "" {
			out = append(out, d)
		}
	}
	return out
}

// DefaultDirs 是库文件的查找顺序：配置里指定的目录 → 二进制同目录 → 二进制同目录下的
// data/（dist/ 出包形态）→ /etc/cdnpanel（install.sh 装库的位置）→ 当前目录
// 的 data/（开发期从仓库根跑）。
func DefaultDirs(configured string) []string {
	dirs := []string{configured}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		dirs = append(dirs, dir, filepath.Join(dir, "data"))
	}
	return append(dirs, "/etc/cdnpanel", filepath.Join("data"))
}
