package tengine

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"cdn/internal/config"
	"cdn/internal/secure"
	"cdn/templates"
)

type Generator struct {
	sitesAvailable string
	sitesEnabled   string
	edgePort       string
	luaEnabled     bool
	sslConfCmd     bool
	tmpl           *template.Template
}

// detectLua 通过 `tengine -V` 的编译参数判断本机 Tengine 是否带 lua-nginx-module。
// 缺失时模板不会输出 access_by_lua_block，避免 `tengine -t` 因 unknown directive 失败。
func detectLua(binary string) bool {
	if binary == "" {
		binary = "tengine"
	}
	out, err := exec.Command(binary, "-V").CombinedOutput()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "lua-nginx-module")
}

// semverAtLeast 比较 `1.19.4` 形式的版本号；位数不足按 0 补齐，任一字段非数字则判 false。
func semverAtLeast(v string, major, minor, patch int) bool {
	parts := strings.Split(v, ".")
	nums := make([]int, 3)
	for i := 0; i < 3 && i < len(parts); i++ {
		n, err := strconv.Atoi(parts[i])
		if err != nil {
			return false
		}
		nums[i] = n
	}
	return nums[0]*1000000+nums[1]*1000+nums[2] >= major*1000000+minor*1000+patch
}

// sslConfCommandSupported 从 `tengine -V` 的文本里判定能否受理 ssl_conf_command Ciphersuites。
// 两个条件同时成立才行：nginx 内核 >= 1.19.4（该指令的引入版本），OpenSSL >= 1.1.1
// （TLS 1.3 套件名的来源）。任一版本读不出来就返回 false：
// 输出一个本机不认识的指令不会只让这一条域名失败，而是 tengine -t 整体失败 →
// reload 被拒 → 该节点所有域名停在旧配置、新域名起不来。少配一行套件没这个代价。
func sslConfCommandSupported(vOutput string) bool {
	m := regexp.MustCompile(`nginx version: nginx/([0-9]+\.[0-9]+\.[0-9]+)`).FindStringSubmatch(vOutput)
	if m == nil {
		return false
	}
	nginxVer := m[1]
	// Tengine 可能用 OpenSSL/BabaSSL/Tongsuo，三者的 -V 行都带 "x.y.z" 版本号；
	// 只认 OpenSSL 会让挂 Tongsuo 的节点白丢这一行配置，所以按 "SSL ... 版本" 通用匹配。
	s := regexp.MustCompile(`(?:OpenSSL|BabaSSL|Tongsuo)[ /]+([0-9]+\.[0-9]+\.[0-9]+)`).FindStringSubmatch(vOutput)
	if s == nil {
		return false
	}
	return semverAtLeast(nginxVer, 1, 19, 4) && semverAtLeast(s[1], 1, 1, 1)
}

func detectSslConfCommand(binary string) bool {
	if binary == "" {
		binary = "tengine"
	}
	out, err := exec.Command(binary, "-V").CombinedOutput()
	if err != nil {
		return false
	}
	return sslConfCommandSupported(string(out))
}

func NewGenerator(sitesAvailable, sitesEnabled, edgePort string) (*Generator, error) {
	return NewGeneratorWithBinary(sitesAvailable, sitesEnabled, edgePort, "")
}

func NewGeneratorWithBinary(sitesAvailable, sitesEnabled, edgePort, tengineBinary string) (*Generator, error) {
	funcMap := template.FuncMap{
		"join": strings.Join,
		"originScheme": func(scheme string) string {
			if scheme == "https" {
				return "https"
			}
			return "http"
		},
		"ttlToSeconds": func(ttl string) int {
			if len(ttl) < 2 {
				return 3600
			}
			n, err := strconv.Atoi(ttl[:len(ttl)-1])
			if err != nil {
				return 3600
			}
			switch ttl[len(ttl)-1] {
			case 's':
				return n
			case 'm':
				return n * 60
			case 'h':
				return n * 3600
			case 'd':
				return n * 86400
			}
			return 3600
		},
	}
	tmpl, err := template.New("site").Funcs(funcMap).Parse(string(secure.MustDecrypt(templates.SiteConfEnc)))
	if err != nil {
		return nil, fmt.Errorf("parse site template: %w", err)
	}
	if edgePort == "" {
		edgePort = "9090"
	}
	return &Generator{
		sitesAvailable: sitesAvailable,
		sitesEnabled:   sitesEnabled,
		edgePort:       edgePort,
		luaEnabled:     detectLua(tengineBinary),
		sslConfCmd:     detectSslConfCommand(tengineBinary),
		tmpl:           tmpl,
	}, nil
}

// domainTemplateData 使用显式字段避免匿名嵌入导致 .Domain 名称冲突。
// 当 config.Domain 以匿名嵌入方式使用时，{{ .Domain }} 会解析为整个嵌入结构体
// 而非 config.Domain.Domain 字符串字段，导致 server_name 生成错误内容。
type domainTemplateData struct {
	ID             string
	Domain         string
	ClusterID      string
	OriginScheme   string
	GatewayProfile config.GatewayProfile
	Upstreams      []config.Upstream
	CacheRules     []config.CacheRule
	SSL            config.SSLConfig
	Enabled        bool
	// StaticPublic 决定静态赛道是否脱掉 auth_request。模板里用 `{{- if not $.StaticPublic }}`
	// 包住那三行：$ 是 range 里回到根变量的唯一写法（与同块的 $.GatewayProfile 一致）。
	StaticPublic   bool
	EdgePort       string
	LuaEnabled     bool
	SslConfCommand bool
}

func newTemplateData(d *config.Domain, edgePort string, luaEnabled, sslConfCmd bool) domainTemplateData {
	profile := d.GatewayProfile
	// 在渲染点兜底，而不是指望每个调用方都记得调：这两条路径会直接成为 location 名和
	// error_page 目标，空串或含非法字符产出的不是"某条路由不对"，而是整节点 tengine -t 失败。
	// Normalize 幂等且只改这两条路径，已经合法的值原样通过。
	profile.Normalize()
	return domainTemplateData{
		ID:             d.ID,
		Domain:         d.Domain,
		ClusterID:      d.ClusterID,
		OriginScheme:   d.OriginScheme,
		GatewayProfile: profile,
		Upstreams:      upstreamsWithPort(d.Upstreams, d.OriginScheme),
		CacheRules:     d.CacheRules,
		SSL:            d.SSL,
		Enabled:        d.Enabled,
		StaticPublic:   d.StaticPublic,
		EdgePort:       edgePort,
		LuaEnabled:     luaEnabled,
		SslConfCommand: sslConfCmd,
	}
}

// upstreamsWithPort 给没写端口的源站地址补上与回源协议一致的默认端口。
// upstream 块里的 server 不带端口时 nginx 一律按 80 连接，不看 proxy_pass 的 https，
// 于是「https 回源 + 源站填 1.2.3.4」会对 80 端口做 TLS 握手，全站 502。
func upstreamsWithPort(ups []config.Upstream, scheme string) []config.Upstream {
	port := "80"
	if scheme == "https" {
		port = "443"
	}
	out := make([]config.Upstream, len(ups))
	for i, u := range ups {
		out[i] = u
		addr := strings.TrimSpace(u.Address)
		if _, _, err := net.SplitHostPort(addr); err == nil {
			out[i].Address = addr
			continue
		}
		host := strings.TrimSuffix(strings.TrimPrefix(addr, "["), "]")
		if host == "" {
			continue
		}
		out[i].Address = net.JoinHostPort(host, port)
	}
	return out
}

func (g *Generator) WriteConfig(d *config.Domain) error {
	// 先渲染再判定：判据是"即将落盘的那份内容"，而不是原始记录。newTemplateData 里的
	// Normalize() 会把历史数据缺失的皮肤路径补成默认值，拿补完的值判定才不会误杀老域名。
	// 判定失败时磁盘、符号链接、reload 一个都不碰，站点继续按上一版 conf 服务。
	data := newTemplateData(d, g.edgePort, g.luaEnabled, g.sslConfCmd)
	if err := validateRenderData(data); err != nil {
		return err
	}
	confPath, err := domainConfPath(g.sitesAvailable, data.Domain)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(g.sitesAvailable, 0755); err != nil {
		return err
	}
	var buf bytes.Buffer
	if err := g.tmpl.Execute(&buf, data); err != nil {
		return fmt.Errorf("render template for %s: %w", d.Domain, err)
	}
	// 原子写入 Tengine 配置：先写 .tmp 再 rename。直接覆盖时如果 kill -9 留下半截
	// 配置，下次 tengine -t 会失败导致整个服务无法启动（所有站点全下线）。
	confTmp := confPath + ".tmp"
	if err := os.WriteFile(confTmp, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("write conf file: %w", err)
	}
	if err := os.Rename(confTmp, confPath); err != nil {
		return fmt.Errorf("rename conf file: %w", err)
	}
	if d.Enabled {
		return g.EnableDomain(d)
	}
	return nil
}

func (g *Generator) RemoveConfig(d *config.Domain) error {
	confPath, err := domainConfPath(g.sitesAvailable, d.Domain)
	if err != nil {
		return err
	}
	_ = g.DisableDomain(d)
	if err := os.Remove(confPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (g *Generator) EnableDomain(d *config.Domain) error {
	src, err := domainConfPath(g.sitesAvailable, d.Domain)
	if err != nil {
		return err
	}
	dst, err := domainConfPath(g.sitesEnabled, d.Domain)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(g.sitesEnabled, 0755); err != nil {
		return err
	}
	_ = os.Remove(dst)
	return os.Symlink(src, dst)
}

func (g *Generator) DisableDomain(d *config.Domain) error {
	dst, err := domainConfPath(g.sitesEnabled, d.Domain)
	if err != nil {
		return err
	}
	if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// ConfigSnapshot 记下若干域名在 sites-available / sites-enabled 里的站点配置原样，
// 新配置过不了 `tengine -t` 时用 Restore 恢复。坏配置如果留在 sites-enabled，运行中的
// Tengine 不受影响（reload 前就测试失败了），但下次重启（systemd 的 ExecStartPre 先跑 -t）
// 整台节点都起不来，所有站点一起下线。
type ConfigSnapshot struct {
	files map[string][]byte // sites-available 路径 → 原内容；nil 表示原来没有这个文件
	links map[string]string // sites-enabled 路径 → 原链接目标；"" 表示原来没有
}

// Snapshot 记录这些域名当前的站点配置（同名去重）。
func (g *Generator) Snapshot(domains ...string) *ConfigSnapshot {
	s := &ConfigSnapshot{files: map[string][]byte{}, links: map[string]string{}}
	for _, name := range domains {
		if name == "" {
			continue
		}
		// 非法域名直接跳过：Restore 会把这里记下的路径原样写回/删掉，收下一个越界名字
		// 等于把"读别人的站点配置再写回去"这条路留在快照里。
		avail, err := domainConfPath(g.sitesAvailable, name)
		if err != nil {
			continue
		}
		if _, seen := s.files[avail]; !seen {
			if b, err := os.ReadFile(avail); err == nil {
				s.files[avail] = b
			} else {
				s.files[avail] = nil
			}
		}
		enabled, err := domainConfPath(g.sitesEnabled, name)
		if err != nil {
			continue
		}
		if _, seen := s.links[enabled]; !seen {
			target, err := os.Readlink(enabled)
			if err != nil {
				target = ""
			}
			s.links[enabled] = target
		}
	}
	return s
}

// Restore 把 Snapshot 记录的文件和链接恢复原样：原来没有的删掉，原来有的写回。
func (s *ConfigSnapshot) Restore() error {
	if s == nil {
		return nil
	}
	var firstErr error
	keep := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for path, content := range s.files {
		if content == nil {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				keep(err)
			}
			continue
		}
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, content, 0644); err != nil {
			keep(err)
			continue
		}
		keep(os.Rename(tmp, path))
	}
	for path, target := range s.links {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			keep(err)
			continue
		}
		if target != "" {
			keep(os.Symlink(target, path))
		}
	}
	return firstErr
}
