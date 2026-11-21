package config

import (
	"fmt"
	"time"

	"golang.org/x/crypto/bcrypt"

	"cdn/internal/geo"
)

func HashPassword(password string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

type PanelConfig struct {
	ListenAddr     string `json:"listen_addr"`
	TengineCmd     string `json:"tengine_cmd"`
	TenginePid     string `json:"tengine_pid"`
	TengineConf    string `json:"tengine_conf"`
	SitesAvailable string `json:"sites_available"`
	SitesEnabled   string `json:"sites_enabled"`
	CacheBasePath  string `json:"cache_base_path"`
	SSLBasePath    string `json:"ssl_base_path"`
	DataDir        string `json:"data_dir"`
	AdminUser      string `json:"admin_user"`
	AdminPassHash  string `json:"admin_pass_hash"`
	AutocertEmail  string `json:"autocert_email"`
	AutocertDir    string `json:"autocert_dir"`
	EdgeAgentPort  string `json:"edge_agent_port"` // cdnedge 监听端口，用于 WAF auth_request

	// Cloudflare 集成（可选）
	CFApiToken   string `json:"cf_api_token"`
	CFZoneID     string `json:"cf_zone_id"`
	CFBaseDomain string `json:"cf_base_domain"`

	// ACME 签发目录（申请 Let's Encrypt 证书用）。留空 = Let's Encrypt 正式环境，
	// 只有在要指向自建/测试 CA 时才填；它不参与任何对客展示。
	ACMEDirectory string `json:"acme_directory,omitempty"`

	// WAF 封禁 IP 文件路径
	WAFBannedIPsFile string `json:"waf_banned_ips_file"`

	// IP 归属地库（dbip-city-*.mmdb）所在目录，留空则用 geoip.DefaultDirs 的查找顺序。
	GeoIPDir string `json:"geoip_dir,omitempty"`

	// MySQL 连接信息（安装向导写入；业务数据现仍在本地 JSON 文件，这里只用于建库和后续接入）
	DBHost     string `json:"db_host,omitempty"`
	DBPort     string `json:"db_port,omitempty"`
	DBUser     string `json:"db_user,omitempty"`
	DBPassword string `json:"db_password,omitempty"`
	DBName     string `json:"db_name,omitempty"`
}

// MySQLDSN 拼出 go-sql-driver/mysql 的 DSN。时间统一按 UTC 存取（loc=UTC 管 Go 侧，
// time_zone='+00:00' 管会话里的 CURRENT_TIMESTAMP/列默认值，服务器时区是 +8 也不会错开），
// 对应 migrations/0001_init.sql 里 DATETIME(6) 存 UTC 的约定。
// clientFoundRows=true：RowsAffected 返回「匹配行数」而非「实际改动行数」。各 repo 用
// affected==0 判 404，写入值与原值相同（如 resync 后 CF 记录没变）时否则会误报 sql.ErrNoRows。
// 不指定 collation：utf8mb4_0900_ai_ci 是 MySQL 8 专有，5.7/MariaDB 握手时直接报 1273；
// 比较时表列自身的排序规则优先于连接的默认排序规则，不指定也不影响大小写不敏感。
func (c *PanelConfig) MySQLDSN() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?parseTime=true&loc=UTC&time_zone=%%27%%2B00%%3A00%%27&charset=utf8mb4&clientFoundRows=true",
		c.DBUser, c.DBPassword, c.DBHost, c.DBPort, c.DBName)
}

func DefaultPanelConfig() *PanelConfig {
	return &PanelConfig{
		ListenAddr:     "0.0.0.0:8080",
		TengineCmd:     "/usr/local/tengine/sbin/tengine",
		TenginePid:     "/var/run/tengine.pid",
		TengineConf:    "/etc/tengine/tengine.conf",
		SitesAvailable: "/etc/tengine/sites-available",
		SitesEnabled:   "/etc/tengine/sites-enabled",
		CacheBasePath:  "/var/cache/tengine",
		SSLBasePath:    "/etc/ssl/cdnpanel",
		DataDir:        "/etc/cdnpanel/domains",
		AdminUser:      "admin",
		AutocertDir:    "/etc/ssl/cdnpanel/autocert",
		EdgeAgentPort:  "9090",
	}
}

type Domain struct {
	ID                    string         `json:"id"`
	Domain                string         `json:"domain"`
	ClusterID             string         `json:"cluster_id"`
	OriginScheme          string         `json:"origin_scheme"`
	GatewayProfile        GatewayProfile `json:"gateway_profile"`
	Upstreams             []Upstream     `json:"upstreams"`
	CacheRules            []CacheRule    `json:"cache_rules"`
	SSL                   SSLConfig      `json:"ssl"`
	Enabled               bool           `json:"enabled"`
	Tags                  []string       `json:"tags,omitempty"`                     // 标签分类
	CNAMERecord           string         `json:"cname_record,omitempty"`             // 切换记录（用户域名 CNAME 的目标），如 exlewl.gqcdnwaf.click
	CNAMERecordID         string         `json:"cname_record_id,omitempty"`          // 用户域名本身的 CNAME 记录 ID（仅用户域名在本 zone 内、由面板代建时有值）
	MainSubdomainRecordID string         `json:"main_subdomain_record_id,omitempty"` // 切换记录的 DNS 记录 ID（灰云 CNAME → 集群子域名 / 高防 CNAME）
	EdgeRecordIDs         []string       `json:"edge_record_ids,omitempty"`          // 边缘节点 A 记录 IDs（多个）
	CloudflareProxyID     string         `json:"cloudflare_proxy_id,omitempty"`      // 已废弃：旧版专用橙云记录 xxx-edge.<base> 的 ID，仅用于删除域名时一并清理
	DefenseCNAME          string         `json:"defense_cname,omitempty"`            // 高防 CDN 给的 CNAME（空 = 用集群默认值）；切到高防时切换记录改指向它
	OnDefense             bool           `json:"on_defense"`                         // 当前切换记录是否指向高防 CNAME
	DefenseByFailover     bool           `json:"defense_by_failover,omitempty"`      // 是否由故障转移自动切到高防（自动回切只处理这类，不动手动切的）
	// StaticPublic 是「纯多媒体/静态资产域名」开关：开启后静态资源赛道不挂 auth_request
	// 逐请求指纹审计，原生 App、小程序、第三方服务端可以无凭证直连拉图拉流。
	// 它是域名属性，不是安全增强项——换来的代价是这条赛道失去速率/指纹审计，随机 Query
	// 打穿缓存的洪水只剩 limit_conn 与全局速率闸兜底，所以只能由租户显式打开。
	// 默认 false：升级前存的域名 JSON 里没有这个键，反序列化即为 false，行为一字不变。
	StaticPublic bool     `json:"static_public"`        // 静态赛道免凭证直连（见上方取舍说明）
	CFMessage    string   `json:"cf_message,omitempty"` // 最近一次 Cloudflare 同步的错误/提示
	CCPolicy     CCPolicy `json:"cc_policy"`            // CC 强检测（JS 挑战）按域名配置
	// GeoPolicy 是按域名的区域规则（封禁/只放行哪些国家）。它的类型就是 internal/geo
	// 里主控校验、面板回显、边缘判定共用的那一份：中间任何一层自己再定义一遍结构体，
	// 就会重演「面板存了一份节点其实不认的配置」。零值（没配过）= 不启用，行为与升级前一致。
	GeoPolicy geo.Policy `json:"geo_policy"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
}

// PreserveCFState 把由面板维护的 Cloudflare 状态从 src 拷回 d。
// 编辑域名时前端会把整张表单（含这些字段）发回来，不能让它覆盖服务端记录的 ID 与状态。
func (d *Domain) PreserveCFState(src *Domain) {
	d.CNAMERecord = src.CNAMERecord
	d.CNAMERecordID = src.CNAMERecordID
	d.MainSubdomainRecordID = src.MainSubdomainRecordID
	d.EdgeRecordIDs = src.EdgeRecordIDs
	d.CloudflareProxyID = src.CloudflareProxyID
	d.OnDefense = src.OnDefense
	d.DefenseByFailover = src.DefenseByFailover
	d.CFMessage = src.CFMessage
}

// CCPolicy 是按域名独立配置的 CC 强检测策略。基础频率阈值（每秒/每分钟请求数等）
// 仍使用全局配置，这里只控制三档强度中第二、三层的开关与域名级阈值：
//  1. 全局按 IP 频率限制（始终生效，见 CCConfig，不受本结构体控制）。
//  2. JS 环境挑战 + 自定义单 IP 速率阈值（ChallengeEnabled/ChallengeThreshold/ChallengeRPS/ChallengeRPM）。
//  3. 高强度检测：JA4H 指纹统计 + IP + 速率（StrictEnabled/StrictThreshold/FingerprintThreshold），
//     语义上要求已开启第二层，且沿用第二层的 ChallengeRPS/ChallengeRPM。
//
// 第 2、3 层默认是「动态阈值自适应触发」：平时盾牌收起来，无凭证的首访请求直接 200 放行
// （低频访客、合规爬虫与搜索引擎巡检因此不会被拖进验证页），只有域名整体 QPS 越过阈值才
// 自动开盾，并在攻击停手后按 ChallengeHoldSeconds 冷却平滑降级回去。
//
// 因此 ChallengeThreshold / StrictThreshold 不是"要不要防"的开关，而是"什么强度算攻击"的
// 判定线：设得越高，静默放行窗口越大，越接近被慢速攻击打穿的程度。
type CCPolicy struct {
	ChallengeEnabled     bool                `json:"challenge_enabled"`       // 是否允许该域名在强攻击时触发 JS 环境验证（未进攻击态时不验证）
	ChallengeAlways      bool                `json:"challenge_always"`        // 始终验证：不等攻击态，任何无有效验证 cookie 的访客进门先验证一次真人（通过后凭 cookie 放行，不收紧封禁阈值）
	ChallengeMode        string              `json:"challenge_mode"`          // 验证模式：""/"js"=无感 JS cookie（默认）；"shield"=3秒盾；"slider"=滑块拖拽；"text"=文字/算术验证
	ChallengeBindScope   string              `json:"challenge_bind_scope"`    // 验证凭证绑定客户端地址的粒度：""/"ip"=完整 IP（默认，最严）；"subnet"=IPv4 /24、IPv6 /48；"none"=不绑地址（出口 IP 会漂移的网络用）
	ChallengeThreshold   int                 `json:"challenge_threshold"`     // 域名整体 QPS 超过此值判定为强攻击、进入开盾态（0 表示使用系统默认值）
	ChallengeHoldSeconds int                 `json:"challenge_hold_seconds"`  // 开盾态最短维持秒数：QPS 回落后仍继续要求验证，避免间歇攻击反复把真人拖进验证页（0=默认 90，限 10~900）
	ChallengeRPS         int                 `json:"challenge_rps"`           // 进入攻击态（第二/三层）后，单个 IP 每秒请求数阈值（0 表示沿用全局阈值，不额外收紧）
	ChallengeRPM         int                 `json:"challenge_rpm"`           // 进入攻击态（第二/三层）后，单个 IP 每分钟请求数阈值（0 表示沿用全局阈值）
	VerifiedRPS          int                 `json:"verified_rps"`            // 已通过验证（持有有效 cookie）的用户每秒请求数阈值（0 或未设置时沿用 challenge_rps）
	VerifiedRPM          int                 `json:"verified_rpm"`            // 已通过验证的用户每分钟请求数阈值（0 或未设置时沿用 challenge_rpm）
	StrictEnabled        bool                `json:"strict_enabled"`          // 是否在更高流量下启用 JA4H 指纹统计检测
	StrictThreshold      int                 `json:"strict_threshold"`        // 域名整体 QPS 超过此值判定为高强度攻击（0 表示使用系统默认值，应高于 ChallengeThreshold）
	FingerprintThreshold int                 `json:"fingerprint_threshold"`   // 单个 JA4H 指纹每秒请求数超过此值判定为可疑（0 表示使用系统默认值）
	CacheBusting         *CacheBustingConfig `json:"cache_busting,omitempty"` // 缓存绕过攻击检测配置（可选）
}

// CacheBustingConfig 缓存绕过攻击检测配置。
type CacheBustingConfig struct {
	WhitelistParams []string `json:"whitelist_params"` // 业务合法使用的参数名（如 token、session_id），这些参数的变化不计入攻击信号
}

type Upstream struct {
	Address string `json:"address"`
	Weight  int    `json:"weight"`
}

type CacheRule struct {
	Extensions []string `json:"extensions"`
	TTL        string   `json:"ttl"`
	Enabled    bool     `json:"enabled"`
}

type SSLConfig struct {
	Enabled  bool   `json:"enabled"`
	Mode     string `json:"mode"` // "autocert" | "manual" | "disabled"
	CertFile string `json:"cert_file,omitempty"`
	KeyFile  string `json:"key_file,omitempty"`
}
