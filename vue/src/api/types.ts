// 与 docs/API-v2.md 对应的类型定义。字段名和契约保持一致，改契约先改这里。

export interface ApiError {
  code: string
  message: string
  details?: Record<string, unknown>
}

export interface Paginated<T> {
  items: T[]
  total: number
  page: number
  page_size: number
}

export interface Job<TResult = unknown> {
  id: string
  type: string
  status: 'pending' | 'running' | 'done' | 'failed'
  progress: number
  message: string
  warning: string
  result: TResult | null
  created_at: string
  updated_at: string
}

// ---------------------------------------------------------------------------
// 认证 / 当前账号（3.1 节租户 Me；管理员结构类似但字段更少，见 AdminMe）
// ---------------------------------------------------------------------------

export interface Me {
  user: { id: string; email: string; role: 'owner' | 'member' | 'readonly' }
  tenant: { id: string; name: string; status: 'active' | 'suspended'; expires_at: string | null }
  plan: { code: string; name: string; max_nodes: number; max_domains: number; max_clusters: number }
  usage: { nodes: number; domains: number; clusters: number }
  csrf_token: string
}

// GET /api/v2/dashboard（3.9 节的子集：usage/plan 复用 Me 的同名字段，clusters 是按
// health.status 汇总的分布计数，如 {"active": 3, "degraded": 1}）
export interface Dashboard {
  usage: Me['usage']
  plan: Me['plan']
  nodes: { online: number; total: number }
  today: {
    requests: number
    bytes: number
    blocked: number
    hourly?: { hour: number; requests: number; bytes: number; blocked: number }[]
  }
  clusters: Record<string, number>
}

export interface AdminMe {
  admin: { id: string; username: string }
  csrf_token: string
}

// ---------------------------------------------------------------------------
// Domain
// ---------------------------------------------------------------------------

export interface Upstream {
  address: string
  weight: number
}

export interface CacheRule {
  extensions: string[]
  ttl: string
  enabled: boolean
}

export interface SslConfig {
  // off / manual 两种：'auto' 以前也在 API 里可选，但面板从未实现自动签发，
  // 选了它等于悄悄不启用 HTTPS。现在自助签发是显式动作（POST .../certificate/acme），
  // 签完落成 manual。
  mode: 'off' | 'manual'
  certificate_id: string | null
  force_https: boolean
}

export interface CCPolicy {
  challenge_enabled: boolean
  // 为 true 时无视 QPS 判定线，对所有无凭证请求恒定弹验证（老的全局强校验行为）。
  // 默认 false：平时静默放行，域名 QPS 越过 challenge_threshold 才自动开盾。
  challenge_always: boolean
  challenge_mode: '' | 'js' | 'shield' | 'slider' | 'text'
  challenge_bind_scope: '' | 'ip' | 'subnet' | 'none'
  // 开盾判定线：该域名秒级 QPS 超过它就进入攻击态。0 = 用系统默认值。
  challenge_threshold: number
  // 开盾后的持稳冷却秒数，期间流量回落也不会立刻收盾。0 = 默认 90 秒。
  challenge_hold_seconds?: number
  challenge_rps: number
  challenge_rpm: number
  verified_rps: number
  verified_rpm: number
  strict_enabled: boolean
  strict_threshold: number
  fingerprint_threshold: number
  cache_busting?: { whitelist_params: string[] }
}

export interface Domain {
  id: string
  domain: string
  cluster_id: string | null
  origin_scheme: 'http' | 'https'
  upstreams: Upstream[]
  cache_rules: CacheRule[]
  ssl: SslConfig
  enabled: boolean
  // 静态赛道免凭证直连：纯多媒体/静态资产域名开启后，静态资源 location 不挂 auth_request，
  // 原生 App / 小程序 / 第三方服务端可无凭证拉图拉流。代价是这条赛道失去逐请求校验
  // （无 JA4H 指纹采集、无 CC 判定、无 WAF 命中），只剩 limit_conn 与全局速率闸。
  static_public: boolean
  tags: string[]
  defense_cname: string
  cc_policy: CCPolicy
  // 按域名的区域规则。后端回显的是真实生效的那一份（没写过的字段补默认值），
  // 不是库里原始的字节，所以 PUT/PATCH 时原样提交它即可。
  geo_policy: GeoPolicy
  geo_push?: GeoPushResult
  verification: {
    status: 'pending' | 'verified'
    record_name: string
    record_value: string
    verified_at: string | null
  }
  dns: {
    cname_target: string
    on_defense: boolean
    defense_by_failover: boolean
    active_target: string
  }
  sync: {
    state: 'synced' | 'pending' | 'error'
    cf_message: string
    edge_failed: Record<string, string>
    synced_at: string | null
  }
  version: number
  created_at: string
  updated_at: string
}

// 创建时只需要的最小字段，其余走 PATCH
export interface DomainCreateInput {
  domain: string
  cluster_id?: string | null
  origin_scheme?: 'http' | 'https'
  upstreams: Upstream[]
  defense_cname?: string
  enabled?: boolean
}

export type DomainPatchInput = Partial<
  Pick<
    Domain,
    | 'cluster_id'
    | 'origin_scheme'
    | 'upstreams'
    | 'cache_rules'
    | 'ssl'
    | 'enabled'
    | 'tags'
    | 'defense_cname'
    | 'cc_policy'
    | 'geo_policy'
  >
>

// ---------------------------------------------------------------------------
// Cluster
// ---------------------------------------------------------------------------

export interface Cluster {
  id: string
  version: number
  created_at: string
  name: string
  subdomain: string
  description: string
  defense_cname: string
  failover: {
    auto: boolean
    threshold: number
    target_cluster_id: string | null
  }
  /** 单节点带宽上限（Mbps，0 = 关闭）与危险值百分比；达到危险值的节点计为不可用，按集群可用率判断切换 */
  bandwidth: {
    limit_mbps: number
    danger_percent: number
  }
  role: 'primary' | 'backup' | 'normal'
  health: {
    status: 'active' | 'degraded' | 'failed' | 'failover_in_progress' | 'failover_complete'
    online_nodes: number
    total_nodes: number
    checked_at: string | null
    /** 当前故障转移是监控自动触发的（稳定 1 小时后自动切回） */
    auto_switched: boolean
    bw_peak_mbps?: number
    bw_peak_node?: string
    bw_saturated_nodes: number
    /** 带宽打满被暂时摘除解析的节点数（恢复后自动加回） */
    dns_paused_nodes: number
    fail_streak: number
    last_reason?: string
    monitored_at?: string
  }
}

export interface ClusterCreateInput {
  name: string
  description?: string
  defense_cname?: string
  role?: Cluster['role']
  failover?: Cluster['failover']
  bandwidth?: Cluster['bandwidth']
}

export type ClusterPatchInput = Partial<
  Pick<Cluster, 'description' | 'defense_cname' | 'failover' | 'bandwidth' | 'role'>
>

// ---------------------------------------------------------------------------
// Node
// ---------------------------------------------------------------------------

export interface Node {
  id: string
  added_at: string
  version: number
  name: string
  address: string
  token_set: boolean
  token_hint: string
  ip: string | null
  cert_fingerprint: string
  /** 主控→边缘的控制面通道是否做了证书钉扎。false 时主控拒绝向该节点推送任何配置。 */
  tls_pinned: boolean
  cluster_id: string | null
  enabled: boolean
  status: {
    online: boolean
    last_heartbeat_at: string | null
    cpu_percent: number
    mem_percent: number
    connections: number
    version: string
    // 面板准备下发的这份 cdnedge 的构建标识，与 version 比出的结论都由主控算好交出来
    // （判据只有一份，面板不复制）。两个键都可能缺失：旧版主控没有这两个字段，
    // 新版在说不清时也不下发（omitempty），所以渲染要按「未知」兜底，不能当「已最新」。
    package_version?: string
    version_state?: 'match' | 'outdated' | 'unknown'
    // attached 只说明 XDP 程序挂在网卡上；armed 才说明阈值真的写进了内核并在生效
    // （内核 enabled=1 且最近一次写 xdp_config 成功）。armed 为 null 表示该节点的
    // cdnedge 版本过旧、没上报这个判据，不能当成"没生效"。
    xdp: {
      installed: boolean
      attached: boolean
      armed: boolean | null
      enabled: boolean
      mode: string
      iface?: string
      config_error?: string
      cpu_syn_limit?: number
      rx_queues?: number
    }
  }
  /** 带宽打满，已被暂时从集群解析摘除（恢复后自动加回） */
  dns_paused: boolean
  dns_paused_at: string | null
}

export interface NodeCreateInput {
  name: string
  address: string
  token: string
  ip?: string
  /** 边缘 `journalctl -u cdnedge | grep 'Certificate fingerprint'` 输出；不填则主控拒绝对该节点推送 */
  cert_fingerprint?: string
  cluster_id?: string | null
}

export interface NodeDeployInput {
  host: string
  port?: number
  user: string
  password?: string
  private_key?: string
  name: string
  cluster_id?: string | null
  edge_port?: number
  xdp_iface?: string
}

export type NodePatchInput = Partial<
  Pick<Node, 'name' | 'address' | 'ip' | 'cert_fingerprint' | 'cluster_id' | 'enabled'>
> & { token?: string | null }

// ---------------------------------------------------------------------------
// 其他
// ---------------------------------------------------------------------------

export interface Ban {
  ip: string
  layers: Array<'waf' | 'cc' | 'xdp'>
  reason: string
  host: string
  offense_count: number
  banned_at: string
  expires_at: string
  country: string
}

// GET /api/v2/cf-credentials：每个代理各存一份，api_token 永不回显，只给 _set/_hint。
export interface CfCredentials {
  configured: boolean
  enabled: boolean
  zone_id: string
  base_domain: string
  api_token_set: boolean
  api_token_hint?: string
  verified_at: string | null
  last_error: string
  updated_at?: string
}

export interface CfCredentialsInput {
  api_token?: string
  zone_id?: string
  base_domain?: string
  enabled?: boolean
}

export interface TagItem {
  tag: string
  domains: number
}

// ---------------------------------------------------------------------------
// 安全 / 统计（/api/v2/security/*，只含本代理自己的节点和域名）
// ---------------------------------------------------------------------------

export interface NodeError {
  node: string
  error: string
}

export interface TopItem {
  key: string
  requests: number
  bytes: number
}

export interface HourBucket {
  hour: number
  requests: number
  bytes: number
  blocked: number
}

export interface DomainTraffic {
  domain: string
  today_bytes: number
  today_mb: number
  unique_ips: number
  requests: number
  blocked: number
}

// 热门来源 IP 的一行。归属地三个字段可能同时为空：库没覆盖（私网、保留段）或根本
// 没装库——后者由 Traffic.geo.ready 区分，页面要给出"地理库未就位"而不是一片空白。
export interface TrafficIP {
  ip: string
  requests: number
  bytes: number
  country?: string
  region?: string
  city?: string
}

export interface GeoStatus {
  ready: boolean
  loaded?: string[]
  missing?: string[]
}

export interface Traffic {
  total_requests: number
  total_bytes: number
  total_blocked: number
  unique_ips: number
  hourly: HourBucket[]
  top_domains: TopItem[]
  top_ips: TrafficIP[]
  // 后端回显本次生效的域名筛选，空串表示全部域名。
  domain: string
  geo: GeoStatus
  domains: DomainTraffic[]
  nodes: Array<{ node: string; ip: string; total_requests: number; total_bytes: number; total_blocked: number; error?: string }>
  errors: NodeError[]
  collected_at: string
}

export interface AttackIP {
  ip: string
  rule: string
  path: string
  violations: number
  blocked: boolean
  blocked_at?: string
  blocked_until?: string
  requests_per_minute: number
  nodes: string[]
}

export interface AttackDomain {
  domain: string
  attacks: number
  blocked_ips: number
  last_attack?: string
  ips: AttackIP[]
}

export interface Attacks {
  domains: AttackDomain[]
  summary: { attacked_domains: number; cc_blocked: number; waf_banned: number; xdp_blocked: number }
  errors: NodeError[]
}

// 一张有界表的占用与退化读数。封禁表和 CC 的各张追踪表共用同一个形状：
// 打满之后走的都是「先回收闲置、再提前解除、最后才放弃」，走到哪一步必须看得见——
// 表被打满只可能发生在攻击进行中，那正是最不能静默失效的时刻。
export interface CapacityPressure {
  size: number
  limit: number
  // 为腾位提前回收的已过期/闲置条目数
  reclaimed: number
  // 为腾位提前解除的仍生效条目数（封禁表专用；追踪表永不提前解除拦截）
  early_unbanned: number
  // 一个空位都腾不出来、被迫放弃的次数（新封禁被丢弃 / 新 IP 不做跨请求统计）
  dropped: number
}

export interface CCPressure {
  ips: CapacityPressure
  domains: CapacityPressure
  fingerprints: CapacityPressure
  cache_buster: CapacityPressure
  cache_paths: CapacityPressure
}

export interface CCStats {
  total_tracked: number
  active_ips: number
  violating_ips: number
  blocked_ips: number
  // 过了人机验证但浏览器环境证据采不到（隐私模式/老内核/旧挑战页缓存）的 IP：
  // 走严格配额、不享受宽松额度，也不被单次超限秒杀。
  downgraded_ips: number
  // 自适应模式下盾牌平时是收起来的：这两个数非 0 才说明真有域名越过了 QPS 判定线。
  // total 取各节点最大值（同一个域名多节点开盾只算一次），逐节点读数看 nodes[].stats。
  domains_in_challenge?: number
  domains_in_strict?: number
  capacity?: CCPressure
}

export interface PerNode<T> {
  node: string
  ip: string
  error?: string
  stats?: T
  loaded?: boolean
}


export interface CCIP {
  ip: string
  requests_per_second: number
  requests_per_minute: number
  violations: number
  blocked: boolean
  last_request: string
  blocked_at: string
  blocked_until: string
  block_rule: string
  block_host: string
  block_path: string
  country?: string
  location?: string
  nodes: string[]
}

export interface CCConfig {
  enabled: boolean
  requests_per_second: number
  requests_per_minute: number
  burst_size: number
  block_duration: number
  whitelist_ips: string[]
  path_whitelist: string[]
}

export interface XDPConfig {
  syn_limit: number
  pps_limit: number
  udp_limit: number
  conn_limit: number
  enabled: number
  icmp_limit: number
  udp_dns_limit: number
  tcp_rst_limit: number
  fragment_drop: number
  invalid_flags_drop: number
  ack_limit: number
  fin_limit: number
  port_guard: number
  bogon_drop: number
  psh_ack_guard: number
  cpu_syn_limit: number
  orphan_tcp_drop: number
  service_orphan_drop: number
}

export interface BanConfig {
  ladder: string
  offender_ttl: string
}

export interface XDPBlock {
  ip: string
  remaining_time: number
  offense_count: number
  ban_duration: number
  nodes: string[]
}

export interface WAFBan {
  ip: string
  expires_at: string
  remaining: number
  nodes: string[]
}

// ---------------------------------------------------------------------------
// WAF 托管规则（策略按代理一份，规则包由平台管理员维护）
// ---------------------------------------------------------------------------

export type WAFMode = 'block' | 'observe'
export type WAFLevel = 'off' | 'low' | 'medium' | 'high' | 'attack'

// 与 internal/waf.Policy 同名字段。rules 是"显式覆盖"而不是全量开关：
// 没出现在 map 里的规则跟着级别走，见 utils/waf.ts 的 effectiveRuleIds。
export interface WAFPolicy {
  enabled: boolean
  mode: WAFMode
  level: WAFLevel
  sets: string[]
  rules: Record<string, boolean>
  // 空串 = 跟随节点的活动包；非空 = 整代理锁定该版本（此时灰度比例不生效）。
  rules_version: string
  gray_percent: number
}

// 规则包目录：主控只导出元数据，正则本体不下发给代理（patterns 字段在这里就没有）。
export interface WAFRuleMeta {
  id: string
  name: string
  description: string
  tier: number
  scopes: string[]
}

export interface WAFRuleSetMeta {
  id: string
  name: string
  description: string
  recommended: boolean
  rules: string[]
}

export interface WAFCatalog {
  version: string
  updated_at?: string
  sets: WAFRuleSetMeta[]
  rules: WAFRuleMeta[]
}

// GET /security/waf/config
export interface WAFConfigResponse {
  config: WAFPolicy
  saved: boolean
  catalog: WAFCatalog
  // rules_version 的合法取值（首项是空串，界面显示为「跟随活动包」）
  versions: string[]
  // 现在应该下发的这一版；空串在 versions 里代表它。
  active_version: string
  builtin_version: string
}

// PUT /security/waf/config：effective 是主控按同一份策略算出的生效规则 id。
export interface WAFConfigSaveResponse {
  config: WAFPolicy
  push: PushResult
  effective: string[]
}

export interface WAFHit {
  rule: string
  name?: string
  observe: number
  blocked: number
}

// GET /security/waf/stats 的逐节点读数。matches_policy 为 false 表示这台节点还在跑
// 别的策略（下发时不在线，或它的 cdnedge 版本太旧没吃到）；null/缺失表示无从判断。
export interface WAFNodeReading {
  node: string
  ip: string
  enabled: boolean
  mode: WAFMode | ''
  level: WAFLevel | ''
  gray_percent: number
  active_version: string
  previous_version: string
  rules_version?: string
  pin_missing: boolean
  effective_rules: number
  observe: number
  blocked: number
  matches_policy?: boolean | null
  reported_at?: string
  error?: string
}

export interface WAFStatsResponse {
  total: { observe: number; blocked: number; rules: number }
  hits: WAFHit[]
  nodes: WAFNodeReading[]
  errors: NodeError[]
  policy: WAFPolicy
}

// 下发结果：节点名 → "ok" 或错误信息
export type PushResult = Record<string, string>

// ---------------------------------------------------------------------------
// 区域封禁（/security/geo/*、/admin/geo*，与 internal/geo 同名字段）
// ---------------------------------------------------------------------------

export type GeoMode = 'observe' | 'block'
export type GeoAction = 'deny' | 'allow'

// 一条区域规则。域名级（七层）与整节点级（四层丢包）用的是同一个形状，
// 差别只有作用范围，所以界面也共用同一份编辑组件。
export interface GeoPolicy {
  enabled: boolean
  mode: GeoMode
  action: GeoAction
  countries: string[]
  // 永远放行的 IP/CIDR。后端存的是归一后的写法（裸 IP 补 /32，网段按掩码对齐），
  // 所以回显和填写可能不同串，判等要以后端返回的为准。
  exceptions: string[]
}

// 保存域名区域规则时后端回的逐节点下发结果，只在本次写入带了 geo_policy 时出现。
// 两样都得到位规则才真的生效：per_node 是前缀表（国家有哪些网段），
// domain_config 是域名配置（这个域名拦不拦，边缘判定读的是它）。
export interface GeoPushResult {
  fingerprint?: string
  total?: number
  countries?: string[]
  per_node?: Record<string, { table?: string }>
  domain_config?: Record<string, string>
  cleared?: string[]
  // 一个可下发的节点都没有（未绑定集群，或集群里没有启用的节点）
  skipped?: string
  failed?: string[]
  error?: string
}

// 管理员那一份：能力总闸 + 租可选范围 + 整节点策略。
export interface GeoScope {
  enabled: boolean
  // 空数组 = 不限（库里有的国家全都能选）
  selectable: string[]
  node: GeoPolicy
}

export interface GeoCounters {
  observe: number
  blocked: number
  pass: number
  unknown: number
  exception: number
  off: number
  no_table: number
}

export interface GeoCountryCount {
  country: string
  observe: number
  blocked: number
  pass: number
}

// GET /security/geo/options：租户侧进页面先问的两个问题——能不能用、我能选哪些。
export interface GeoOptionsResponse {
  enabled: boolean
  saved: boolean
  selectable: string[]
  available: string[]
  unavailable: string[]
  catalog: string[]
  catalog_note: string
  db_ready: boolean
  used: string[]
  note: string
}

// GET /security/geo/stats：本代理各节点的判决读数。
export interface GeoTenantNodeReading {
  node: string
  ip: string
  loaded: boolean
  fingerprint?: string
  total: number
  countries?: string[]
  scope_enabled: boolean
  l4_armed: boolean
  l4_want: boolean
  l4_dropped: number
  table_error?: string
  l4_error?: string
  reported_at?: string
  matches_plan_fingerprint?: boolean | null
  error?: string
}

export interface GeoStatsResponse {
  counters: GeoCounters
  countries: GeoCountryCount[]
  nodes: GeoTenantNodeReading[]
  errors: NodeError[]
  expected_fingerprint: string
  expected_total: number
  expected_countries: string[]
  notes: string[]
  report_interval_secs: number
  scope_enabled: boolean
  db_ready: boolean
}

// 管理员侧的「这张表现在长什么样」：指纹与前缀条数是节点对照的基准。
export interface GeoPlanView {
  countries: string[]
  l4_enabled: boolean
  notes: string[]
  total: number
  fingerprint: string
  gzip_bytes?: number
}

export interface GeoDBReading {
  ready: boolean
  ipv4: boolean
  ipv6: boolean
  loaded: string[]
  missing: string[]
  countries?: string[]
  catalog_error?: string
}

export interface GeoAdminSummary {
  nodes: number
  reported: number
  silent: number
  counters?: GeoCounters
  countries?: GeoCountryCount[]
  error?: string
}

// GET /admin/geo
export interface GeoAdminResponse {
  scope: GeoScope
  saved: boolean
  plan: GeoPlanView
  geo_db: GeoDBReading
  readings: GeoAdminSummary
}

// PUT /admin/geo、POST /admin/geo/push：push 是逐节点的下发结果。
export interface GeoAdminSaveResponse {
  scope: GeoScope
  plan: GeoPlanView
  push: GeoPushSummary
}

export interface GeoAdminPushResponse {
  plan: GeoPlanView
  push: GeoPushSummary
}

// 一台节点两步下发：先是前缀表本体（按指纹可能跳过），再是节点级配置。
// 每步的取值都带人话说明，页面原样显示——"点了保存"不等于"全网都在拦"。
export interface GeoPushNodeResult {
  table?: string
  table_fingerprint?: string
  // 换表成功但落盘失败：这台节点一重启就回到旧表。
  table_not_persisted?: boolean
  table_was?: string
  config?: string
}

export interface GeoPushSummary {
  nodes: number
  ok: number
  per_node: Record<string, GeoPushNodeResult>
  total: number
  countries: string[]
  fingerprint?: string
  failed?: string[]
  notes?: string[]
  error?: string
}

// GET /admin/geo/nodes：l4_matches 只在四层确实在丢包时给结论，
// 观察模式/allow/总闸关这些"本来就不该装四层"的组合是 null。
export interface GeoAdminNodeReading {
  node: string
  ip: string
  fingerprint?: string
  total: number
  countries?: string[]
  loaded: boolean
  scope_enabled: boolean
  node_mode?: string
  l4_armed: boolean
  l4_want: boolean
  l4_entries: number
  l4_dropped: number
  l4_error?: string
  l4_fingerprint?: string
  l4_applied?: string
  l4_matches?: boolean | null
  observe: number
  blocked: number
  pass: number
  unknown: number
  exception: number
  table_error?: string
  reported_at?: string
  matches_plan_fingerprint?: boolean | null
  error?: string
}

export interface GeoAdminNodesResponse {
  expected_fingerprint: string
  expected_total: number
  items: GeoAdminNodeReading[]
  total: { observe: number; blocked: number; unknown: number; exception: number }
  notes: string[]
}

export interface Certificate {
  id: string
  domain_id: string
  source: 'upload' | 'acme'
  issuer: string
  subject: string
  dns_names: string[]
  not_before: string
  not_after: string
  in_use: boolean
  created_at: string
}

// ---------------------------------------------------------------------------
// 平台管理员：代理（租户）/ 套餐 / 代理账号
// ---------------------------------------------------------------------------

export interface AdminPlan {
  id: number
  code: string
  name: string
  max_nodes: number
  max_domains: number
  max_clusters: number
  tenants: number
  created_at: string
}

export interface AdminTenant {
  id: string
  name: string
  status: 'active' | 'suspended'
  expired: boolean
  expires_at: string | null
  plan: { id: number; code: string; name: string; max_nodes: number; max_domains: number; max_clusters: number }
  usage: { nodes: number; domains: number; clusters: number }
  owner_email: string
  created_at: string
}

export interface AdminTenantUser {
  id: string
  tenant_id: string
  email: string
  role: 'owner' | 'member' | 'readonly'
  status: 'active' | 'disabled'
  last_login_at: string | null
  created_at: string
}
