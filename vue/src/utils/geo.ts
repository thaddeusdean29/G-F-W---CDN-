import type { GeoAction, GeoCounters, GeoMode, GeoPolicy } from '@/api/types'

// 区域封禁在面板侧的显示与校验 helpers。
//
// 判定语义的唯一来源是 internal/geo/policy.go（Decide / ValidatePolicy / ValidateScope），
// 这里只做显示和"提交前当场拒掉"，不重算判决：一处翻译就会重演
// 「面板显示的和节点实际执行的不一致」。

export const geoModes: { value: GeoMode; label: string; hint: string }[] = [
  { value: 'observe', label: '观察', hint: '命中只记账、照常放行：新规则先走这一档，看清读数再开拦' },
  { value: 'block', label: '拦截', hint: '命中即拒绝：七层返回 403，四层直接丢包' },
]

export const geoActions: { value: GeoAction; label: string; hint: string }[] = [
  { value: 'deny', label: '封禁所列国家', hint: '这些国家的来源被拒，其余照常放行' },
  { value: 'allow', label: '只放行所列国家', hint: '清单外的来源被拒。只有七层域名规则支持：四层分不清「归属未知」和「不在清单」' },
]

// 后端 ValidatePolicy 的三条硬要求，在页面上同步拦一遍：
// 服务端拒绝会给出一片红字，而这里能在点保存之前就说出缺哪一项。
export function geoPolicyIssues(p: GeoPolicy, opts: { denyOnly?: boolean } = {}): string[] {
  const out: string[] = []
  // 未启用的规则可以先存着空清单（启用它才必须选国家）。
  if (p.enabled && !p.countries.length) out.push('启用区域规则至少要选一个国家')
  if (p.action === 'allow' && opts.denyOnly) {
    out.push('整节点（四层丢包）只支持封禁所列国家：要按国家只放行，请配在域名的七层规则上')
  }
  if (p.enabled && opts.denyOnly && !p.exceptions.length) {
    out.push('整节点策略必须至少填一条例外 IP/CIDR（主控与节点互联地址），否则封禁国家内的管理流量会一起被丢掉，节点会从集群里消失且不报错')
  }
  return [...new Set(out)]
}

// describe 给列表里的窄列用：一行说清这条规则在做什么。
// 未启用单独成句，免得 "封禁 0 个国家" 被读成"配了但没生效"。
export function describeGeoPolicy(p: GeoPolicy | undefined): string {
  if (!p?.enabled) return '未启用'
  const verb = p.action === 'allow' ? '只放行' : '封禁'
  const mode = p.mode === 'block' ? '拦截' : '观察'
  const n = p.countries.length
  return `${verb} ${n} 个国家（${mode}）`
}

// counterRows 是读数区的固定顺序。每个 Why 都必须单独出现：
// 少了任何一格，那部分流量就在页面上彻底消失，而"归属未知"正是区域规则唯一的放行口子。
export const counterRows: { key: keyof GeoCounters; label: string; hint: string }[] = [
  { key: 'observe', label: '命中未拦', hint: '命中名单，但因为是观察模式放行了' },
  { key: 'blocked', label: '已拦下', hint: '命中名单且真的拦下（七层 403 / 四层丢包）' },
  { key: 'pass', label: '放行', hint: '按名单判定应当放行' },
  { key: 'unknown', label: '归属未知', hint: '表里查不到这个地址的归属（私网、保留段、库未覆盖），按放行处理' },
  { key: 'exception', label: '命中例外', hint: '落在例外清单里，永远放行' },
  { key: 'off', label: '规则未执行', hint: '规则没启用，或平台总闸关着' },
  { key: 'no_table', label: '没有表', hint: '这台节点一张前缀表都没装上，全部按未知处理' },
]

// 例外清单在页面上按行编辑，存的是字符串数组。粘贴一串（换行或逗号分隔）是常态，
// 归成交互前先拆开，免得整段变成一个非法条目然后被后端拒掉。
export function splitNets(input: string): string[] {
  const seen = new Set<string>()
  for (const raw of input.split(/[\s,;]+/)) {
    const s = raw.trim()
    if (s) seen.add(s)
  }
  return [...seen]
}

export function formatBytes(n: number | undefined): string {
  if (!n) return '0'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(2)} MB`
}
