import type { WAFCatalog, WAFLevel, WAFPolicy, WAFRuleMeta } from '@/api/types'

// 面板侧的"这条规则到底跑不跑"判定。
//
// 必须与 internal/waf/waf.go 的 EffectiveRules、ruleset.go 的 tierByLevel 逐条一致：
// 界面显示「这 14 条都开着」而边缘只按级别跑 5 条，是托管规则最容易出的假账，
// 灰度验证时没人能解释为什么没命中。保存响应里后端会回 authoritative 的 effective
// 清单，页面用它校一遍（对不上就报错，而不是继续显示面板自己算的那份）。

// 级别 → 执行到第几档。档位常量是对外协议（只能加不能改），未知级别按「中」处理，
// 与后端一样不按 0 把防护关掉。
export const levelTier: Record<WAFLevel, number> = {
  off: 0,
  low: 1,
  medium: 2,
  high: 3,
  attack: 4,
}

export function tierOf(level: WAFLevel): number {
  return levelTier[level] ?? levelTier.medium
}

export const wafLevels: { value: WAFLevel; label: string; hint: string }[] = [
  { value: 'off', label: '关闭', hint: '不执行任何托管规则；IP 封禁、UA 与上传校验不受影响' },
  { value: 'low', label: '低', hint: '只跑第 1 档：最常见的注入与探测，误报面最小' },
  { value: 'medium', label: '中', hint: '跑到第 2 档：默认档，覆盖 SQL/XSS/路径穿越等主体' },
  { value: 'high', label: '高', hint: '跑到第 3 档：开始包含需要业务配合排除的规则' },
  { value: 'attack', label: '攻击中', hint: '全部 4 档，含误报面最大的 CRLF/LDAP/反序列化' },
]

export const wafModes: { value: WAFPolicy['mode']; label: string; hint: string }[] = [
  { value: 'block', label: '拦截', hint: '命中即拒绝请求并记账' },
  { value: 'observe', label: '观察', hint: '命中只记账不拦：先用它验证新规则会不会误报' },
]

// 勾选规则集只会把规则加进来，不会把级别内的规则关掉（与 EffectiveRules 同语义）。
export function boostedRuleIds(catalog: WAFCatalog | null, sets: string[]): Set<string> {
  const on = new Set(sets ?? [])
  const boosted = new Set<string>()
  for (const s of catalog?.sets ?? []) {
    if (!on.has(s.id)) continue
    for (const id of s.rules ?? []) boosted.add(id)
  }
  return boosted
}

// 级别 + 规则集对这条规则的默认判定（不含单条显式覆盖）。
export function ruleDefault(rule: WAFRuleMeta, level: WAFLevel, boosted: Set<string>): boolean {
  return rule.tier <= tierOf(level) || boosted.has(rule.id)
}

export function effectiveRuleIds(catalog: WAFCatalog | null, pol: WAFPolicy): string[] {
  if (!catalog || !pol.enabled) return []
  const boosted = boostedRuleIds(catalog, pol.sets)
  const out: string[] = []
  for (const r of catalog.rules ?? []) {
    let on = ruleDefault(r, pol.level, boosted)
    const want = pol.rules?.[r.id]
    if (want !== undefined) on = want
    if (on) out.push(r.id)
  }
  return out
}

// 每个级别会跑到多少条（不含规则集与单条覆盖），用来在级别选择旁边给出量感。
export function levelRuleCounts(catalog: WAFCatalog | null): Record<WAFLevel, number> {
  const rules = catalog?.rules ?? []
  const out = { off: 0, low: 0, medium: 0, high: 0, attack: 0 } as Record<WAFLevel, number>
  for (const lv of Object.keys(out) as WAFLevel[]) {
    out[lv] = rules.filter((r) => r.tier <= tierOf(lv)).length
  }
  return out
}

export function versionLabel(v: string, activeVersion: string): string {
  if (!v) return activeVersion ? `跟随活动包（${activeVersion}）` : '跟随活动包'
  return v
}
