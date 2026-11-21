import { adminApi } from './client'
import type { WAFRuleSetMeta } from './types'

// WAF 托管规则包（平台级）。规则包本体是全量规则 + 正则，只有平台管理员能维护，
// 代理侧只能看到不含正则的目录（见 api/types.ts 的 WAFCatalog）。
//
// 库里的 payload 是密文：GET 单包时后端解密后把明文规则还给管理员，
// 是因为维护规则的人要的就是"能改回来再传上去"的那份文本。

// 列表/详情里的行（不含 payload 本体）。size_bytes 是密文长度，不是明文规则大小。
export interface WafPackageRow {
  id: string
  version: string
  notes: string
  rule_count: number
  set_count: number
  enabled: boolean
  size_bytes: number
  created_at: string
  updated_at: string
  activated_at: string | null
}

// 下发结果里每台节点一行。status 除 ok/failed/rejected 外还可能是
// applied-not-persisted（换表成功、落盘失败：这台节点一重启就回到上一份包）。
export interface WafPushNodeResult {
  status: string
  error?: string
  persist_error?: string
  active_version?: string
  previous_version?: string
}

export interface WafPushResult {
  nodes: number
  ok: number
  per_node: Record<string, WafPushNodeResult>
  active_version: string
  previous_version?: string
}

export interface WafPackageList {
  items: WafPackageRow[]
  builtin: { version: string; rule_count: number; set_count: number }
  active: {
    version: string
    from_db: boolean
    rule_count: number
    previous_version?: string
    error?: string
  }
}

// 规则包明文：比代理侧看到的目录多了 patterns。只有平台管理员的会话能取到。
export interface WafRulePlain {
  id: string
  name: string
  description: string
  tier: number
  scopes: string[]
  patterns: string[]
}

export interface WafPackagePlain {
  version: string
  updated_at?: string
  sets: WAFRuleSetMeta[]
  rules: WafRulePlain[]
}

// 详情里的 rules 是规则包明文，改完原样 PUT 回去就是"编辑这一份"。
export interface WafPackageDetail {
  package: WafPackageRow
  rules: WafPackagePlain
}

export interface WafNodeReading {
  node: string
  ip: string
  active_version: string
  previous_version: string
  builtin_version: string
  reported_at?: string
  // false = 这台节点跑的不是"当前启用的那一份"（不在线、拒收、或还没上报过）。
  matches_active?: boolean | null
  error?: string
}

export interface WafNodesResponse {
  expected_version: string
  items: WafNodeReading[]
  total: number
}

export interface WafPackageCreateInput {
  notes?: string
  package: unknown
  activate?: boolean
}

export interface WafPackagePatchInput {
  notes?: string
  package?: unknown
}

export async function listWafPackages(): Promise<WafPackageList> {
  return (await adminApi.get<WafPackageList>('/waf/packages')).data
}

export async function getWafPackage(id: string): Promise<WafPackageDetail> {
  return (await adminApi.get<WafPackageDetail>(`/waf/packages/${id}`)).data
}

export async function createWafPackage(
  input: WafPackageCreateInput,
): Promise<{ id: string; version: string; rule_count: number; set_count: number; enabled?: boolean; push?: WafPushResult }> {
  return (await adminApi.post('/waf/packages', input)).data
}

export async function updateWafPackage(
  id: string,
  input: WafPackagePatchInput,
): Promise<{ id: string; version: string; rule_count?: number; set_count?: number; repushed?: boolean; push?: WafPushResult }> {
  return (await adminApi.patch(`/waf/packages/${id}`, input)).data
}

export async function deleteWafPackage(id: string): Promise<void> {
  await adminApi.delete(`/waf/packages/${id}`)
}

// 启用 = 换活动包并立即下发全网，返回值里的 push 是各节点的结果。
export async function activateWafPackage(id: string): Promise<{ id: string; push: WafPushResult }> {
  return (await adminApi.post(`/waf/packages/${id}/activate`, {})).data
}

// 不改启用行，只把当前该生效的那份重推一遍（节点当时不在线、后来装好了用它）。
export async function pushWafPackages(): Promise<WafPushResult> {
  return (await adminApi.post<WafPushResult>('/waf/packages/push', {})).data
}

export async function listWafNodePackages(): Promise<WafNodesResponse> {
  return (await adminApi.get<WafNodesResponse>('/waf/nodes')).data
}
