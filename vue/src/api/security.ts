import { tenantApi } from './client'
import type {
  Attacks,
  BanConfig,
  CacheRule,
  CapacityPressure,
  CCConfig,
  CCIP,
  CCStats,
  GeoOptionsResponse,
  GeoStatsResponse,
  NodeError,
  PerNode,
  PushResult,
  Traffic,
  WAFConfigResponse,
  WAFConfigSaveResponse,
  WAFPolicy,
  WAFStatsResponse,
  WAFBan,
  XDPBlock,
  XDPConfig,
} from './types'

// /api/v2/security/*：服务端只汇总本代理自己的节点和域名。

export interface ListResult<T> {
  items: T[]
  total: number
  errors: NodeError[]
}

export type XDPStats = Record<string, number>

const s = (p: string) => `/security/${p}`

// domain 非空时只筛选「热门来源 IP」这一块；小时曲线与总量仍是本代理全量，
// 口径由后端 security.go 保证，前端不要把上面的数字当成该域名的。
export async function getTraffic(domain = ''): Promise<Traffic> {
  return (await tenantApi.get<Traffic>(s('traffic'), { params: domain ? { domain } : {} })).data
}

export async function getAttacks(): Promise<Attacks> {
  return (await tenantApi.get<Attacks>(s('attacks'))).data
}

export async function getCacheStats(): Promise<{
  bytes: number
  files: number
  nodes: Array<{ node: string; ip: string; bytes?: number; files?: number; error?: string }>
}> {
  return (await tenantApi.get(s('cache/stats'))).data
}

export interface CacheConfig {
  rules: CacheRule[]
}

export async function getCacheConfig(): Promise<{ config: CacheConfig; saved: boolean; platform_default: CacheConfig }> {
  return (await tenantApi.get(s('cache/config'))).data
}

// 保存后服务端会把本代理全部域名重新下发到节点，push 是各节点的结果。
export async function putCacheConfig(cfg: CacheConfig): Promise<{ config: CacheConfig; push: PushResult }> {
  return (await tenantApi.put(s('cache/config'), cfg)).data
}

export async function getCCStats(): Promise<{ total: CCStats; nodes: PerNode<CCStats>[] }> {
  return (await tenantApi.get(s('cc/stats'))).data
}

export async function getCCIPs(blocked = false): Promise<ListResult<CCIP>> {
  return (await tenantApi.get(s('cc/ips'), { params: blocked ? { blocked: 'true' } : {} })).data
}

export async function getCCConfig(): Promise<{ config: CCConfig; saved: boolean }> {
  return (await tenantApi.get(s('cc/config'))).data
}

export async function putCCConfig(cfg: CCConfig): Promise<{ config: CCConfig; push: PushResult }> {
  return (await tenantApi.put(s('cc/config'), cfg)).data
}

export async function getXDPStats(): Promise<{ total: XDPStats; nodes: PerNode<XDPStats>[] }> {
  return (await tenantApi.get(s('xdp/stats'))).data
}

export async function getXDPBlocklist(): Promise<ListResult<XDPBlock>> {
  return (await tenantApi.get(s('xdp/blocklist'))).data
}

export async function getXDPConfig(): Promise<{ config: XDPConfig; saved: boolean }> {
  return (await tenantApi.get(s('xdp/config'))).data
}

export async function putXDPConfig(cfg: XDPConfig): Promise<{ config: XDPConfig; push: PushResult }> {
  return (await tenantApi.put(s('xdp/config'), cfg)).data
}

export async function getBanConfig(): Promise<{ config: BanConfig; saved: boolean; preview: string[] | null }> {
  return (await tenantApi.get(s('xdp/ban-config'))).data
}

export async function putBanConfig(cfg: BanConfig): Promise<{ config: BanConfig; push: PushResult }> {
  return (await tenantApi.put(s('xdp/ban-config'), cfg)).data
}

// capacity 是全网封禁表的额度读数（各节点额度求和）：dropped/early_unbanned 不为 0
// 就说明封禁额度已被攻击用尽，防护正在降级运行。
export async function getWAFBanned(): Promise<ListResult<WAFBan> & { capacity?: CapacityPressure }> {
  return (await tenantApi.get(s('waf/banned'))).data
}

// 托管规则策略（GET/PUT security/waf/config）。规则包本体不在这里：那是平台级的，
// 代理只能选"跟随活动包"还是固定到某个已下发的版本。
export async function getWAFConfig(): Promise<WAFConfigResponse> {
  return (await tenantApi.get(s('waf/config'))).data
}

// 全量提交（后端是补丁语义，少传字段只会保持原值，不会当成关闭），
// 返回里的 effective 是主控算出的生效规则 id。
export async function putWAFConfig(cfg: WAFPolicy): Promise<WAFConfigSaveResponse> {
  return (await tenantApi.put(s('waf/config'), cfg)).data
}

// 数据来自节点定期上报，主控不回连节点：上报周期内改完配置这里不会立刻变。
export async function getWAFStats(): Promise<WAFStatsResponse> {
  return (await tenantApi.get(s('waf/stats'))).data
}

// 区域封禁：这一层只读。域名规则本身跟着 PATCH /domains/:id 走（geo_policy 字段），
// 平台总闸、可选国家、整节点的四层丢包都由管理员那份范围决定。
// options 回答"我能选哪些"，stats 回答"我选的到底落到节点上没有"。
export async function getGeoOptions(): Promise<GeoOptionsResponse> {
  return (await tenantApi.get<GeoOptionsResponse>(s('geo/options'))).data
}

// 读数来自节点每 10 秒一次的上报，主控不回连节点：刚改完规则这里不会立刻变。
export async function getGeoStats(): Promise<GeoStatsResponse> {
  return (await tenantApi.get<GeoStatsResponse>(s('geo/stats'))).data
}

export async function blockIP(
  ip: string,
  layer: 'waf' | 'xdp' | 'all',
  minutes = 60,
): Promise<{ push: PushResult }> {
  return (await tenantApi.post(s('block'), { ip, layer, minutes })).data
}
export async function unblockIP(
  ip: string,
  layer: 'all' | 'waf' | 'cc' | 'xdp' = 'all',
): Promise<{ push: PushResult }> {
  return (await tenantApi.post(s('unblock'), { ip, layer })).data
}

export async function pushDefense(): Promise<{ push: Record<string, PushResult>; nodes: number }> {
  return (await tenantApi.post(s('push'))).data
}
