import { adminApi } from './client'
import type { LoginFeature } from './branding'

// 公开首页（根路径 /）的内容，平台管理员编辑。字段长度限制与 internal/apiv2/homepage.go 一致。

export interface HomepagePlan {
  name: string
  price: string
  period: string
  desc: string
  // 关联的真实套餐编码；关联后首页自动显示该套餐的节点 / 域名 / 集群上限
  plan_code: string
  items: string[]
  highlight: boolean
}

export type ContactType = 'wechat' | 'qq' | 'telegram' | 'email' | 'phone' | 'other'

export interface HomepageContact {
  type: ContactType
  label: string
  value: string
}

export interface HomepageConfig {
  enabled: boolean
  hero_title: string
  hero_subtitle: string
  features: LoginFeature[]
  plans_note: string
  plans: HomepagePlan[]
  contact_note: string
  contacts: HomepageContact[]
  icp: string
  footer_note: string
}

export interface PlanRow {
  code: string
  name: string
  max_nodes: number
  max_domains: number
  max_clusters: number
}

export interface HomepageResponse {
  config: HomepageConfig
  saved: boolean
  plans: PlanRow[]
}

export async function fetchHomepage(): Promise<HomepageResponse> {
  const { data } = await adminApi.get<HomepageResponse>('/homepage')
  return data
}

export async function saveHomepage(cfg: HomepageConfig): Promise<HomepageResponse> {
  const { data } = await adminApi.put<HomepageResponse>('/homepage', cfg)
  return data
}
