import { adminApi } from './client'

// 首页「常见问题」区块，平台管理员编辑。长度限制与 internal/apiv2/docs.go 一致。

export interface FAQItem {
  question: string
  // 纯文本：空一行分段；「- 」开头的行显示为列表；「1. 」开头的行显示为编号列表
  answer: string
}

export interface FAQGroup {
  title: string
  items: FAQItem[]
}

export interface FAQConfig {
  intro: string
  groups: FAQGroup[]
}

export async function fetchFAQ(): Promise<{ config: FAQConfig; saved: boolean }> {
  const { data } = await adminApi.get('/faq')
  return data
}

export async function saveFAQ(cfg: FAQConfig): Promise<{ config: FAQConfig; saved: boolean }> {
  const { data } = await adminApi.put('/faq', cfg)
  return data
}
