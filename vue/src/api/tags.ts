import { tenantApi } from './client'
import type { TagItem } from './types'

export async function listTags(): Promise<TagItem[]> {
  const { data } = await tenantApi.get<{ items: TagItem[] }>('/tags')
  return data.items ?? []
}

export async function createTag(tag: string): Promise<TagItem> {
  const { data } = await tenantApi.post<TagItem>('/tags', { tag })
  return data
}

export async function deleteTag(tag: string): Promise<{ tag: string; domains_updated: number }> {
  const { data } = await tenantApi.delete<{ tag: string; domains_updated: number }>(
    `/tags/${encodeURIComponent(tag)}`,
  )
  return data
}
