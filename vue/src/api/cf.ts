import { tenantApi } from './client'
import type { CfCredentials, CfCredentialsInput } from './types'

export async function getCfCredentials(): Promise<CfCredentials> {
  const { data } = await tenantApi.get<CfCredentials>('/cf-credentials')
  return data
}

export async function saveCfCredentials(input: CfCredentialsInput): Promise<CfCredentials> {
  const { data } = await tenantApi.put<CfCredentials>('/cf-credentials', input)
  return data
}

export async function deleteCfCredentials(): Promise<void> {
  await tenantApi.delete('/cf-credentials')
}

export async function testCfCredentials(): Promise<{ ok: boolean; error?: string }> {
  const { data } = await tenantApi.post<{ ok: boolean; error?: string }>('/cf-credentials/test')
  return data
}
