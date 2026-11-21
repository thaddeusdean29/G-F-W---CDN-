import { tenantApi } from './client'
import type { Dashboard } from './types'

export async function getDashboard(): Promise<Dashboard> {
  const { data } = await tenantApi.get<Dashboard>('/dashboard')
  return data
}
