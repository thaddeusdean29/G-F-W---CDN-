import { adminApi } from './client'
import type { AdminPlan, AdminTenant, AdminTenantUser, Paginated } from './types'

// 平台管理员接口：开通/管理代理（租户）。每个代理是一套独立后台，
// 域名/节点/集群都按租户隔离，这里只管「开户」和套餐。

export interface TenantCreateInput {
  name: string
  plan_id: number
  expires_at: string | null
  owner: { email: string; password: string }
}

export interface TenantPatchInput {
  name?: string
  plan_id?: number
  status?: 'active' | 'suspended'
  expires_at?: string | null
}

export interface PlanInput {
  code?: string
  name: string
  max_nodes: number
  max_domains: number
  max_clusters: number
}

export async function listTenants(params: { q?: string; page?: number; page_size?: number } = {}): Promise<Paginated<AdminTenant>> {
  const { data } = await adminApi.get<Paginated<AdminTenant>>('/tenants', { params })
  return data
}

export async function createTenant(input: TenantCreateInput): Promise<AdminTenant> {
  const { data } = await adminApi.post<AdminTenant>('/tenants', input)
  return data
}

export async function patchTenant(id: string, patch: TenantPatchInput): Promise<AdminTenant> {
  const { data } = await adminApi.patch<AdminTenant>(`/tenants/${id}`, patch)
  return data
}

export async function deleteTenant(id: string): Promise<void> {
  await adminApi.delete(`/tenants/${id}`)
}

export async function listTenantUsers(tenantId: string): Promise<Paginated<AdminTenantUser>> {
  const { data } = await adminApi.get<Paginated<AdminTenantUser>>(`/tenants/${tenantId}/users`)
  return data
}

export async function createTenantUser(
  tenantId: string,
  input: { email: string; password: string; role: AdminTenantUser['role'] },
): Promise<AdminTenantUser> {
  const { data } = await adminApi.post<AdminTenantUser>(`/tenants/${tenantId}/users`, input)
  return data
}

export async function patchTenantUser(
  id: string,
  patch: { password?: string; status?: AdminTenantUser['status']; role?: AdminTenantUser['role'] },
): Promise<AdminTenantUser> {
  const { data } = await adminApi.patch<AdminTenantUser>(`/users/${id}`, patch)
  return data
}

export async function listPlans(): Promise<Paginated<AdminPlan>> {
  const { data } = await adminApi.get<Paginated<AdminPlan>>('/plans')
  return data
}

export async function createPlan(input: PlanInput): Promise<AdminPlan> {
  const { data } = await adminApi.post<AdminPlan>('/plans', input)
  return data
}

export async function patchPlan(id: number, patch: Omit<PlanInput, 'code'>): Promise<AdminPlan> {
  const { data } = await adminApi.patch<AdminPlan>(`/plans/${id}`, patch)
  return data
}

export async function deletePlan(id: number): Promise<void> {
  await adminApi.delete(`/plans/${id}`)
}
