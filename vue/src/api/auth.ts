import { adminApi, tenantApi } from './client'
import type { AdminMe, Me } from './types'

export async function login(email: string, password: string): Promise<Me> {
  const { data } = await tenantApi.post<Me>('/auth/login', { email, password })
  return data
}

export async function logout(): Promise<void> {
  await tenantApi.post('/auth/logout')
}

export async function fetchMe(): Promise<Me> {
  const { data } = await tenantApi.get<Me>('/auth/me')
  return data
}

export async function changePassword(oldPassword: string, newPassword: string): Promise<void> {
  await tenantApi.patch('/auth/me', { password: { old: oldPassword, new: newPassword } })
}

export async function adminLogin(username: string, password: string, totp?: string): Promise<AdminMe> {
  const { data } = await adminApi.post<AdminMe>('/auth/login', { username, password, totp })
  return data
}

export async function adminLogout(): Promise<void> {
  await adminApi.post('/auth/logout')
}

export async function fetchAdminMe(): Promise<AdminMe> {
  const { data } = await adminApi.get<AdminMe>('/auth/me')
  return data
}

// 平台管理员自助改密码。响应里带着重建会话后下发的新 CSRF token，调用方必须换上它，
// 否则后续管理端写操作会全部撞上 csrf_invalid。
export async function adminChangePassword(oldPassword: string, newPassword: string): Promise<AdminMe> {
  const { data } = await adminApi.patch<AdminMe>('/auth/me', {
    password: { old: oldPassword, new: newPassword },
  })
  return data
}
