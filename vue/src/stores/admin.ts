import { defineStore } from 'pinia'
import * as authApi from '@/api/auth'
import { setCsrfToken } from '@/api/client'
import type { AdminMe } from '@/api/types'

// 平台管理员会话，与租户（代理）会话 useAuthStore 完全分开：不同 Cookie、不同 CSRF token。
export const useAdminStore = defineStore('admin', {
  state: () => ({
    me: null as AdminMe | null,
    loading: true,
  }),
  getters: {
    isAuthenticated: (state) => state.me !== null,
  },
  actions: {
    async fetchMe() {
      try {
        this.me = await authApi.fetchAdminMe()
        setCsrfToken(this.me.csrf_token, 'admin')
      } catch {
        this.me = null
      } finally {
        this.loading = false
      }
    },
    async login(username: string, password: string) {
      this.me = await authApi.adminLogin(username, password)
      setCsrfToken(this.me.csrf_token, 'admin')
    },
    async changePassword(oldPassword: string, newPassword: string) {
      // 后端改完密码会清掉旧会话并当场发一个新的，所以这里要同时换 me 和 CSRF token。
      this.me = await authApi.adminChangePassword(oldPassword, newPassword)
      setCsrfToken(this.me.csrf_token, 'admin')
    },
    async logout() {
      await authApi.adminLogout()
      this.clearSession()
    },
    clearSession() {
      this.me = null
      setCsrfToken('', 'admin')
    },
  },
})
