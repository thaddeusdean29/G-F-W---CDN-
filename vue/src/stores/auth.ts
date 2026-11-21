import { defineStore } from 'pinia'
import * as authApi from '@/api/auth'
import { setCsrfToken } from '@/api/client'
import type { Me } from '@/api/types'

export const useAuthStore = defineStore('auth', {
  state: () => ({
    me: null as Me | null,
    loading: true, // 初次加载时为 true，路由守卫据此判断是否已经查过会话
  }),
  getters: {
    isAuthenticated: (state) => state.me !== null,
  },
  actions: {
    async fetchMe() {
      try {
        this.me = await authApi.fetchMe()
        setCsrfToken(this.me.csrf_token)
      } catch {
        this.me = null
      } finally {
        this.loading = false
      }
    },
    async login(email: string, password: string) {
      this.me = await authApi.login(email, password)
      setCsrfToken(this.me.csrf_token)
    },
    async logout() {
      await authApi.logout()
      this.me = null
      setCsrfToken('')
    },
    // 401 拦截器触发时调用：只清本地状态，不发请求（会话本来就已经失效）
    clearSession() {
      this.me = null
      setCsrfToken('')
    },
  },
})
