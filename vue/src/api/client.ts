import axios, { AxiosError, type AxiosInstance } from 'axios'
import type { ApiError } from './types'

// 统一封装的错误类型：调用方 catch 到的就是这个，而不是裸的 AxiosError。
export class ApiClientError extends Error {
  code: string
  details?: Record<string, unknown>
  status: number

  constructor(status: number, err: ApiError) {
    super(err.message)
    this.name = 'ApiClientError'
    this.code = err.code
    this.details = err.details
    this.status = status
  }
}

// CSRF token 由登录响应 / GET /auth/me 下发，写请求必须带上（见 API-v2.md 0.2）。
// 租户和管理员是两套会话、两个 token，分开存，同一浏览器同时登录两边也不会串。
type Realm = 'tenant' | 'admin'
const csrfTokens: Record<Realm, string> = { tenant: '', admin: '' }
export function setCsrfToken(token: string, realm: Realm = 'tenant') {
  csrfTokens[realm] = token
}

// 会话失效时的回调，由路由层注入（避免这里直接依赖 vue-router）。
const onUnauthenticated: Partial<Record<Realm, () => void>> = {}
export function setUnauthenticatedHandler(handler: () => void, realm: Realm = 'tenant') {
  onUnauthenticated[realm] = handler
}

function createClient(basePath: string, realm: Realm): AxiosInstance {
  const instance = axios.create({
    baseURL: basePath,
    withCredentials: true,
    headers: { 'Content-Type': 'application/json' },
  })

  instance.interceptors.request.use((config) => {
    const method = (config.method ?? 'get').toLowerCase()
    const csrfToken = csrfTokens[realm]
    if (method !== 'get' && csrfToken) {
      config.headers.set('X-CSRF-Token', csrfToken)
    }
    return config
  })

  instance.interceptors.response.use(
    (res) => res,
    (error: AxiosError<{ error: ApiError }>) => {
      const status = error.response?.status ?? 0
      const body = error.response?.data?.error
      if (status === 401) {
        onUnauthenticated[realm]?.()
      }
      if (body) {
        return Promise.reject(new ApiClientError(status, body))
      }
      return Promise.reject(
        new ApiClientError(status, { code: 'network_error', message: error.message }),
      )
    },
  )

  return instance
}

// 租户接口和管理员接口用不同 Cookie，分成两个客户端，互不影响。
export const tenantApi = createClient('/api/v2', 'tenant')
export const adminApi = createClient('/api/v2/admin', 'admin')

/**
 * 轮询一个 Job 直到 done/failed。intervalMs 默认 1.5s，符合 API-v2.md 0.8 的建议区间。
 */
export async function pollJob<T>(
  client: AxiosInstance,
  jobId: string,
  opts: {
    intervalMs?: number
    timeoutMs?: number
    onProgress?: (job: import('./types').Job<T>) => void
  } = {},
): Promise<import('./types').Job<T>> {
  const intervalMs = opts.intervalMs ?? 1500
  const timeoutMs = opts.timeoutMs ?? 10 * 60 * 1000
  const startedAt = Date.now()

  while (true) {
    const { data } = await client.get<import('./types').Job<T>>(`/jobs/${jobId}`)
    opts.onProgress?.(data)
    if (data.status === 'done' || data.status === 'failed') {
      return data
    }
    if (Date.now() - startedAt > timeoutMs) {
      throw new ApiClientError(0, { code: 'job_timeout', message: '任务轮询超时' })
    }
    await new Promise((resolve) => setTimeout(resolve, intervalMs))
  }
}
