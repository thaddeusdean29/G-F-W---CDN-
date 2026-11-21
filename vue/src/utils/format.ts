import { ApiClientError } from '@/api/client'
import type { NodeError, PushResult } from '@/api/types'

export function formatBytes(n: number | undefined | null): string {
  const v0 = Number(n) || 0
  if (v0 < 1024) return `${v0} B`
  const units = ['KB', 'MB', 'GB', 'TB', 'PB']
  let v = v0
  let i = -1
  do {
    v /= 1024
    i++
  } while (v >= 1024 && i < units.length - 1)
  return `${v.toFixed(2)} ${units[i]}`
}

export function formatNumber(n: number | undefined | null): string {
  return (Number(n) || 0).toLocaleString()
}

export function formatDuration(sec: number | undefined | null): string {
  let s = Math.max(0, Math.floor(Number(sec) || 0))
  if (s === 0) return '-'
  const d = Math.floor(s / 86400)
  s %= 86400
  const h = Math.floor(s / 3600)
  s %= 3600
  const m = Math.floor(s / 60)
  s %= 60
  const parts: string[] = []
  if (d) parts.push(`${d}天`)
  if (h) parts.push(`${h}小时`)
  if (m && !d) parts.push(`${m}分`)
  if (!d && !h) parts.push(`${s}秒`)
  return parts.join('')
}

export function formatTime(s: string | undefined | null): string {
  if (!s || s.startsWith('0001-')) return '-'
  const d = new Date(s)
  return isNaN(d.getTime()) ? s : d.toLocaleString()
}

export function errMessage(e: unknown, fallback = '操作失败'): string {
  return e instanceof ApiClientError ? e.message : fallback
}

// 汇总下发结果：返回失败节点列表（空 = 全部成功）。
// "skipped: ..." 表示该项代理从未保存过配置、节点继续用自带默认值，不算失败。
export function pushFailures(res: PushResult | undefined | null): string[] {
  return Object.entries(res ?? {})
    .filter(([, v]) => v !== 'ok' && !String(v).startsWith('skipped'))
    .map(([k, v]) => `${k}: ${v}`)
}

export function nodeErrorsText(errs: NodeError[] | undefined | null): string {
  return (errs ?? []).map((e) => `${e.node}: ${e.error}`).join('；')
}
