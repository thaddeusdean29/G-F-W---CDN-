<script setup lang="ts">
// 24 小时单序列面积折线图（纯 SVG，无图表库依赖）。
// 按像素坐标绘制（ResizeObserver 取容器宽度），保证线宽恒为 2px、文字不被拉伸；
// 曲线用单调三次插值，不会冲到 0 以下或超过相邻点；悬停/方向键显示十字线与提示框。
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { formatBytes, formatNumber } from '@/utils/format'

type Kind = 'count' | 'bytes' | 'percent'

const props = defineProps<{
  title: string
  /** 下标即小时 0-23 */
  values: number[]
  /** 画到第几个小时（含），之后的小时尚未到来不画 */
  lastHour: number
  color: string
  kind: Kind
}>()

const HEIGHT = 210
const PAD_TOP = 14
const PAD_RIGHT = 16
const PAD_BOTTOM = 26

const wrap = ref<HTMLDivElement | null>(null)
const width = ref(600)
const active = ref<number | null>(null)
let ro: ResizeObserver | undefined

onMounted(() => {
  if (!wrap.value) return
  width.value = wrap.value.clientWidth || 600
  ro = new ResizeObserver((entries) => {
    const w = entries[0]?.contentRect.width
    if (w) width.value = w
  })
  ro.observe(wrap.value)
})
onBeforeUnmount(() => ro?.disconnect())

// ── 数值格式 ────────────────────────────────────────────────────────────────
const BYTE_UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']

function trim(v: number): string {
  return Number.isInteger(v) ? String(v) : v.toFixed(1).replace(/\.0$/, '')
}

function compactCount(v: number): string {
  const abs = Math.abs(v)
  if (abs >= 1e9) return `${trim(v / 1e9)}B`
  if (abs >= 1e6) return `${trim(v / 1e6)}M`
  if (abs >= 1e3) return `${trim(v / 1e3)}K`
  return trim(v)
}

function fullValue(v: number): string {
  if (props.kind === 'bytes') return formatBytes(v)
  if (props.kind === 'percent') return `${v.toFixed(2)}%`
  return formatNumber(v)
}

// ── 刻度：取「好看」的步长；流量按 1024 进制换单位后再取步长 ────────────────
function niceStep(raw: number): number {
  if (raw <= 0) return 1
  const mag = 10 ** Math.floor(Math.log10(raw))
  const n = raw / mag
  const s = n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10
  return s * mag
}

const drawn = computed(() => props.values.slice(0, Math.max(0, props.lastHour) + 1).map((v) => Number(v) || 0))

const scale = computed(() => {
  const max = Math.max(0, ...drawn.value)
  let unitIdx = 0
  let unit = 1
  if (props.kind === 'bytes') {
    while (max / unit >= 1024 && unitIdx < BYTE_UNITS.length - 1) {
      unit *= 1024
      unitIdx++
    }
  }
  let step = niceStep(max / unit / 4) * unit
  if (props.kind === 'count' || props.kind === 'bytes') step = Math.max(step, 1)
  if (props.kind === 'percent') step = Math.max(step, 0.25)
  const top = Math.max(step * 4, Math.ceil(max / step) * step)
  const ticks: number[] = []
  for (let t = 0; t <= top + step / 2; t += step) ticks.push(t)
  return { top, ticks, unit, unitIdx }
})

function axisLabel(v: number): string {
  if (v === 0) return '0'
  if (props.kind === 'bytes') return `${trim(v / scale.value.unit)} ${BYTE_UNITS[scale.value.unitIdx]}`
  if (props.kind === 'percent') return `${trim(v)}%`
  return compactCount(v)
}

const padLeft = computed(() => {
  const longest = Math.max(...scale.value.ticks.map((t) => axisLabel(t).length))
  return Math.max(28, longest * 7 + 12)
})

// ── 几何 ────────────────────────────────────────────────────────────────────
const plotW = computed(() => Math.max(10, width.value - padLeft.value - PAD_RIGHT))
const plotH = HEIGHT - PAD_TOP - PAD_BOTTOM
const baseY = PAD_TOP + plotH

function xOf(hour: number): number {
  return padLeft.value + (hour / 23) * plotW.value
}
function yOf(v: number): number {
  return PAD_TOP + plotH - (v / scale.value.top) * plotH
}

const points = computed(() => drawn.value.map((v, h) => ({ x: xOf(h), y: yOf(v) })))

// Fritsch–Carlson 单调三次插值（与 d3.curveMonotoneX 等价），零值段不会出现负的下凹。
function monotonePath(pts: { x: number; y: number }[]): string {
  const n = pts.length
  if (n === 0) return ''
  if (n === 1) return `M${pts[0].x},${pts[0].y}`
  const dx: number[] = []
  const m: number[] = []
  for (let i = 0; i < n - 1; i++) {
    dx[i] = pts[i + 1].x - pts[i].x
    m[i] = (pts[i + 1].y - pts[i].y) / dx[i]
  }
  const t: number[] = new Array(n)
  t[0] = m[0]
  t[n - 1] = m[n - 2]
  for (let i = 1; i < n - 1; i++) {
    t[i] = m[i - 1] * m[i] <= 0 ? 0 : (3 * (dx[i - 1] + dx[i])) / ((2 * dx[i] + dx[i - 1]) / m[i - 1] + (dx[i] + 2 * dx[i - 1]) / m[i])
  }
  let d = `M${pts[0].x},${pts[0].y}`
  for (let i = 0; i < n - 1; i++) {
    const h = dx[i] / 3
    d += `C${pts[i].x + h},${pts[i].y + t[i] * h} ${pts[i + 1].x - h},${pts[i + 1].y - t[i + 1] * h} ${pts[i + 1].x},${pts[i + 1].y}`
  }
  return d
}

const linePath = computed(() => monotonePath(points.value))
const areaPath = computed(() => {
  const pts = points.value
  if (pts.length < 2) return ''
  return `${linePath.value}L${pts[pts.length - 1].x},${baseY}L${pts[0].x},${baseY}Z`
})

const xTicks = [0, 3, 6, 9, 12, 15, 18, 21, 23]
const gradId = `hac-${Math.random().toString(36).slice(2, 9)}`

// ── 汇总与交互 ──────────────────────────────────────────────────────────────
const peak = computed(() => {
  let hour = 0
  drawn.value.forEach((v, h) => {
    if (v > drawn.value[hour]) hour = h
  })
  return { hour, value: drawn.value[hour] ?? 0 }
})

const ariaLabel = computed(
  () => `${props.title}，今日 0 时至 ${props.lastHour} 时，峰值 ${fullValue(peak.value.value)}（${pad(peak.value.hour)}:00）`,
)

function pad(h: number): string {
  return String(h).padStart(2, '0')
}

function onMove(e: PointerEvent) {
  const svg = e.currentTarget as SVGSVGElement
  const x = e.clientX - svg.getBoundingClientRect().left
  const h = Math.round(((x - padLeft.value) / plotW.value) * 23)
  active.value = Math.min(Math.max(h, 0), drawn.value.length - 1)
}

function onKey(e: KeyboardEvent) {
  const last = drawn.value.length - 1
  if (e.key === 'ArrowLeft') active.value = Math.max(0, (active.value ?? last) - 1)
  else if (e.key === 'ArrowRight') active.value = Math.min(last, (active.value ?? -1) + 1)
  else if (e.key === 'Escape') active.value = null
  else return
  e.preventDefault()
}

const tip = computed(() => {
  const h = active.value
  if (h === null || h >= points.value.length) return null
  const p = points.value[h]
  const flip = p.x > width.value - 160
  return { hour: h, x: p.x, y: p.y, flip, value: fullValue(drawn.value[h]) }
})
</script>

<template>
  <div class="hac">
    <div class="hac-head">
      <span class="hac-title">{{ title }}</span>
      <span class="hac-peak">峰值 <b>{{ fullValue(peak.value) }}</b> · {{ pad(peak.hour) }}:00</span>
    </div>
    <div ref="wrap" class="hac-plot">
      <svg
        :width="width"
        :height="HEIGHT"
        role="img"
        :aria-label="ariaLabel"
        tabindex="0"
        @pointermove="onMove"
        @pointerleave="active = null"
        @focus="active = drawn.length - 1"
        @blur="active = null"
        @keydown="onKey"
      >
        <defs>
          <linearGradient :id="gradId" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" :stop-color="color" stop-opacity="0.22" />
            <stop offset="100%" :stop-color="color" stop-opacity="0.01" />
          </linearGradient>
        </defs>

        <g class="grid">
          <line v-for="t in scale.ticks" :key="`g${t}`" :x1="padLeft" :x2="padLeft + plotW" :y1="yOf(t)" :y2="yOf(t)" />
        </g>
        <g class="y-axis">
          <text v-for="t in scale.ticks" :key="`y${t}`" :x="padLeft - 8" :y="yOf(t)" dy="0.32em" text-anchor="end">
            {{ axisLabel(t) }}
          </text>
        </g>
        <g class="x-axis">
          <text v-for="h in xTicks" :key="`x${h}`" :x="xOf(h)" :y="HEIGHT - 8" text-anchor="middle">{{ pad(h) }}:00</text>
        </g>

        <path v-if="areaPath" :d="areaPath" :fill="`url(#${gradId})`" />
        <path :d="linePath" fill="none" :stroke="color" stroke-width="2" stroke-linejoin="round" stroke-linecap="round" />

        <!-- 当前小时的端点 -->
        <circle
          v-if="points.length && tip === null"
          :cx="points[points.length - 1].x"
          :cy="points[points.length - 1].y"
          r="4"
          :fill="color"
          class="ring"
        />

        <g v-if="tip">
          <line class="crosshair" :x1="tip.x" :x2="tip.x" :y1="PAD_TOP" :y2="baseY" />
          <circle :cx="tip.x" :cy="tip.y" r="5" :fill="color" class="ring" />
        </g>
      </svg>

      <div
        v-if="tip"
        class="hac-tip"
        :style="{ left: `${tip.x}px`, top: `${Math.max(4, tip.y - 12)}px`, transform: tip.flip ? 'translate(calc(-100% - 12px), -100%)' : 'translate(12px, -100%)' }"
      >
        <div class="v"><i :style="{ background: color }"></i>{{ tip.value }}</div>
        <div class="t">{{ pad(tip.hour) }}:00 – {{ pad(tip.hour) }}:59</div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.hac-head {
  display: flex;
  align-items: baseline;
  justify-content: space-between;
  gap: 8px;
  margin-bottom: 6px;
}
.hac-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--text);
}
.hac-peak {
  font-size: 12px;
  color: var(--text-dim);
}
.hac-peak b {
  color: var(--text);
  font-weight: 600;
}
.hac-plot {
  position: relative;
  width: 100%;
}
svg {
  display: block;
  overflow: visible;
  outline: none;
  cursor: crosshair;
  touch-action: pan-y;
}
svg:focus-visible {
  outline: 1px solid var(--line-strong);
  outline-offset: 2px;
  border-radius: 4px;
}
.grid line {
  stroke: rgba(125, 139, 171, 0.14);
  stroke-width: 1;
  shape-rendering: crispEdges;
}
.y-axis text,
.x-axis text {
  fill: var(--text-dim);
  font-size: 11px;
  font-variant-numeric: tabular-nums;
}
.crosshair {
  stroke: rgba(219, 230, 255, 0.35);
  stroke-width: 1;
  shape-rendering: crispEdges;
}
.ring {
  stroke: #0d1424;
  stroke-width: 2;
}
.hac-tip {
  position: absolute;
  pointer-events: none;
  padding: 6px 10px;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: rgba(10, 16, 30, 0.96);
  box-shadow: 0 6px 20px rgba(0, 0, 0, 0.45);
  white-space: nowrap;
  z-index: 2;
}
.hac-tip .v {
  display: flex;
  align-items: center;
  gap: 6px;
  font-size: 14px;
  font-weight: 600;
  color: var(--text);
}
.hac-tip .v i {
  display: inline-block;
  width: 12px;
  height: 2px;
  border-radius: 1px;
}
.hac-tip .t {
  margin-top: 2px;
  font-size: 11px;
  color: var(--text-dim);
}
</style>
