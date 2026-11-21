<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { getDashboard } from '@/api/dashboard'
import HourlyAreaChart from '@/components/HourlyAreaChart.vue'
import type { Dashboard } from '@/api/types'
import { ApiClientError } from '@/api/client'
import { formatBytes, formatNumber } from '@/utils/format'

const dashboard = ref<Dashboard | null>(null)
const loading = ref(true)
const error = ref('')

const healthLabels: Record<string, string> = {
  active: '正常',
  degraded: '降级',
  failed: '故障',
  failover_in_progress: '切换中',
  failover_complete: '已切换',
}

const healthTagType: Record<string, 'success' | 'warning' | 'danger' | 'info'> = {
  active: 'success',
  degraded: 'warning',
  failed: 'danger',
  failover_in_progress: 'warning',
  failover_complete: 'info',
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    dashboard.value = await getDashboard()
  } catch (e) {
    error.value = e instanceof ApiClientError ? e.message : '加载失败'
  } finally {
    loading.value = false
  }
}

onMounted(load)

// 分时数据：缺的小时补 0，固定 24 项。
const hourly = computed(() => {
  const map = new Map<number, { requests: number; bytes: number; blocked: number }>()
  for (const h of dashboard.value?.today.hourly ?? []) map.set(h.hour, h)
  return Array.from({ length: 24 }, (_, hour) => ({ hour, requests: 0, bytes: 0, blocked: 0, ...map.get(hour) }))
})
// 只画到当前小时；若节点时区与浏览器不同导致更晚的小时已有数据，则画到有数据的最后一小时。
const lastHour = computed(() => {
  let last = new Date().getHours()
  hourly.value.forEach((h) => {
    if (h.requests || h.bytes || h.blocked) last = Math.max(last, h.hour)
  })
  return last
})
const series = computed(() => ({
  requests: hourly.value.map((h) => h.requests),
  bytes: hourly.value.map((h) => h.bytes),
  blocked: hourly.value.map((h) => h.blocked),
  rate: hourly.value.map((h) => (h.requests ? (h.blocked / h.requests) * 100 : 0)),
}))
const blockRate = computed(() => {
  const t = dashboard.value?.today
  return t && t.requests ? ((t.blocked / t.requests) * 100).toFixed(2) : '0.00'
})
const showTable = ref(false)
const tableRows = computed(() => hourly.value.slice(0, lastHour.value + 1).reverse())

// 已用 validate_palette.js 在深色面板底色 #0d1424 上校验（亮度带/色度/CVD/对比度全部通过）。
const COLORS = { requests: '#0f9fd0', bytes: '#8466ff', blocked: '#e04466' }
</script>

<template>
  <div class="page" v-loading="loading">
    <div class="page-header">
      <div>
        <h1>看板</h1>
        <p class="sub">本代理的节点、域名与今日流量概况</p>
      </div>
      <div class="actions">
        <el-button :loading="loading" @click="load">刷新</el-button>
      </div>
    </div>
    <el-alert v-if="error" :title="error" type="error" show-icon :closable="false" />

    <template v-if="dashboard">
      <div class="stat-grid">
        <div class="stat ok">
          <div class="label">节点在线</div>
          <div class="value">{{ dashboard.nodes.online }}<small>/ {{ dashboard.nodes.total }}</small></div>
        </div>
        <div class="stat">
          <div class="label">今日请求</div>
          <div class="value">{{ formatNumber(dashboard.today.requests) }}</div>
        </div>
        <div class="stat">
          <div class="label">今日流量</div>
          <div class="value">{{ formatBytes(dashboard.today.bytes) }}</div>
        </div>
        <div class="stat danger">
          <div class="label">今日拦截</div>
          <div class="value">{{ formatNumber(dashboard.today.blocked) }}<small>{{ blockRate }}%</small></div>
        </div>
        <div class="stat warn">
          <div class="label">节点配额</div>
          <div class="value">{{ dashboard.usage.nodes }}<small>/ {{ dashboard.plan.max_nodes }}</small></div>
        </div>
        <div class="stat warn">
          <div class="label">域名配额</div>
          <div class="value">{{ dashboard.usage.domains }}<small>/ {{ dashboard.plan.max_domains }}</small></div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-title">
          <span>今日分时趋势</span>
          <el-button link type="primary" @click="showTable = !showTable">{{ showTable ? '收起明细' : '查看明细' }}</el-button>
        </div>
        <div class="chart-grid">
          <div class="chart-card">
            <HourlyAreaChart title="请求数" :values="series.requests" :last-hour="lastHour" :color="COLORS.requests" kind="count" />
          </div>
          <div class="chart-card">
            <HourlyAreaChart title="流量" :values="series.bytes" :last-hour="lastHour" :color="COLORS.bytes" kind="bytes" />
          </div>
          <div class="chart-card">
            <HourlyAreaChart title="拦截请求" :values="series.blocked" :last-hour="lastHour" :color="COLORS.blocked" kind="count" />
          </div>
          <div class="chart-card">
            <HourlyAreaChart
              :title="`拦截率（全天 ${blockRate}%）`"
              :values="series.rate"
              :last-hour="lastHour"
              :color="COLORS.blocked"
              kind="percent"
            />
          </div>
        </div>
        <el-table v-if="showTable" :data="tableRows" size="small" class="hour-table" max-height="360">
          <el-table-column label="时段" width="130">
            <template #default="{ row }">{{ String(row.hour).padStart(2, '0') }}:00 – {{ String(row.hour).padStart(2, '0') }}:59</template>
          </el-table-column>
          <el-table-column label="请求数" align="right">
            <template #default="{ row }">{{ formatNumber(row.requests) }}</template>
          </el-table-column>
          <el-table-column label="流量" align="right">
            <template #default="{ row }">{{ formatBytes(row.bytes) }}</template>
          </el-table-column>
          <el-table-column label="拦截" align="right">
            <template #default="{ row }">{{ formatNumber(row.blocked) }}</template>
          </el-table-column>
          <el-table-column label="拦截率" align="right">
            <template #default="{ row }">{{ row.requests ? ((row.blocked / row.requests) * 100).toFixed(2) : '0.00' }}%</template>
          </el-table-column>
        </el-table>
      </div>

      <div class="panel">
        <div class="panel-title"><span>集群健康分布</span></div>
        <div v-if="Object.keys(dashboard.clusters).length === 0" class="dim">暂无集群</div>
        <div v-else class="health-tags">
          <el-tag
            v-for="(count, status) in dashboard.clusters"
            :key="status"
            :type="healthTagType[status] ?? 'info'"
            size="large"
            effect="dark"
          >
            {{ healthLabels[status] ?? status }}: {{ count }}
          </el-tag>
        </div>
      </div>
    </template>
  </div>
</template>

<style scoped>
.chart-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 12px;
}
@media (max-width: 1100px) {
  .chart-grid {
    grid-template-columns: minmax(0, 1fr);
  }
}
.chart-card {
  padding: 12px 14px 6px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: rgba(13, 20, 36, 0.6);
  min-width: 0;
}
.hour-table {
  margin-top: 12px;
}
.health-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}
</style>
