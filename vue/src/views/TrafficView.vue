<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { getTraffic } from '@/api/security'
import type { Traffic, TrafficIP } from '@/api/types'
import { errMessage, formatBytes, formatNumber, formatTime, nodeErrorsText } from '@/utils/format'

const data = ref<Traffic | null>(null)
const loading = ref(false)
const auto = ref(true)
// 只筛选「热门来源 IP」，上面的总量/曲线口径不变（后端 security.go 就是这么实现的）。
const ipDomain = ref('')
let timer: number | undefined

async function load() {
  loading.value = true
  try {
    data.value = await getTraffic(ipDomain.value)
  } catch (e) {
    ElMessage.error(errMessage(e, '加载流量统计失败'))
  } finally {
    loading.value = false
  }
}

// 换筛选域名时下拉框直接 @change="load" 走同一个函数；自动刷新开着时也带上这个筛选。
function toggleAuto(on: boolean | string | number) {
  window.clearInterval(timer)
  timer = on ? window.setInterval(load, 30000) : undefined
}

onMounted(() => {
  load()
  toggleAuto(auto.value)
})
onBeforeUnmount(() => window.clearInterval(timer))

// 24 小时柱状图：没有数据的小时补 0，保证 24 根柱子都在。
const hours = computed(() => {
  const map = new Map<number, { requests: number; bytes: number; blocked: number }>()
  for (const h of data.value?.hourly ?? []) map.set(h.hour, h)
  return Array.from({ length: 24 }, (_, hour) => ({ hour, requests: 0, bytes: 0, blocked: 0, ...map.get(hour) }))
})
const maxReq = computed(() => Math.max(1, ...hours.value.map((h) => h.requests)))
const blockRate = computed(() => {
  const t = data.value
  if (!t || !t.total_requests) return '0.00'
  return ((t.total_blocked / t.total_requests) * 100).toFixed(2)
})
const errors = computed(() => nodeErrorsText(data.value?.errors))

// 下拉选项取「域名流量」表：那份是本代理的全部域名（后端按代理自己的域名清单建的），
// 不随筛选变化，切到某个域名后不会把其他选项洗掉。
const ipDomainOptions = computed(() => (data.value?.domains ?? []).map((d) => d.domain))

// 地理库的状态必须说清楚，不能让归属地列静默空白：
// ready=false 是没装/打不开，missing 里带着找过的绝对路径；只装了一个家族则是部分可用。
const geoNote = computed(() => {
  const g = data.value?.geo
  if (!g) return ''
  if (!g.ready) return 'IP 归属地不可用：' + (g.missing ?? []).join('；')
  if (g.missing?.length) return 'IP 归属地只部分可用：' + g.missing.join('；')
  return ''
})

// 城市 → 省份 → 国家码，空的层级跳过；查不到（私网、保留段、库未覆盖）显示破折号。
function geoText(row: TrafficIP): string {
  const parts = [row.city, row.region, row.country].filter(Boolean)
  return parts.length ? parts.join(' · ') : '—'
}
</script>

<template>
  <div class="page">
    <div class="page-header">
      <div>
        <h1>流量统计</h1>
        <p class="sub">
          仅统计本代理自己的节点与域名 · 更新于 {{ formatTime(data?.collected_at) }}
        </p>
      </div>
      <div class="actions">
        <el-switch v-model="auto" active-text="30 秒自动刷新" @change="toggleAuto" />
        <el-button :loading="loading" @click="load">刷新</el-button>
      </div>
    </div>

    <el-alert v-if="errors" type="warning" :closable="false" show-icon :title="`部分节点未返回数据：${errors}`" />

    <div class="stat-grid" v-loading="loading && !data">
      <div class="stat">
        <div class="label">今日请求</div>
        <div class="value">{{ formatNumber(data?.total_requests) }}</div>
      </div>
      <div class="stat ok">
        <div class="label">今日流量</div>
        <div class="value">{{ formatBytes(data?.total_bytes) }}</div>
      </div>
      <div class="stat danger">
        <div class="label">拦截请求</div>
        <div class="value">{{ formatNumber(data?.total_blocked) }}<small>{{ blockRate }}%</small></div>
      </div>
      <div class="stat">
        <div class="label">独立 IP</div>
        <div class="value">{{ formatNumber(data?.unique_ips) }}</div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">
        <span>24 小时请求分布</span>
        <span class="legend dim"><i class="lg req"></i>请求 <i class="lg blk"></i>拦截</span>
      </div>
      <div class="bar-chart" role="img" aria-label="24 小时请求分布柱状图">
        <div v-for="h in hours" :key="h.hour" class="bar">
          <el-tooltip
            :content="`${h.hour}:00 · 请求 ${formatNumber(h.requests)} · 拦截 ${formatNumber(h.blocked)} · ${formatBytes(h.bytes)}`"
            placement="top"
          >
            <div class="fill" :style="{ height: `${(h.requests / maxReq) * 100}%` }">
              <div
                class="blk"
                :style="{ height: h.requests ? `${Math.min(100, (h.blocked / h.requests) * 100)}%` : '0' }"
              ></div>
            </div>
          </el-tooltip>
          <div class="x">{{ h.hour }}</div>
        </div>
      </div>
    </div>

    <div class="two-col">
      <div class="panel">
        <div class="panel-title"><span>热门域名</span></div>
        <el-table :data="data?.top_domains ?? []" size="small" empty-text="暂无数据">
          <el-table-column type="index" width="44" />
          <el-table-column label="域名" prop="key" min-width="160" show-overflow-tooltip />
          <el-table-column label="请求" width="100" align="right">
            <template #default="{ row }">{{ formatNumber(row.requests) }}</template>
          </el-table-column>
          <el-table-column label="流量" width="110" align="right">
            <template #default="{ row }">{{ formatBytes(row.bytes) }}</template>
          </el-table-column>
        </el-table>
      </div>
      <div class="panel">
        <div class="panel-title">
          <span>热门来源 IP</span>
          <span class="ip-filter">
            <el-select v-model="ipDomain" size="small" clearable placeholder="全部域名" @change="load">
              <el-option v-for="d in ipDomainOptions" :key="d" :label="d" :value="d" />
            </el-select>
          </span>
        </div>
        <p class="ip-scope">
          {{ ipDomain ? `只看 ${ipDomain} 的来源 IP。` : '看的是本代理全部域名的来源 IP。' }}
          上方总量与 24 小时曲线不随这个筛选变化。
        </p>
        <el-alert v-if="geoNote" type="warning" :closable="false" show-icon :title="geoNote" class="geo-note" />
        <el-table :data="data?.top_ips ?? []" size="small" empty-text="暂无数据">
          <el-table-column type="index" width="44" />
          <el-table-column label="IP" min-width="140">
            <template #default="{ row }"><span class="mono">{{ row.ip }}</span></template>
          </el-table-column>
          <el-table-column label="归属地" min-width="150" show-overflow-tooltip>
            <template #default="{ row }"><span class="small">{{ geoText(row) }}</span></template>
          </el-table-column>
          <el-table-column label="请求" width="90" align="right">
            <template #default="{ row }">{{ formatNumber(row.requests) }}</template>
          </el-table-column>
          <el-table-column label="流量" width="100" align="right">
            <template #default="{ row }">{{ formatBytes(row.bytes) }}</template>
          </el-table-column>
        </el-table>
        <!-- DB-IP 是 CC BY 4.0：只要这一页展示了它算出来的归属地，就必须带署名回链。
             链接文字用许可原文要求的 "IP Geolocation by DB-IP"，许可正文见 data/DBIP-LICENSE。 -->
        <p v-if="data?.geo?.ready" class="geo-attr">
          <a href="https://db-ip.com" target="_blank" rel="noopener noreferrer">IP Geolocation by DB-IP</a>
          （City Edition Lite，CC BY 4.0）
        </p>
      </div>
    </div>

    <div class="panel">
      <div class="panel-title"><span>域名流量</span></div>
      <el-table :data="data?.domains ?? []" size="small" empty-text="暂无数据" :default-sort="{ prop: 'today_bytes', order: 'descending' }">
        <el-table-column label="域名" prop="domain" min-width="200" sortable />
        <el-table-column label="今日流量" prop="today_bytes" width="130" align="right" sortable>
          <template #default="{ row }">{{ formatBytes(row.today_bytes) }}</template>
        </el-table-column>
        <el-table-column label="请求" prop="requests" width="120" align="right" sortable>
          <template #default="{ row }">{{ formatNumber(row.requests) }}</template>
        </el-table-column>
        <el-table-column label="拦截" prop="blocked" width="110" align="right" sortable>
          <template #default="{ row }">
            <span :class="{ danger: row.blocked > 0 }">{{ formatNumber(row.blocked) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="独立 IP" prop="unique_ips" width="110" align="right" sortable>
          <template #default="{ row }">{{ formatNumber(row.unique_ips) }}</template>
        </el-table-column>
      </el-table>
    </div>

    <div class="panel">
      <div class="panel-title"><span>节点状态</span></div>
      <el-table :data="data?.nodes ?? []" size="small" empty-text="暂无节点">
        <el-table-column label="节点" min-width="160">
          <template #default="{ row }">
            <span class="dot" :class="row.error ? 'bad' : 'on'"></span>{{ row.node }}
          </template>
        </el-table-column>
        <el-table-column label="IP" width="150">
          <template #default="{ row }"><span class="mono">{{ row.ip }}</span></template>
        </el-table-column>
        <el-table-column label="请求" width="120" align="right">
          <template #default="{ row }">{{ formatNumber(row.total_requests) }}</template>
        </el-table-column>
        <el-table-column label="流量" width="120" align="right">
          <template #default="{ row }">{{ formatBytes(row.total_bytes) }}</template>
        </el-table-column>
        <el-table-column label="拦截" width="110" align="right">
          <template #default="{ row }">{{ formatNumber(row.total_blocked) }}</template>
        </el-table-column>
        <el-table-column label="状态" min-width="160" show-overflow-tooltip>
          <template #default="{ row }">
            <span v-if="row.error" class="danger">{{ row.error }}</span>
            <span v-else class="dim">正常</span>
          </template>
        </el-table-column>
      </el-table>
    </div>
  </div>
</template>

<style scoped>
.two-col {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
  gap: 16px;
}
.legend {
  font-size: 12px;
  font-weight: 400;
}
.lg {
  display: inline-block;
  width: 10px;
  height: 10px;
  border-radius: 2px;
  margin: 0 4px 0 10px;
  vertical-align: -1px;
}
.lg.req {
  background: var(--accent);
}
.lg.blk {
  background: var(--danger);
}
.danger {
  color: var(--danger);
}
.small {
  font-size: 11px;
}
.ip-filter {
  display: inline-flex;
  align-items: center;
  font-weight: 400;
}
.ip-filter :deep(.el-select) {
  width: 200px;
}
.ip-scope {
  margin: 0 0 10px;
  font-size: 12px;
  color: var(--text-dim);
}
.geo-note {
  margin-bottom: 10px;
}
.geo-attr {
  margin: 10px 0 0;
  font-size: 11px;
  color: var(--text-dim);
}
.geo-attr a {
  color: var(--accent);
  text-decoration: none;
}
.geo-attr a:hover {
  text-decoration: underline;
}
</style>
