<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { blockIP, getCCConfig, getCCIPs, getCCStats, putCCConfig, unblockIP } from '@/api/security'
import type { CCConfig, CCIP, CCPressure, CCStats, PerNode, PushResult } from '@/api/types'
import { errMessage, formatNumber, formatTime, nodeErrorsText, pushFailures } from '@/utils/format'

const total = ref<CCStats | null>(null)
const perNode = ref<PerNode<CCStats>[]>([])
const ips = ref<CCIP[]>([])
const ipErrors = ref('')
const onlyBlocked = ref(true)
const q = ref('')
const loadingStats = ref(false)
const loadingIPs = ref(false)
const saving = ref(false)
const saved = ref(false)
const busy = ref<Record<string, boolean>>({})

const cfg = reactive<CCConfig>({
  enabled: true,
  requests_per_second: 0,
  requests_per_minute: 0,
  burst_size: 0,
  block_duration: 600,
  whitelist_ips: [],
  path_whitelist: [],
})
const whitelistText = ref('')
const pathText = ref('')

const manual = reactive({ ip: '', minutes: 60 })

function reportPush(push: PushResult, okMsg: string) {
  const fails = pushFailures(push)
  if (fails.length) ElMessage.warning(`${okMsg}，但部分节点失败：${fails.join('；')}`)
  else ElMessage.success(okMsg)
}

async function loadStats() {
  loadingStats.value = true
  try {
    const r = await getCCStats()
    total.value = r.total
    perNode.value = r.nodes
  } catch (e) {
    ElMessage.error(errMessage(e, '加载 CC 统计失败'))
  } finally {
    loadingStats.value = false
  }
}

async function loadIPs() {
  loadingIPs.value = true
  try {
    const r = await getCCIPs(onlyBlocked.value)
    ips.value = r.items
    ipErrors.value = nodeErrorsText(r.errors)
  } catch (e) {
    ElMessage.error(errMessage(e, '加载 IP 列表失败'))
  } finally {
    loadingIPs.value = false
  }
}

async function loadConfig() {
  try {
    const r = await getCCConfig()
    Object.assign(cfg, r.config)
    saved.value = r.saved
    whitelistText.value = (r.config.whitelist_ips ?? []).join('\n')
    pathText.value = (r.config.path_whitelist ?? []).join('\n')
  } catch (e) {
    ElMessage.error(errMessage(e, '加载 CC 配置失败'))
  }
}

function lines(s: string): string[] {
  return s
    .split(/[\n,]/)
    .map((x) => x.trim())
    .filter(Boolean)
}

async function save() {
  saving.value = true
  try {
    const r = await putCCConfig({ ...cfg, whitelist_ips: lines(whitelistText.value), path_whitelist: lines(pathText.value) })
    Object.assign(cfg, r.config)
    saved.value = true
    reportPush(r.push, 'CC 配置已保存并下发')
  } catch (e) {
    ElMessage.error(errMessage(e, '保存失败'))
  } finally {
    saving.value = false
  }
}

async function unblock(row: CCIP) {
  busy.value[row.ip] = true
  try {
    const r = await unblockIP(row.ip, 'cc')
    reportPush(r.push, `已解封 ${row.ip}`)
    await Promise.all([loadIPs(), loadStats()])
  } catch (e) {
    ElMessage.error(errMessage(e, '解封失败'))
  } finally {
    busy.value[row.ip] = false
  }
}

async function manualBlock() {
  const ip = manual.ip.trim()
  if (!ip) return
  busy.value.__manual = true
  try {
    const r = await blockIP(ip, 'waf', manual.minutes)
    reportPush(r.push, `已封禁 ${ip} ${manual.minutes} 分钟`)
    manual.ip = ''
    await loadIPs()
  } catch (e) {
    ElMessage.error(errMessage(e, '封禁失败'))
  } finally {
    busy.value.__manual = false
  }
}

const filtered = computed(() => {
  const kw = q.value.trim()
  if (!kw) return ips.value
  return ips.value.filter((i) => i.ip.includes(kw) || (i.block_host ?? '').includes(kw))
})

// 追踪表额度读数。dropped / early_unbanned 不为 0 意味着防御正在降级运行：
// 表被打满时系统宁可回收闲置条目，也不肯停止统计——但回收本身必须被看见。
const pressureRows = computed(() => {
  const cap = total.value?.capacity
  if (!cap) return []
  return [
    { label: 'IP 追踪表', ...cap.ips },
    { label: '域名追踪表', ...cap.domains },
    { label: '指纹追踪表', ...cap.fingerprints },
    { label: '缓存绕过追踪表', ...cap.cache_buster },
    { label: '路径变体额度', ...cap.cache_paths },
  ].filter((r) => r.size > 0 || r.reclaimed > 0 || r.early_unbanned > 0 || r.dropped > 0)
})

const degradedTables = computed(() =>
  pressureRows.value.filter((r) => r.early_unbanned > 0 || r.dropped > 0),
)

// 自适应模式下盾牌平时是收起来的：0 个域名开盾说明此刻全部静默放行，非 0 就是真有域名
// 越过了 QPS 判定线。总数取各节点最大值（同一域名在多个节点开盾只算一个域名）。
const shieldLabel = computed(() => {
  const strict = total.value?.domains_in_strict ?? 0
  const challenge = total.value?.domains_in_challenge ?? 0
  const held = Math.max(strict, challenge)
  if (!held) return '静默放行'
  return strict ? `${held} 个 · ${strict} 个进指纹层` : `${held} 个`
})

// 某个节点的追踪表是否发生过"牺牲防护换腾位"。
function nodeDegraded(cap?: CCPressure): boolean {
  if (!cap) return false
  return [cap.ips, cap.domains, cap.fingerprints, cap.cache_buster, cap.cache_paths].some(
    (p) => p.early_unbanned > 0 || p.dropped > 0,
  )
}

// 逐节点表里的开盾读数：一个都没开时给「—」，别让整列 0 抢走"哪台在挨打"的注意力。
// 斜杠后面是其中已经进入第三层指纹判定的域名数。
function shieldCell(stats?: CCStats): string {
  const challenge = stats?.domains_in_challenge ?? 0
  const strict = stats?.domains_in_strict ?? 0
  if (!challenge && !strict) return '—'
  return strict ? `${challenge} / ${strict}` : `${challenge}`
}

function refreshAll() {
  loadStats()
  loadIPs()
}

onMounted(() => {
  refreshAll()
  loadConfig()
})
</script>

<template>
  <div class="page">
    <div class="page-header">
      <div>
        <h1>CC 防御</h1>
        <p class="sub">七层频率限制与人机验证 · 域名级验证策略在「域名 → 编辑 → CC 防御」中配置</p>
      </div>
      <div class="actions">
        <el-button :loading="loadingStats || loadingIPs" @click="refreshAll">刷新</el-button>
      </div>
    </div>

    <div class="stat-grid" v-loading="loadingStats && !total">
      <div class="stat">
        <div class="label">追踪 IP</div>
        <div class="value">{{ formatNumber(total?.total_tracked) }}</div>
      </div>
      <div class="stat ok">
        <div class="label">活跃 IP</div>
        <div class="value">{{ formatNumber(total?.active_ips) }}</div>
      </div>
      <div class="stat warn">
        <div class="label">违规 IP</div>
        <div class="value">{{ formatNumber(total?.violating_ips) }}</div>
      </div>
      <div class="stat danger">
        <div class="label">封禁 IP</div>
        <div class="value">{{ formatNumber(total?.blocked_ips) }}</div>
      </div>
      <div class="stat">
        <div class="label">降权凭证 IP</div>
        <div class="value">{{ formatNumber(total?.downgraded_ips) }}</div>
      </div>
      <div class="stat" :class="(total?.domains_in_strict ?? 0) ? 'danger' : (total?.domains_in_challenge ?? 0) ? 'warn' : 'ok'">
        <div class="label">开盾域名</div>
        <div class="value">{{ shieldLabel }}</div>
      </div>
      <div class="stat" :class="degradedTables.length ? 'danger' : 'ok'">
        <div class="label">追踪表退化</div>
        <div class="value">{{ degradedTables.length ? `${degradedTables.length} 张表` : '未发生' }}</div>
      </div>
    </div>

    <el-alert
      v-if="degradedTables.length"
      type="error"
      :closable="false"
      show-icon
      title="追踪表额度已被攻击用尽，防御正在降级运行"
    >
      <div v-for="r in degradedTables" :key="r.label" class="small">
        {{ r.label }}：占用 {{ formatNumber(r.size) }} / 额度 {{ formatNumber(r.limit) }}，提前解除
        {{ formatNumber(r.early_unbanned) }} 次，放弃追踪 {{ formatNumber(r.dropped) }} 次
      </div>
      <div class="small dim">
        「提前解除」会放过仍在封禁或拦截期的对象，「放弃追踪」让新对象不再被跨请求统计。回收闲置条目不算退化。
      </div>
    </el-alert>

    <el-tabs type="border-card" class="tabs">
      <el-tab-pane label="IP 列表">
        <el-alert v-if="ipErrors" type="warning" :closable="false" show-icon :title="`部分节点未返回：${ipErrors}`" />
        <div class="toolbar">
          <el-radio-group v-model="onlyBlocked" @change="loadIPs">
            <el-radio-button :value="true">已封禁</el-radio-button>
            <el-radio-button :value="false">全部追踪</el-radio-button>
          </el-radio-group>
          <el-input v-model="q" placeholder="过滤 IP / 域名" clearable style="width: 200px" />
          <span class="grow"></span>
          <el-input v-model="manual.ip" placeholder="手动封禁 IP" style="width: 180px" @keyup.enter="manualBlock" />
          <el-input-number v-model="manual.minutes" :min="1" :max="43200" controls-position="right" style="width: 130px" />
          <span class="dim">分钟</span>
          <el-button type="danger" :loading="busy.__manual" :disabled="!manual.ip.trim()" @click="manualBlock">
            封禁
          </el-button>
        </div>
        <el-table v-loading="loadingIPs" :data="filtered" size="small" empty-text="暂无记录" max-height="560">
          <el-table-column label="IP" min-width="140">
            <template #default="{ row }">
              <span class="mono">{{ row.ip }}</span>
              <div v-if="row.location || row.country" class="dim small">{{ row.location || row.country }}</div>
            </template>
          </el-table-column>
          <el-table-column label="RPS" width="70" align="right" prop="requests_per_second" sortable />
          <el-table-column label="RPM" width="80" align="right" prop="requests_per_minute" sortable />
          <el-table-column label="违规" width="70" align="right" prop="violations" sortable />
          <el-table-column label="封禁原因" min-width="180" show-overflow-tooltip>
            <template #default="{ row }">
              <template v-if="row.blocked">
                {{ row.block_rule || '-' }}
                <span v-if="row.block_host" class="dim"> · {{ row.block_host }}{{ row.block_path }}</span>
              </template>
              <span v-else class="dim">-</span>
            </template>
          </el-table-column>
          <el-table-column label="状态" width="170">
            <template #default="{ row }">
              <el-tag v-if="row.blocked" type="danger" size="small" effect="dark">已封禁</el-tag>
              <el-tag v-else size="small" type="info">追踪中</el-tag>
              <div v-if="row.blocked" class="dim small">至 {{ formatTime(row.blocked_until) }}</div>
              <div v-else class="dim small">{{ formatTime(row.last_request) }}</div>
            </template>
          </el-table-column>
          <el-table-column label="节点" min-width="110" show-overflow-tooltip>
            <template #default="{ row }">{{ row.nodes.join(', ') }}</template>
          </el-table-column>
          <el-table-column label="操作" width="80" fixed="right">
            <template #default="{ row }">
              <el-button v-if="row.blocked" link type="primary" :loading="busy[row.ip]" @click="unblock(row)">
                解封
              </el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="全局配置">
        <el-alert
          v-if="!saved"
          type="info"
          :closable="false"
          show-icon
          title="当前显示的是默认值，保存后才会写入本代理配置并下发到你的全部节点。"
        />
        <el-form label-width="140px" class="cfg-form" @submit.prevent="save">
          <el-form-item label="启用 CC 防御">
            <el-switch v-model="cfg.enabled" />
          </el-form-item>
          <el-form-item label="每秒请求上限">
            <el-input-number v-model="cfg.requests_per_second" :min="0" controls-position="right" />
            <span class="hint">单 IP 每秒，0 = 不限制</span>
          </el-form-item>
          <el-form-item label="每分钟请求上限">
            <el-input-number v-model="cfg.requests_per_minute" :min="0" controls-position="right" />
            <span class="hint">单 IP 每分钟，0 = 不限制</span>
          </el-form-item>
          <el-form-item label="突发容量">
            <el-input-number v-model="cfg.burst_size" :min="0" controls-position="right" />
          </el-form-item>
          <el-form-item label="封禁时长（秒）">
            <el-input-number v-model="cfg.block_duration" :min="1" :max="2592000" controls-position="right" />
          </el-form-item>
          <el-form-item label="IP 白名单">
            <el-input v-model="whitelistText" type="textarea" :rows="4" class="mono" placeholder="每行一个 IP 或 CIDR" />
          </el-form-item>
          <el-form-item label="路径白名单">
            <el-input v-model="pathText" type="textarea" :rows="3" class="mono" placeholder="每行一个路径前缀，如 /health" />
          </el-form-item>
          <el-form-item>
            <el-button type="primary" native-type="submit" :loading="saving">保存并下发</el-button>
          </el-form-item>
        </el-form>
      </el-tab-pane>

      <el-tab-pane label="节点统计">
        <el-table :data="perNode" size="small" empty-text="暂无节点">
          <el-table-column label="节点" min-width="160">
            <template #default="{ row }">
              <span class="dot" :class="row.error ? 'bad' : 'on'"></span>{{ row.node }}
            </template>
          </el-table-column>
          <el-table-column label="IP" width="150">
            <template #default="{ row }"><span class="mono">{{ row.ip }}</span></template>
          </el-table-column>
          <el-table-column label="追踪" width="90" align="right">
            <template #default="{ row }">{{ formatNumber(row.stats?.total_tracked) }}</template>
          </el-table-column>
          <el-table-column label="活跃" width="90" align="right">
            <template #default="{ row }">{{ formatNumber(row.stats?.active_ips) }}</template>
          </el-table-column>
          <el-table-column label="违规" width="90" align="right">
            <template #default="{ row }">{{ formatNumber(row.stats?.violating_ips) }}</template>
          </el-table-column>
          <el-table-column label="封禁" width="90" align="right">
            <template #default="{ row }">{{ formatNumber(row.stats?.blocked_ips) }}</template>
          </el-table-column>
          <el-table-column label="降权凭证" width="90" align="right">
            <template #default="{ row }">{{ formatNumber(row.stats?.downgraded_ips) }}</template>
          </el-table-column>
          <el-table-column label="开盾 / 指纹" width="110" align="right">
            <template #default="{ row }">{{ shieldCell(row.stats) }}</template>
          </el-table-column>
          <el-table-column label="退化" width="90" align="right">
            <template #default="{ row }">{{ nodeDegraded(row.stats?.capacity) ? '降级运行' : '—' }}</template>
          </el-table-column>
          <el-table-column label="错误" min-width="160" show-overflow-tooltip>
            <template #default="{ row }"><span class="err">{{ row.error }}</span></template>
          </el-table-column>
        </el-table>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<style scoped>
.tabs {
  background: var(--panel);
  border-color: var(--line);
}
.toolbar {
  display: flex;
  gap: 8px;
  align-items: center;
  flex-wrap: wrap;
  margin-bottom: 12px;
}
.grow {
  flex: 1;
}
.small {
  font-size: 11px;
}
.cfg-form {
  max-width: 640px;
}
.hint {
  margin-left: 10px;
  font-size: 12px;
  color: var(--text-dim);
}
.err {
  color: var(--danger);
}
</style>
