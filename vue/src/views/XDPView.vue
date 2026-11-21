<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  blockIP,
  getBanConfig,
  getXDPBlocklist,
  getXDPConfig,
  getXDPStats,
  putBanConfig,
  putXDPConfig,
  unblockIP,
  type XDPStats,
} from '@/api/security'
import type { BanConfig, PerNode, PushResult, XDPBlock, XDPConfig } from '@/api/types'
import { errMessage, formatDuration, formatNumber, nodeErrorsText, pushFailures } from '@/utils/format'

// 丢包计数器 → 中文说明，顺序即展示顺序。
const DROP_LABELS: Array<[string, string]> = [
  ['dropped_blocklist', '黑名单'],
  ['dropped_syn_flood', 'SYN 洪水'],
  ['dropped_pps', 'PPS 超限'],
  ['dropped_conn_limit', '并发连接超限'],
  ['dropped_udp_flood', 'UDP 洪水'],
  ['dropped_icmp_flood', 'ICMP 洪水'],
  ['dropped_dns_amp', 'DNS 反射放大'],
  ['dropped_tcp_rst', 'RST 洪水'],
  ['dropped_ack_flood', 'ACK 洪水'],
  ['dropped_fin_flood', 'FIN 洪水'],
  ['dropped_psh_ack_guard', 'PSH-ACK 守卫'],
  ['dropped_invalid_flags', '非法 TCP 标志'],
  ['dropped_fragment', 'IP 分片'],
  ['dropped_invalid_packet', '畸形包'],
  ['dropped_bogon', '伪造源地址'],
  ['dropped_orphan_tcp', '无主 TCP 反射'],
  ['dropped_service_orphan', '服务端口随机源'],
  ['dropped_geo', '区域封禁丢包'],
]

const total = ref<XDPStats>({})
const perNode = ref<PerNode<XDPStats>[]>([])
const blocks = ref<XDPBlock[]>([])
const blockErrors = ref('')
const loadingStats = ref(false)
const loadingBlocks = ref(false)
const savingCfg = ref(false)
const savingBan = ref(false)
const cfgSaved = ref(false)
const banSaved = ref(false)
const q = ref('')
const busy = ref<Record<string, boolean>>({})

const cfg = reactive<XDPConfig>({
  syn_limit: 0,
  pps_limit: 0,
  udp_limit: 0,
  conn_limit: 0,
  enabled: 1,
  icmp_limit: 0,
  udp_dns_limit: 0,
  tcp_rst_limit: 0,
  fragment_drop: 0,
  invalid_flags_drop: 0,
  ack_limit: 0,
  fin_limit: 0,
  port_guard: 0,
  bogon_drop: 0,
  psh_ack_guard: 0,
  cpu_syn_limit: 0,
  orphan_tcp_drop: 0,
  service_orphan_drop: 0,
})
const ban = reactive<BanConfig>({ ladder: '', offender_ttl: '' })
const preview = ref<string[]>([])
const manual = reactive({ ip: '', minutes: 60 })

type NumKey = Exclude<keyof XDPConfig, never>
const LIMITS: Array<{ key: NumKey; label: string; hint: string }> = [
  { key: 'syn_limit', label: 'SYN 限速', hint: '单 IP 每秒 SYN 包' },
  {
    key: 'cpu_syn_limit',
    label: '单核 SYN 总量',
    // 这一项是「每包换一个伪造源」的 SYN 洪水的唯一闸门：per-IP 阈值对它永远碰不到。
    // 节点实际放行量 = 该值 × 收包队列数，安装时按 2 万/秒的预算除出来（依据见
    // internal/xdp 的 DefaultSynTotalBudget 注释），队列数在节点列表的 XDP 列里能看到。
    hint: '每 CPU 每秒放行多少个新建连接 SYN；节点总量 ≈ 该值 × 队列数，0 = 不限',
  },
  { key: 'pps_limit', label: 'PPS 限速', hint: '单 IP 每秒包数' },
  { key: 'conn_limit', label: '并发连接', hint: '单 IP 新建连接上限' },
  { key: 'udp_limit', label: 'UDP 限速', hint: '单 IP 每秒 UDP 包' },
  { key: 'udp_dns_limit', label: 'DNS 响应限速', hint: '源端口 53 的 UDP，防反射放大' },
  { key: 'icmp_limit', label: 'ICMP 限速', hint: '单 IP 每秒 ICMP' },
  { key: 'tcp_rst_limit', label: 'RST 限速', hint: '单 IP 每秒 RST' },
  { key: 'ack_limit', label: 'ACK 限速', hint: '只计无负载纯 ACK' },
  { key: 'fin_limit', label: 'FIN 限速', hint: '单 IP 每秒 FIN' },
]
const SWITCHES: Array<{ key: NumKey; label: string; hint: string; danger?: boolean }> = [
  { key: 'fragment_drop', label: '丢弃 IP 分片', hint: '正常 Web 流量几乎不分片' },
  { key: 'invalid_flags_drop', label: '丢弃非法 TCP 标志', hint: 'XMAS / NULL / SYN+FIN 等' },
  { key: 'bogon_drop', label: '丢弃伪造源地址', hint: '保留地址段作源的包' },
  { key: 'orphan_tcp_drop', label: '无主 TCP 反射过滤', hint: '丢弃内核 socket 表里不存在的连接回包' },
  { key: 'service_orphan_drop', label: '服务端口随机源过滤', hint: '80/443 上无连接的 ACK/RST/FIN 洪水' },
  { key: 'port_guard', label: '端口白名单', hint: '只拦非服务端口的纯 SYN', danger: true },
  { key: 'psh_ack_guard', label: 'PSH-ACK 守卫', hint: '只查服务端口的包', danger: true },
]

function reportPush(push: PushResult, okMsg: string) {
  const fails = pushFailures(push)
  if (fails.length) ElMessage.warning(`${okMsg}，但部分节点失败：${fails.join('；')}`)
  else ElMessage.success(okMsg)
}

const passed = computed(() => total.value.passed ?? 0)
const dropped = computed(() => DROP_LABELS.reduce((s, [k]) => s + (total.value[k] ?? 0), 0))
const drops = computed(() =>
  DROP_LABELS.map(([key, label]) => ({ key, label, value: total.value[key] ?? 0 })),
)
const maxDrop = computed(() => Math.max(1, ...drops.value.map((d) => d.value)))
const filteredBlocks = computed(() => {
  const kw = q.value.trim()
  return kw ? blocks.value.filter((b) => b.ip.includes(kw)) : blocks.value
})

async function loadStats() {
  loadingStats.value = true
  try {
    const r = await getXDPStats()
    total.value = r.total ?? {}
    perNode.value = r.nodes
  } catch (e) {
    ElMessage.error(errMessage(e, '加载 XDP 统计失败'))
  } finally {
    loadingStats.value = false
  }
}

async function loadBlocks() {
  loadingBlocks.value = true
  try {
    const r = await getXDPBlocklist()
    blocks.value = r.items
    blockErrors.value = nodeErrorsText(r.errors)
  } catch (e) {
    ElMessage.error(errMessage(e, '加载封禁列表失败'))
  } finally {
    loadingBlocks.value = false
  }
}

async function loadConfig() {
  try {
    const [c, b] = await Promise.all([getXDPConfig(), getBanConfig()])
    Object.assign(cfg, c.config)
    cfgSaved.value = c.saved
    Object.assign(ban, b.config)
    banSaved.value = b.saved
    preview.value = b.preview ?? []
  } catch (e) {
    ElMessage.error(errMessage(e, '加载 XDP 配置失败'))
  }
}

async function saveCfg() {
  if (cfg.port_guard || cfg.psh_ack_guard) {
    try {
      await ElMessageBox.confirm(
        '端口白名单 / PSH-ACK 守卫配置不当会丢掉源站回包，导致全站 504。确定开启？',
        '高风险开关',
        { type: 'warning', confirmButtonText: '仍然保存', cancelButtonText: '取消' },
      )
    } catch {
      return
    }
  }
  savingCfg.value = true
  try {
    const r = await putXDPConfig({ ...cfg })
    Object.assign(cfg, r.config)
    cfgSaved.value = true
    reportPush(r.push, 'XDP 配置已保存并下发')
  } catch (e) {
    ElMessage.error(errMessage(e, '保存失败'))
  } finally {
    savingCfg.value = false
  }
}

async function saveBan() {
  savingBan.value = true
  try {
    const r = await putBanConfig({ ladder: ban.ladder.trim(), offender_ttl: ban.offender_ttl.trim() })
    Object.assign(ban, r.config)
    banSaved.value = true
    reportPush(r.push, '封禁阶梯已保存并下发')
    preview.value = (await getBanConfig()).preview ?? []
  } catch (e) {
    ElMessage.error(errMessage(e, '保存失败'))
  } finally {
    savingBan.value = false
  }
}

async function unblock(row: XDPBlock) {
  busy.value[row.ip] = true
  try {
    const r = await unblockIP(row.ip, 'xdp')
    reportPush(r.push, `已解封 ${row.ip}`)
    await loadBlocks()
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
    const r = await blockIP(ip, 'xdp', manual.minutes)
    reportPush(r.push, `已在 XDP 层封禁 ${ip} ${manual.minutes} 分钟`)
    manual.ip = ''
    await loadBlocks()
  } catch (e) {
    ElMessage.error(errMessage(e, '封禁失败'))
  } finally {
    busy.value.__manual = false
  }
}

function refreshAll() {
  loadStats()
  loadBlocks()
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
        <h1>XDP 防御</h1>
        <p class="sub">网卡驱动层四层防护 · 仅显示本代理自己安装的节点</p>
      </div>
      <div class="actions">
        <el-button :loading="loadingStats || loadingBlocks" @click="refreshAll">刷新</el-button>
      </div>
    </div>

    <div class="stat-grid" v-loading="loadingStats && !perNode.length">
      <div class="stat ok">
        <div class="label">放行包</div>
        <div class="value">{{ formatNumber(passed) }}</div>
      </div>
      <div class="stat danger">
        <div class="label">丢弃包</div>
        <div class="value">{{ formatNumber(dropped) }}</div>
      </div>
      <div class="stat warn">
        <div class="label">XDP 封禁 IP</div>
        <div class="value">{{ formatNumber(blocks.length) }}</div>
      </div>
      <div class="stat">
        <div class="label">在线节点</div>
        <div class="value">
          {{ perNode.filter((n) => !n.error).length }}<small>/ {{ perNode.length }}</small>
        </div>
      </div>
    </div>

    <el-tabs type="border-card" class="tabs">
      <el-tab-pane label="丢包统计">
        <div class="drops">
          <div v-for="d in drops" :key="d.key" class="drop">
            <span class="dl">{{ d.label }}</span>
            <div class="track"><div class="fill" :style="{ width: `${(d.value / maxDrop) * 100}%` }"></div></div>
            <span class="dv mono">{{ formatNumber(d.value) }}</span>
          </div>
        </div>
        <div class="panel-title node-title"><span>节点明细</span></div>
        <el-table :data="perNode" size="small" empty-text="暂无节点">
          <el-table-column label="节点" min-width="160">
            <template #default="{ row }">
              <span class="dot" :class="row.error ? 'bad' : row.loaded === false ? 'off' : 'on'"></span>{{ row.node }}
            </template>
          </el-table-column>
          <el-table-column label="IP" width="150">
            <template #default="{ row }"><span class="mono">{{ row.ip }}</span></template>
          </el-table-column>
          <el-table-column label="XDP" width="90">
            <template #default="{ row }">
              <el-tag v-if="row.error" type="danger" size="small">离线</el-tag>
              <el-tag v-else-if="row.loaded === false" type="info" size="small">未加载</el-tag>
              <el-tag v-else type="success" size="small">运行中</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="放行" width="120" align="right">
            <template #default="{ row }">{{ formatNumber(row.stats?.passed) }}</template>
          </el-table-column>
          <el-table-column label="丢弃" width="120" align="right">
            <template #default="{ row }">
              {{ formatNumber(DROP_LABELS.reduce((s, [k]) => s + (row.stats?.[k] ?? 0), 0)) }}
            </template>
          </el-table-column>
          <el-table-column label="错误" min-width="160" show-overflow-tooltip>
            <template #default="{ row }"><span class="err">{{ row.error }}</span></template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="封禁列表">
        <el-alert v-if="blockErrors" type="warning" :closable="false" show-icon :title="`部分节点未返回：${blockErrors}`" />
        <div class="toolbar">
          <el-input v-model="q" placeholder="过滤 IP" clearable style="width: 200px" />
          <span class="grow"></span>
          <el-input v-model="manual.ip" placeholder="手动封禁 IP" style="width: 180px" @keyup.enter="manualBlock" />
          <el-input-number v-model="manual.minutes" :min="1" :max="43200" controls-position="right" style="width: 130px" />
          <span class="dim">分钟</span>
          <el-button type="danger" :loading="busy.__manual" :disabled="!manual.ip.trim()" @click="manualBlock">
            封禁
          </el-button>
        </div>
        <el-table v-loading="loadingBlocks" :data="filteredBlocks" size="small" empty-text="暂无封禁" max-height="560">
          <el-table-column label="IP" min-width="150">
            <template #default="{ row }"><span class="mono">{{ row.ip }}</span></template>
          </el-table-column>
          <el-table-column label="剩余" width="130" prop="remaining_time" sortable>
            <template #default="{ row }">{{ formatDuration(row.remaining_time) }}</template>
          </el-table-column>
          <el-table-column label="本次时长" width="120">
            <template #default="{ row }">{{ formatDuration(row.ban_duration) }}</template>
          </el-table-column>
          <el-table-column label="累犯" width="80" align="right" prop="offense_count" sortable>
            <template #default="{ row }">{{ row.offense_count ? `第 ${row.offense_count} 次` : '-' }}</template>
          </el-table-column>
          <el-table-column label="节点" min-width="140" show-overflow-tooltip>
            <template #default="{ row }">{{ row.nodes.join(', ') }}</template>
          </el-table-column>
          <el-table-column label="操作" width="80" fixed="right">
            <template #default="{ row }">
              <el-button link type="primary" :loading="busy[row.ip]" @click="unblock(row)">解封</el-button>
            </template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="防护配置">
        <el-alert
          v-if="!cfgSaved"
          type="info"
          :closable="false"
          show-icon
          title="当前显示的是默认值，保存后才会写入本代理配置并下发到你的全部节点。"
        />
        <el-form label-width="130px" @submit.prevent="saveCfg">
          <el-form-item label="启用 XDP">
            <el-switch v-model="cfg.enabled" :active-value="1" :inactive-value="0" />
          </el-form-item>
          <div class="grid">
            <el-form-item v-for="l in LIMITS" :key="l.key" :label="l.label">
              <el-input-number v-model="cfg[l.key]" :min="0" controls-position="right" />
              <div class="hint">{{ l.hint }}</div>
            </el-form-item>
          </div>
          <div class="grid">
            <el-form-item v-for="sw in SWITCHES" :key="sw.key" :label="sw.label">
              <el-switch v-model="cfg[sw.key]" :active-value="1" :inactive-value="0" />
              <div class="hint" :class="{ risky: sw.danger }">
                {{ sw.hint }}<template v-if="sw.danger"> · 可能丢掉源站回包导致 504，默认关闭</template>
              </div>
            </el-form-item>
          </div>
          <el-form-item>
            <el-button type="primary" native-type="submit" :loading="savingCfg">保存并下发</el-button>
          </el-form-item>
        </el-form>
      </el-tab-pane>

      <el-tab-pane label="封禁阶梯">
        <el-alert
          type="info"
          :closable="false"
          show-icon
          title="同一 IP 在记忆窗口内再次触发时按阶梯递增封禁时长；窗口必须大于最后一档，否则封顶档形同虚设。"
        />
        <el-form label-width="130px" class="ban-form" @submit.prevent="saveBan">
          <el-form-item label="时长阶梯">
            <el-input v-model="ban.ladder" class="mono" placeholder="1h,6h,24h（留空 = 默认）" />
          </el-form-item>
          <el-form-item label="累犯记忆窗口">
            <el-input v-model="ban.offender_ttl" class="mono" placeholder="48h（留空 = 默认）" />
          </el-form-item>
          <el-form-item label="当前生效">
            <div v-if="preview.length" class="preview">
              <el-tag v-for="p in preview" :key="p" size="small" effect="plain" class="mono">{{ p }}</el-tag>
            </div>
            <span v-else class="dim">默认阶梯 1h / 6h / 24h，窗口 48h</span>
            <span v-if="!banSaved" class="dim"> · 尚未保存过</span>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" native-type="submit" :loading="savingBan">保存并下发</el-button>
          </el-form-item>
        </el-form>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<style scoped>
.tabs {
  background: var(--panel);
  border-color: var(--line);
}
.drops {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(340px, 1fr));
  gap: 8px 24px;
  margin-bottom: 18px;
}
.drop {
  display: flex;
  align-items: center;
  gap: 10px;
  font-size: 13px;
}
.dl {
  width: 110px;
  color: var(--text-dim);
  flex-shrink: 0;
}
.track {
  flex: 1;
  height: 6px;
  border-radius: 3px;
  background: rgba(255, 255, 255, 0.05);
  overflow: hidden;
}
.track .fill {
  height: 100%;
  background: var(--danger);
}
.dv {
  width: 100px;
  text-align: right;
}
.node-title {
  margin-top: 4px;
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
.grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(380px, 1fr));
  column-gap: 16px;
}
.hint {
  width: 100%;
  font-size: 12px;
  line-height: 1.5;
  color: var(--text-dim);
}
.hint.risky {
  color: var(--warn);
}
.ban-form {
  max-width: 620px;
}
.preview {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}
.err {
  color: var(--danger);
}
</style>
