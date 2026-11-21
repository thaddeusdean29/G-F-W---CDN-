<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage } from 'element-plus'
import {
  blockIP,
  getGeoOptions,
  getGeoStats,
  getWAFBanned,
  getWAFConfig,
  getWAFStats,
  putWAFConfig,
  unblockIP,
} from '@/api/security'
import { ApiClientError } from '@/api/client'
import type {
  CapacityPressure,
  GeoOptionsResponse,
  GeoStatsResponse,
  GeoTenantNodeReading,
  PushResult,
  WAFBan,
  WAFCatalog,
  WAFHit,
  WAFNodeReading,
  WAFPolicy,
  WAFStatsResponse,
} from '@/api/types'
import {
  boostedRuleIds,
  effectiveRuleIds,
  levelRuleCounts,
  ruleDefault,
  versionLabel,
  wafLevels,
  wafModes,
} from '@/utils/waf'
import { counterRows } from '@/utils/geo'
import { countryName } from '@/utils/countries'
import { errMessage, formatDuration, formatNumber, formatTime, nodeErrorsText, pushFailures } from '@/utils/format'

// ── 封禁列表 ────────────────────────────────────────────────────────────────
const items = ref<WAFBan[]>([])
const banErrors = ref('')
// 封禁表的额度读数（各节点额度求和）。表打满后走的是"提前解除最快到期的一条"而不是
// "拒收新封禁"，这个取舍必须让运维看得见，否则封禁时长形同虚设却没人知道。
const capacity = ref<CapacityPressure | null>(null)
const loading = ref(false)
const q = ref('')
const busy = ref<Record<string, boolean>>({})
const form = reactive<{ ip: string; minutes: number; layer: 'waf' | 'all' }>({ ip: '', minutes: 60, layer: 'waf' })

// ── 托管规则配置 ────────────────────────────────────────────────────────────
const cfg = reactive<WAFPolicy>({
  enabled: true,
  mode: 'block',
  level: 'medium',
  sets: [],
  rules: {},
  rules_version: '',
  gray_percent: 0,
})
const catalog = ref<WAFCatalog | null>(null)
const versions = ref<string[]>([''])
const activeVersion = ref('')
const builtinVersion = ref('')
const saved = ref(false)
const loadingCfg = ref(false)
const saving = ref(false)
const ruleFilter = ref('')
const onlyEffective = ref(false)

// ── 节点读数（来自边缘定期上报，主控不回连节点）────────────────────────────
const stats = ref<WAFStatsResponse | null>(null)
const statErrors = ref('')
const loadingStats = ref(false)
const tab = ref('rules')

function reportPush(push: PushResult, okMsg: string) {
  const fails = pushFailures(push)
  if (fails.length) ElMessage.warning(`${okMsg}，但部分节点失败：${fails.join('；')}`)
  else ElMessage.success(okMsg)
}

async function loadBans() {
  loading.value = true
  try {
    const r = await getWAFBanned()
    items.value = r.items
    capacity.value = r.capacity ?? null
    banErrors.value = nodeErrorsText(r.errors)
  } catch (e) {
    ElMessage.error(errMessage(e, '加载 WAF 封禁列表失败'))
  } finally {
    loading.value = false
  }
}

function assignCfg(p: WAFPolicy) {
  cfg.enabled = p.enabled
  cfg.mode = p.mode
  cfg.level = p.level
  cfg.sets = [...(p.sets ?? [])]
  cfg.rules = { ...(p.rules ?? {}) }
  cfg.rules_version = p.rules_version ?? ''
  cfg.gray_percent = p.gray_percent ?? 0
}

async function loadConfig() {
  loadingCfg.value = true
  try {
    const r = await getWAFConfig()
    assignCfg(r.config)
    catalog.value = r.catalog
    versions.value = r.versions?.length ? r.versions : ['']
    activeVersion.value = r.active_version ?? ''
    builtinVersion.value = r.builtin_version ?? ''
    saved.value = r.saved
  } catch (e) {
    ElMessage.error(errMessage(e, '加载 WAF 配置失败'))
  } finally {
    loadingCfg.value = false
  }
}

async function loadStats() {
  loadingStats.value = true
  try {
    stats.value = await getWAFStats()
    statErrors.value = nodeErrorsText(stats.value.errors)
  } catch (e) {
    ElMessage.error(errMessage(e, '加载 WAF 节点读数失败'))
  } finally {
    loadingStats.value = false
  }
}

// 节点没回话时后端只填 error，其余字段全是零值。零值不等于"关着 / 0 条 / 不灰度"：
// 一台离线的节点要显示成未知，否则这张表会把"没上报"讲成"防护已关"。
const noReport = (row: WAFNodeReading) => !!row.error

// 后端 validateWAFPolicy 是"拒绝而不是纠正"：非法值一律 400 并逐字段给原因。
// 界面必须把原因原样摊开，否则改的人只看到一个"保存失败"。
const fieldLabels: Record<string, string> = {
  mode: '执行模式',
  level: '安全级别',
  sets: '规则集',
  rules: '单条规则',
  rules_version: '规则包版本',
  gray_percent: '灰度比例',
}

function saveError(e: unknown): string {
  if (e instanceof ApiClientError && e.code === 'validation_failed') {
    const fields = (e.details as { fields?: Record<string, string> } | undefined)?.fields
    if (fields) {
      return (
        '配置不合法：' +
        Object.entries(fields)
          .map(([k, v]) => `${fieldLabels[k] ?? k} ${v}`)
          .join('；')
      )
    }
  }
  return errMessage(e, '保存失败')
}

async function save() {
  saving.value = true
  try {
    const r = await putWAFConfig({
      enabled: cfg.enabled,
      mode: cfg.mode,
      level: cfg.level,
      sets: [...cfg.sets],
      rules: { ...cfg.rules },
      rules_version: cfg.rules_version,
      gray_percent: cfg.gray_percent,
    })
    assignCfg(r.config)
    saved.value = true
    await Promise.all([loadConfig(), loadStats()])
    const mine = effectiveRuleIds(catalog.value, r.config).length
    const theirs = r.effective?.length ?? mine
    // 面板与主控对"生效几条"算得不一致，就是两边的判定分叉了。
    // 这种时候继续显示面板自己算的数字等于做假账，必须当场报出来。
    if (mine !== theirs) {
      ElMessage.warning(
        `配置已下发，但面板算出生效 ${mine} 条、主控算出 ${theirs} 条：请把本页版本报给运维核对`,
      )
    } else {
      reportPush(r.push, `托管规则已保存并下发，当前执行 ${theirs} 条`)
    }
  } catch (e) {
    ElMessage.error(saveError(e))
  } finally {
    saving.value = false
  }
}

async function ban() {
  const ip = form.ip.trim()
  if (!ip) return
  busy.value.__form = true
  try {
    const r = await blockIP(ip, form.layer, form.minutes)
    reportPush(r.push, `已封禁 ${ip} ${form.minutes} 分钟`)
    form.ip = ''
    await loadBans()
  } catch (e) {
    ElMessage.error(errMessage(e, '封禁失败'))
  } finally {
    busy.value.__form = false
  }
}

async function unban(row: WAFBan) {
  busy.value[row.ip] = true
  try {
    const r = await unblockIP(row.ip, 'waf')
    reportPush(r.push, `已解封 ${row.ip}`)
    await loadBans()
  } catch (e) {
    ElMessage.error(errMessage(e, '解封失败'))
  } finally {
    busy.value[row.ip] = false
  }
}

// ── 区域规则（配置在域名上，这里只看全网执行情况）─────────────────────────
const router = useRouter()
// 和 WAF 读数同一个来源：节点定期上报。这一页不给编辑入口是刻意的——区域规则
// 按域名生效，编辑入口只有「域名 → 区域封禁」，两处都能改必然出现两个真相。
const geoStats = ref<GeoStatsResponse | null>(null)
const geoCap = ref<GeoOptionsResponse | null>(null)
const loadingGeo = ref(false)
const geoErrors = ref('')

async function loadGeo() {
  loadingGeo.value = true
  try {
    const [statsR, capR] = await Promise.all([
      getGeoStats(),
      // 能力清单失败不该让读数整块消失，所以单独 catch 成 null。
      getGeoOptions().catch(() => null),
    ])
    geoStats.value = statsR
    geoCap.value = capR
    geoErrors.value = nodeErrorsText(statsR.errors)
  } catch (e) {
    ElMessage.error(errMessage(e, '加载区域规则读数失败'))
  } finally {
    loadingGeo.value = false
  }
}

// 节点没回话时后端只填 error，其余字段全是零值。零值不等于"没装载 / 0 条 / 没丢包"：
// 一台离线的节点要显示成未知，否则这张表会把"没上报"讲成"封禁没生效"。
const geoNoReport = (row: GeoTenantNodeReading) => !!row.error

// 首次切到这一页才请求：区域封禁多半是关着的，不该让每次打开 WAF 页都多两个请求。
function onTabChange(name: string | number) {
  if (name === 'geo' && !geoStats.value && !loadingGeo.value) loadGeo()
}

const geoMismatch = computed(() => (geoStats.value?.nodes ?? []).filter((n) => n.matches_plan_fingerprint === false))
const geoL4Bad = computed(() => (geoStats.value?.nodes ?? []).filter((n) => n.l4_error))
const geoReportSecs = computed(() => geoStats.value?.report_interval_secs ?? 10)

// 一句话结论：这一页最先要回答的是"我配的到底在不在跑"。
const geoVerdict = computed(() => {
  const s = geoStats.value
  if (!s) return ''
  if (!s.scope_enabled) return '平台总闸未开启：所有域名的区域规则都不会执行，下面的数字只是记账。'
  if (!s.db_ready) return '平台已开启，但国家级地理库未就位：节点装不上前缀表，规则目前不会拦任何请求。'
  if (!s.expected_total) return '当前没有需要编译的国家：所有域名的区域规则都没启用，或清单为空。'
  if (geoMismatch.value.length) {
    return `有 ${geoMismatch.value.length} 台节点跑的表和本页要它跑的不是同一张，来自那些节点的流量按旧表判定。`
  }
  return `表已就位：${formatNumber(s.expected_total)} 条前缀，覆盖 ${s.expected_countries.length} 个国家。`
})

const geoVerdictLevel = computed(() => {
  const s = geoStats.value
  if (!s) return 'info'
  if (!s.scope_enabled || !s.db_ready || geoMismatch.value.length) return 'warning'
  return 'success'
})

// 平台划的可选范围：租户改不了它，但必须看得见它，否则"这个国家选不到"
// 会被当成面板的 bug 报上来。
const geoScopeText = computed(() => {
  const c = geoCap.value
  if (!c) return ''
  if (!c.selectable.length) return `平台未限制可选国家，本代理可用 ${c.catalog.length} 个`
  const tail = c.unavailable.length ? `，其中 ${c.unavailable.length} 个在地理库里没有网段，选了也拦不到` : ''
  return `平台开放的可选国家 ${c.selectable.length} 个${tail}`
})

function refreshAll() {
  loadBans()
  loadStats()
  // 没进过区域规则这一页就不补这两个请求；进过之后刷新按钮要连它一起刷。
  if (geoStats.value || tab.value === 'geo') loadGeo()
}

// ── 派生读数 ────────────────────────────────────────────────────────────────
const boosted = computed(() => boostedRuleIds(catalog.value, cfg.sets))
const effectiveIds = computed(() => effectiveRuleIds(catalog.value, cfg))
const effectiveSet = computed(() => new Set(effectiveIds.value))
const levelCounts = computed(() => levelRuleCounts(catalog.value))
const modeHint = computed(() => wafModes.find((m) => m.value === cfg.mode)?.hint ?? '')
const levelHint = computed(() => wafLevels.find((l) => l.value === cfg.level)?.hint ?? '')

const ruleRows = computed(() => {
  const kw = ruleFilter.value.trim().toLowerCase()
  let rows = catalog.value?.rules ?? []
  if (kw) {
    rows = rows.filter(
      (r) =>
        r.id.toLowerCase().includes(kw) ||
        r.name.toLowerCase().includes(kw) ||
        (r.description ?? '').toLowerCase().includes(kw),
    )
  }
  if (onlyEffective.value) rows = rows.filter((r) => effectiveSet.value.has(r.id))
  return rows
})

const hitsByRule = computed(() => {
  const m: Record<string, WAFHit> = {}
  for (const h of stats.value?.hits ?? []) m[h.rule] = h
  return m
})

// 单条规则三态：跟随级别 / 强制开启 / 强制关闭。后端 rules 里没这个 id 就是"跟随"。
function ruleMode(id: string): 'auto' | 'on' | 'off' {
  const v = cfg.rules[id]
  if (v === undefined) return 'auto'
  return v ? 'on' : 'off'
}

function setRuleMode(id: string, m: 'auto' | 'on' | 'off') {
  if (m === 'auto') delete cfg.rules[id]
  else cfg.rules[id] = m === 'on'
  // delete 改的是对象上的键，reactive 会捕获；这里显式换引用只为让依赖 rules 的
  // computed 在任何版本下都重算一次。
  cfg.rules = { ...cfg.rules }
}

const overrideCount = computed(() => Object.keys(cfg.rules).length)
const mismatchNodes = computed(() => (stats.value?.nodes ?? []).filter((n) => n.matches_policy === false))
// 只有明确报回"一致"的才算一致：没上报过的节点不能算成功，否则这一列会在
// 节点掉线时反而变成绿色。
const consistentNodes = computed(() => (stats.value?.nodes ?? []).filter((n) => n.matches_policy === true).length)
const pinMissingNodes = computed(() => (stats.value?.nodes ?? []).filter((n) => n.pin_missing))
const unreadNodes = computed(() => (stats.value?.nodes ?? []).filter((n) => !!n.error))
const nodeCount = computed(() => (stats.value?.nodes ?? []).length)

const filtered = computed(() => {
  const kw = q.value.trim()
  return kw ? items.value.filter((i) => i.ip.includes(kw)) : items.value
})

const banDegraded = computed(
  () => !!capacity.value && (capacity.value.early_unbanned > 0 || capacity.value.dropped > 0),
)

onMounted(() => {
  loadBans()
  loadConfig()
  loadStats()
})
</script>

<template>
  <div class="page">
    <div class="page-header">
      <div>
        <h1>WAF</h1>
        <p class="sub">托管规则与七层封禁 · 配置与封禁都会同步到本代理的全部节点</p>
      </div>
      <div class="actions">
        <el-button :loading="loading || loadingStats || loadingCfg" @click="refreshAll">刷新</el-button>
      </div>
    </div>

    <div class="stat-grid">
      <div class="stat" :class="cfg.enabled ? 'ok' : 'warn'">
        <div class="label">托管规则执行</div>
        <div class="value">
          {{ cfg.enabled ? `${formatNumber(effectiveIds.length)} 条` : '已关闭' }}
          <small v-if="cfg.enabled"> / {{ formatNumber(catalog?.rules.length ?? 0) }} 条可选</small>
        </div>
      </div>
      <div class="stat" :class="cfg.mode === 'observe' ? 'warn' : ''">
        <div class="label">执行模式</div>
        <div class="value">{{ cfg.mode === 'observe' ? '观察' : '拦截' }}</div>
      </div>
      <div class="stat" :class="(stats?.total.blocked ?? 0) > 0 ? 'danger' : ''">
        <div class="label">观察命中 / 已拦截</div>
        <div class="value">
          {{ formatNumber(stats?.total.observe) }} / {{ formatNumber(stats?.total.blocked) }}
        </div>
      </div>
      <div class="stat" :class="mismatchNodes.length || unreadNodes.length ? 'danger' : 'ok'">
        <div class="label">策略一致的节点</div>
        <div class="value">
          {{ nodeCount ? `${formatNumber(consistentNodes)} / ${formatNumber(nodeCount)}` : '—' }}
        </div>
      </div>
      <div class="stat danger">
        <div class="label">WAF 封禁 IP</div>
        <div class="value">{{ formatNumber(items.length) }}</div>
      </div>
      <div v-if="capacity" class="stat" :class="banDegraded ? 'danger' : 'ok'">
        <div class="label">封禁额度占用</div>
        <div class="value">{{ formatNumber(capacity.size) }} / {{ formatNumber(capacity.limit) }}</div>
      </div>
      <div v-if="capacity" class="stat" :class="banDegraded ? 'danger' : ''">
        <div class="label">为腾位提前解封</div>
        <div class="value">{{ formatNumber(capacity.early_unbanned) }} 次</div>
      </div>
    </div>

    <el-alert
      v-if="mismatchNodes.length"
      type="error"
      :closable="false"
      show-icon
      title="这些节点上实际执行的策略与面板不一致"
    >
      <div class="small">{{ mismatchNodes.map((n) => n.node).join('、') }}</div>
      <div class="small dim">
        常见原因：保存时该节点不在线（配置没能下发）、它的 cdnedge 版本过旧没有托管规则配置入口。
        节点恢复在线后会自动补发；旧版本要先升级。
      </div>
    </el-alert>

    <el-alert v-if="pinMissingNodes.length" type="warning" :closable="false" show-icon title="固定到这台节点的规则包版本不存在">
      <div class="small">
        {{ pinMissingNodes.map((n) => `${n.node}（固定 ${n.rules_version}，本机活动包 ${n.active_version || '未知'}）`).join('；') }}
      </div>
      <div class="small dim">
        这些节点已回落到自己的活动包继续防护，不会因为没有新版本就不跑规则；但你以为锁定的那一版并没有在跑。
      </div>
    </el-alert>

    <el-alert v-if="banDegraded" type="error" :closable="false" show-icon title="封禁表额度已被攻击用尽">
      <div class="small">
        这台代理上累计提前解除 {{ formatNumber(capacity?.early_unbanned) }} 条仍在封禁期的 IP，放弃新封禁
        {{ formatNumber(capacity?.dropped) }} 次。表满时系统选择"放进去一个正在攻击的 IP、放走一个最快到期的"，
        但这意味着封禁时长已经不再可信。
      </div>
      <div class="small dim">处置方向：缩短 CC/WAF 的默认封禁时长，或提高节点内存后调大 maxBlockedIPs。</div>
    </el-alert>

    <el-tabs v-model="tab" type="border-card" class="tabs" @tab-change="onTabChange">
      <el-tab-pane label="托管规则" name="rules">
        <el-alert
          v-if="!saved"
          type="info"
          :closable="false"
          show-icon
          title="当前是出厂默认策略（全量规则、拦截、中级别）。保存后才会写入本代理并下发到你的全部节点。"
        />
        <div v-loading="loadingCfg">
          <el-form label-width="120px" class="cfg-form" @submit.prevent="save">
            <el-form-item label="启用托管规则">
              <el-switch v-model="cfg.enabled" />
              <span class="hint">
                只控制托管规则与级别。IP 封禁、UA 校验、上传校验与 ACME 限速不受这个开关影响。
              </span>
            </el-form-item>

            <el-form-item label="执行模式">
              <el-radio-group v-model="cfg.mode">
                <el-radio-button v-for="m in wafModes" :key="m.value" :value="m.value">{{ m.label }}</el-radio-button>
              </el-radio-group>
              <span class="hint">{{ modeHint }}</span>
            </el-form-item>

            <el-form-item label="安全级别">
              <el-select v-model="cfg.level" style="width: 220px">
                <el-option
                  v-for="l in wafLevels"
                  :key="l.value"
                  :value="l.value"
                  :label="`${l.label}（${levelCounts[l.value]} 条）`"
                />
              </el-select>
              <span class="hint">{{ levelHint }}</span>
            </el-form-item>

            <el-form-item label="规则包版本">
              <el-select v-model="cfg.rules_version" style="width: 300px">
                <el-option
                  v-for="v in versions"
                  :key="v || '__follow__'"
                  :value="v"
                  :label="versionLabel(v, activeVersion)"
                />
              </el-select>
              <span class="hint">
                固定版本后灰度比例不生效。出厂包 {{ builtinVersion || '未知'
                }}；列表只包含节点上真装得着的版本，写别的会被主控拒绝。
              </span>
            </el-form-item>

            <el-form-item label="灰度比例">
              <el-input-number
                v-model="cfg.gray_percent"
                :min="0"
                :max="99"
                controls-position="right"
                :disabled="!!cfg.rules_version"
              />
              <span class="hint">
                % 的域名（按 Host 稳定哈希）改跑旧档规则包，用于新包上线后对照误报；
                {{ cfg.rules_version ? '当前已固定版本，灰度不生效。' : '0 = 全部域名用活动包。' }}
              </span>
            </el-form-item>

            <el-form-item label="规则集">
              <div class="sets">
                <el-checkbox-group v-model="cfg.sets">
                  <el-checkbox v-for="s in catalog?.sets ?? []" :key="s.id" :value="s.id">
                    {{ s.name }}
                    <span class="dim small">（{{ s.rules.length }} 条）</span>
                    <el-tag v-if="s.recommended" size="small" type="success" effect="plain">推荐</el-tag>
                  </el-checkbox>
                </el-checkbox-group>
                <div v-if="!(catalog?.sets ?? []).length" class="dim">这份规则包没有分组。</div>
                <div class="dim small">
                  勾选只会把组内规则加进执行集合，不会关掉级别本身要跑的规则。
                </div>
              </div>
            </el-form-item>

            <el-form-item>
              <el-button type="primary" native-type="submit" :loading="saving">保存并下发</el-button>
              <el-button :disabled="saving" @click="loadConfig">放弃改动重新载入</el-button>
              <span class="hint">
                当前配置下执行 {{ formatNumber(effectiveIds.length) }} 条，其中
                {{ formatNumber(overrideCount) }} 条是单条手动指定。
              </span>
            </el-form-item>
          </el-form>

          <div class="panel-title">
            <span>单条规则</span>
            <div class="filters">
              <el-input v-model="ruleFilter" placeholder="过滤 id / 名称 / 说明" size="small" clearable style="width: 220px" />
              <el-checkbox v-model="onlyEffective" size="small">只看执行中的</el-checkbox>
            </div>
          </div>
          <el-table :data="ruleRows" size="small" empty-text="规则包为空" max-height="560">
            <el-table-column label="规则" min-width="220">
              <template #default="{ row }">
                <div class="mono">{{ row.id }}</div>
                <div>{{ row.name }}</div>
                <div v-if="row.description" class="dim small">{{ row.description }}</div>
              </template>
            </el-table-column>
            <el-table-column label="档位" width="70" align="right" prop="tier" sortable />
            <el-table-column label="检查位置" min-width="140" show-overflow-tooltip>
              <template #default="{ row }">
                <span class="mono dim">{{ (row.scopes ?? []).join('、') || '—' }}</span>
              </template>
            </el-table-column>
            <el-table-column label="级别判定" width="100">
              <template #default="{ row }">
                <el-tag size="small" :type="ruleDefault(row, cfg.level, boosted) ? 'warning' : 'info'" effect="plain">
                  {{ ruleDefault(row, cfg.level, boosted) ? '该跑' : '不跑' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="本代理覆盖" width="150">
              <template #default="{ row }">
                <el-select
                  :model-value="ruleMode(row.id)"
                  size="small"
                  @update:model-value="(v: 'auto' | 'on' | 'off') => setRuleMode(row.id, v)"
                >
                  <el-option value="auto" label="跟随级别" />
                  <el-option value="on" label="强制开启" />
                  <el-option value="off" label="强制关闭" />
                </el-select>
              </template>
            </el-table-column>
            <el-table-column label="实际执行" width="100">
              <template #default="{ row }">
                <el-tag size="small" :type="effectiveSet.has(row.id) ? 'success' : 'info'" effect="dark">
                  {{ effectiveSet.has(row.id) ? '执行' : '跳过' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column label="命中（观察 / 拦截）" width="170" align="right">
              <template #default="{ row }">
                <span v-if="hitsByRule[row.id]">
                  {{ formatNumber(hitsByRule[row.id].observe) }} / {{ formatNumber(hitsByRule[row.id].blocked) }}
                </span>
                <span v-else class="dim">—</span>
              </template>
            </el-table-column>
          </el-table>
        </div>
      </el-tab-pane>

      <el-tab-pane label="节点执行情况" name="stats">
        <el-alert v-if="statErrors" type="warning" :closable="false" show-icon :title="`部分节点未返回：${statErrors}`" />
        <div class="toolbar">
          <span class="dim">
            数据来自节点定期上报（约 10 秒一轮），刚保存的配置不会立刻在下面变。
          </span>
          <span class="grow"></span>
          <el-button :loading="loadingStats" @click="loadStats">重新读取</el-button>
        </div>
        <el-table v-loading="loadingStats && !stats" :data="stats?.nodes ?? []" size="small" empty-text="暂无节点">
          <el-table-column label="节点" min-width="150">
            <template #default="{ row }">
              <span class="dot" :class="row.error ? 'bad' : row.matches_policy === false ? 'off' : 'on'"></span>
              {{ row.node }}
            </template>
          </el-table-column>
          <el-table-column label="IP" width="140">
            <template #default="{ row }"><span class="mono">{{ row.ip }}</span></template>
          </el-table-column>
          <el-table-column label="开关" width="80">
            <template #default="{ row }">
              <span v-if="noReport(row)" class="dim">未知</span>
              <el-tag v-else size="small" :type="row.enabled ? 'success' : 'info'" effect="plain">
                {{ row.enabled ? '启用' : '关闭' }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="模式 / 级别" width="120">
            <template #default="{ row }">
              <span v-if="noReport(row)" class="dim">未知</span>
              <span v-else>
                {{ row.mode === 'observe' ? '观察' : row.mode === 'block' ? '拦截' : '—' }} /
                {{ wafLevels.find((l) => l.value === row.level)?.label ?? '—' }}
              </span>
            </template>
          </el-table-column>
          <el-table-column label="执行条数" width="90" align="right">
            <template #default="{ row }">
              <span v-if="noReport(row)" class="dim">未知</span>
              <span v-else>{{ formatNumber(row.effective_rules) }}</span>
            </template>
          </el-table-column>
          <el-table-column label="活动包 / 旧档" min-width="180">
            <template #default="{ row }">
              <span v-if="noReport(row)" class="dim">未知</span>
              <template v-else>
                <span class="mono">{{ row.active_version || '—' }}</span>
                <div class="dim small">旧档 {{ row.previous_version || '无' }}</div>
              </template>
            </template>
          </el-table-column>
          <el-table-column label="灰度 / 固定" width="120">
            <template #default="{ row }">
              <span v-if="noReport(row)" class="dim">未知</span>
              <div v-else-if="row.rules_version">
                固定 <span class="mono">{{ row.rules_version }}</span>
                <el-tag v-if="row.pin_missing" size="small" type="danger" effect="dark">本机没有</el-tag>
              </div>
              <div v-else class="dim">{{ row.gray_percent ? `${row.gray_percent}% 走旧档` : '不灰度' }}</div>
            </template>
          </el-table-column>
          <el-table-column label="观察 / 拦截" width="140" align="right">
            <template #default="{ row }">
              <span v-if="noReport(row)" class="dim">未知</span>
              <span v-else>{{ formatNumber(row.observe) }} / {{ formatNumber(row.blocked) }}</span>
            </template>
          </el-table-column>
          <el-table-column label="与面板一致" width="110">
            <template #default="{ row }">
              <el-tag v-if="row.error" size="small" type="info" effect="plain">未上报</el-tag>
              <el-tag v-else-if="row.matches_policy" size="small" type="success" effect="dark">一致</el-tag>
              <el-tag v-else-if="row.matches_policy === false" size="small" type="danger" effect="dark">不一致</el-tag>
              <span v-else class="dim">未知</span>
            </template>
          </el-table-column>
          <el-table-column label="上报时间" width="170">
            <template #default="{ row }">{{ formatTime(row.reported_at) }}</template>
          </el-table-column>
          <el-table-column label="错误" min-width="160" show-overflow-tooltip>
            <template #default="{ row }"><span class="err">{{ row.error }}</span></template>
          </el-table-column>
        </el-table>

        <div class="panel-title">
          <span>规则命中（各节点求和）</span>
          <span class="dim small">
            共 {{ formatNumber(stats?.total.rules) }} 条规则产生过命中；观察模式的命中不会拦截。
          </span>
        </div>
        <el-table :data="stats?.hits ?? []" size="small" empty-text="暂无命中" max-height="420">
          <el-table-column label="规则" min-width="200">
            <template #default="{ row }">
              <span class="mono">{{ row.rule }}</span>
              <span v-if="row.name" class="dim"> · {{ row.name }}</span>
            </template>
          </el-table-column>
          <el-table-column label="观察命中" width="110" align="right" prop="observe" sortable>
            <template #default="{ row }">{{ formatNumber(row.observe) }}</template>
          </el-table-column>
          <el-table-column label="已拦截" width="110" align="right" prop="blocked" sortable>
            <template #default="{ row }">{{ formatNumber(row.blocked) }}</template>
          </el-table-column>
        </el-table>
      </el-tab-pane>

      <el-tab-pane label="区域规则" name="geo">
        <div v-loading="loadingGeo && !geoStats" class="geo-wrap">
          <el-alert
            v-if="geoErrors"
            type="warning"
            :closable="false"
            show-icon
            :title="`部分节点未返回：${geoErrors}`"
            class="geo-alert"
          />
          <el-alert v-if="geoVerdict" :type="geoVerdictLevel" :closable="false" show-icon :title="geoVerdict" class="geo-alert" />
          <el-alert
            v-if="geoCap?.note"
            type="info"
            :closable="false"
            show-icon
            :title="geoCap.note"
            class="geo-alert"
          />

          <div class="toolbar">
            <span class="dim">{{ geoScopeText || '国家清单还没读到，点右侧的重新读取。' }}</span>
            <span class="grow"></span>
            <el-button @click="router.push('/domains')">去域名配置</el-button>
            <el-button :loading="loadingGeo" @click="loadGeo">重新读取</el-button>
          </div>

          <p class="hint">
            区域规则按域名配置（域名 → 区域封禁），这一页只显示全网执行情况。
            数据来自节点定期上报（约 {{ geoReportSecs }} 秒一轮），刚保存的规则不会立刻在下面变。
          </p>

          <div class="geo-counters">
            <div v-for="c in counterRows" :key="c.key" class="geo-counter">
              <div class="k">{{ c.label }}</div>
              <div class="v">{{ formatNumber(geoStats?.counters?.[c.key] ?? 0) }}</div>
              <div class="hint">{{ c.hint }}</div>
            </div>
          </div>

          <div class="panel-title">
            <span>按国家（各节点求和）</span>
            <span class="dim small">观察模式下的「命中未拦」，就是开拦之后会拦下的次数。</span>
          </div>
          <el-table :data="geoStats?.countries ?? []" size="small" empty-text="暂无国家命中" max-height="360">
            <el-table-column label="国家" min-width="180">
              <template #default="{ row }">
                <span class="mono">{{ row.country }}</span>
                <span class="dim"> · {{ countryName(row.country) }}</span>
              </template>
            </el-table-column>
            <el-table-column label="命中未拦" width="120" align="right" prop="observe" sortable>
              <template #default="{ row }">{{ formatNumber(row.observe) }}</template>
            </el-table-column>
            <el-table-column label="已拦下" width="110" align="right" prop="blocked" sortable>
              <template #default="{ row }">{{ formatNumber(row.blocked) }}</template>
            </el-table-column>
            <el-table-column label="放行" width="110" align="right" prop="pass" sortable>
              <template #default="{ row }">{{ formatNumber(row.pass) }}</template>
            </el-table-column>
          </el-table>

          <div class="panel-title">
            <span>节点</span>
            <span class="dim small">
              「与面板一致」比的是节点实跑的前缀表指纹：下发时不在线、或 cdnedge 版本太旧不吃这张表的节点，只有这一列能看出来。
            </span>
          </div>
          <el-table :data="geoStats?.nodes ?? []" size="small" empty-text="暂无节点">
            <el-table-column label="节点" min-width="150">
              <template #default="{ row }">
                <span
                  class="dot"
                  :class="row.error ? 'bad' : row.matches_plan_fingerprint === false ? 'off' : 'on'"
                ></span>
                {{ row.node }}
              </template>
            </el-table-column>
            <el-table-column label="IP" width="140">
              <template #default="{ row }"><span class="mono">{{ row.ip }}</span></template>
            </el-table-column>
            <el-table-column label="实跑的表" min-width="200">
              <template #default="{ row }">
                <span v-if="geoNoReport(row)" class="dim">未知</span>
                <template v-else>
                  <div v-if="row.loaded">
                    <span class="mono">{{ row.fingerprint || '—' }}</span>
                    <span class="dim small"> · {{ formatNumber(row.total) }} 条</span>
                  </div>
                  <span v-else class="dim">未装载</span>
                  <div v-if="row.table_error" class="err small">{{ row.table_error }}</div>
                </template>
              </template>
            </el-table-column>
            <el-table-column label="与面板一致" width="110">
              <template #default="{ row }">
                <el-tag v-if="row.error" size="small" type="info" effect="plain">未上报</el-tag>
                <el-tag v-else-if="row.matches_plan_fingerprint" size="small" type="success" effect="dark">一致</el-tag>
                <el-tag v-else-if="row.matches_plan_fingerprint === false" size="small" type="danger" effect="dark">
                  不一致
                </el-tag>
                <span v-else class="dim">未知</span>
              </template>
            </el-table-column>
            <el-table-column label="四层丢包" min-width="190">
              <template #default="{ row }">
                <span v-if="geoNoReport(row)" class="dim">未知</span>
                <template v-else>
                  <el-tag size="small" :type="row.l4_armed ? 'success' : 'info'" effect="plain">
                    {{ row.l4_armed ? '已挂载' : '未挂载' }}
                  </el-tag>
                  <div class="dim small">
                    主控期望 {{ row.l4_want ? '装载' : '不装' }} · 已丢包 {{ formatNumber(row.l4_dropped) }}
                  </div>
                  <div v-if="row.l4_error" class="err small">{{ row.l4_error }}</div>
                </template>
              </template>
            </el-table-column>
            <el-table-column label="上报时间" width="170">
              <template #default="{ row }">{{ formatTime(row.reported_at) }}</template>
            </el-table-column>
            <el-table-column label="错误" min-width="160" show-overflow-tooltip>
              <template #default="{ row }"><span class="err">{{ row.error }}</span></template>
            </el-table-column>
          </el-table>

          <div v-if="geoL4Bad.length" class="hint warn">
            有 {{ geoL4Bad.length }} 台节点的四层丢包报错：域名级的七层 403 照常执行，但这台节点不会在网络层丢掉封禁国家的包。
          </div>
        </div>
      </el-tab-pane>

      <el-tab-pane label="封禁列表" name="bans">
        <el-alert v-if="banErrors" type="warning" :closable="false" show-icon :title="`部分节点未返回：${banErrors}`" />
        <div class="panel-title">
          <span>手动封禁</span>
        </div>
        <el-form inline @submit.prevent="ban">
          <el-form-item label="IP">
            <el-input v-model="form.ip" placeholder="1.2.3.4" style="width: 200px" />
          </el-form-item>
          <el-form-item label="时长（分钟）">
            <el-input-number v-model="form.minutes" :min="1" :max="43200" controls-position="right" />
          </el-form-item>
          <el-form-item label="范围">
            <el-select v-model="form.layer" style="width: 160px">
              <el-option value="waf" label="仅 WAF（七层）" />
              <el-option value="all" label="WAF + XDP" />
            </el-select>
          </el-form-item>
          <el-form-item>
            <el-button type="danger" native-type="submit" :loading="busy.__form" :disabled="!form.ip.trim()">
              封禁
            </el-button>
          </el-form-item>
        </el-form>

        <p class="hint">
          封禁当场下发到全部节点并立刻生效；下面这张表和上面的额度数字读的是节点定期上报（约 10 秒一轮），
          刚封的 IP 要等下一轮上报才会出现，看不到就按「刷新」重读。
        </p>

        <div class="panel-title">
          <span>封禁列表</span>
          <el-input v-model="q" placeholder="过滤 IP" clearable size="small" style="width: 180px" />
        </div>
        <el-table v-loading="loading" :data="filtered" size="small" empty-text="暂无封禁">
          <el-table-column label="IP" min-width="160">
            <template #default="{ row }"><span class="mono">{{ row.ip }}</span></template>
          </el-table-column>
          <el-table-column label="剩余" width="140" prop="remaining" sortable>
            <template #default="{ row }">{{ row.remaining > 0 ? formatDuration(row.remaining) : '永久' }}</template>
          </el-table-column>
          <el-table-column label="到期时间" width="190">
            <template #default="{ row }">{{ formatTime(row.expires_at) }}</template>
          </el-table-column>
          <el-table-column label="节点" min-width="160" show-overflow-tooltip>
            <template #default="{ row }">{{ row.nodes.join(', ') }}</template>
          </el-table-column>
          <el-table-column label="操作" width="80" fixed="right">
            <template #default="{ row }">
              <el-button link type="primary" :loading="busy[row.ip]" @click="unban(row)">解封</el-button>
            </template>
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
.cfg-form {
  max-width: 760px;
}
.hint {
  margin-left: 10px;
  font-size: 12px;
  color: var(--text-dim);
}
.sets {
  display: flex;
  flex-direction: column;
  gap: 2px;
}
.filters {
  display: flex;
  align-items: center;
  gap: 10px;
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
.err {
  color: var(--danger);
}
.geo-wrap {
  min-height: 140px;
}
.geo-alert {
  margin-bottom: 10px;
}
.geo-wrap .hint {
  margin-left: 0;
}
.geo-counters {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 10px;
  margin: 4px 0 20px;
}
.geo-counter {
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 10px 12px;
  background: var(--panel-2);
}
.geo-counter .k {
  font-size: 12px;
  color: var(--text-dim);
}
.geo-counter .v {
  font-size: 20px;
  font-weight: 600;
  font-variant-numeric: tabular-nums;
}
.geo-counter .hint {
  margin-top: 4px;
  line-height: 1.5;
}
.hint.warn {
  color: var(--el-color-warning, #e6a23c);
  margin-top: 10px;
}
</style>
