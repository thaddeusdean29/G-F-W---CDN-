<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { getGeoScope, listGeoNodes, pushGeoScope, putGeoScope } from '@/api/geoAdmin'
import { ApiClientError } from '@/api/client'
import GeoPolicyForm from '@/components/GeoPolicyForm.vue'
import type {
  GeoAdminNodeReading,
  GeoAdminSummary,
  GeoDBReading,
  GeoPlanView,
  GeoPushSummary,
  GeoScope,
} from '@/api/types'
import { counterRows, formatBytes, geoPolicyIssues } from '@/utils/geo'
import { countryLabel, countryName, sortByCountry, toCodes } from '@/utils/countries'
import { formatNumber, formatTime } from '@/utils/format'

// 平台级的区域封禁页：三样东西都只在这里改——能力总闸、租可选范围、整节点的四层丢包。
//
// 域名的区域规则不在这一页（在「代理管理」之外，由每个代理自己在域名上配），
// 这一页决定的是"这件事在平台上开不开、能开多大、以及要不要在网络层直接丢包"。
// 保存会立刻重算前缀表并下发全部启用节点，所以逐节点结果必须摊开：
// 接口 200 只说明主控存下了，不说明任何一台节点真的开始丢包。

const scope = reactive<GeoScope>({ enabled: false, selectable: [], node: { enabled: false, mode: 'observe', action: 'deny', countries: [], exceptions: [] } })
const saved = ref(false)
const plan = ref<GeoPlanView | null>(null)
const db = ref<GeoDBReading | null>(null)
const readings = ref<GeoAdminSummary | null>(null)
const nodes = ref<GeoAdminNodeReading[]>([])
const expected = reactive({ fingerprint: '', total: 0 })
const nodeNotes = ref<string[]>([])

const loading = ref(false)
const loadingNodes = ref(false)
const saving = ref(false)
const pushing = ref(false)
const loadError = ref('')
const pushResult = ref<GeoPushSummary | null>(null)

const catalog = computed(() => sortByCountry(db.value?.countries ?? []))
const catalogText = computed(() => {
  const n = catalog.value.length
  if (!n) return '库里读不出国家目录'
  return `${n} 个国家有网段`
})

// 可选范围的选择框：空 = 不限。这里用全量目录当选项（管理员自己不受范围限制），
// 范围只约束租户能挑哪些，见 internal/geo/policy.go 的 CanSelect。
const picked = computed({
  get: () => scope.selectable,
  set: (v) => {
    scope.selectable = toCodes(v as string[])
  },
})

const nodeIssues = computed(() => geoPolicyIssues(scope.node, { denyOnly: true }))
const blockingIssues = computed(() => {
  if (!scope.enabled && !scope.node.enabled) return []
  if (!db.value?.ready) return ['国家级地理库未就位，开不了区域封禁：装不出前缀表就没有任何判决依据']
  return nodeIssues.value
})

const mismatchNodes = computed(() => nodes.value.filter((n) => n.matches_plan_fingerprint === false))
const l4BadNodes = computed(() => nodes.value.filter((n) => !!n.l4_error))
const silentNodes = computed(() => nodes.value.filter((n) => !!n.error))
const l4ArmedNodes = computed(() => nodes.value.filter((n) => n.l4_armed))
const l4MismatchNodes = computed(() => nodes.value.filter((n) => n.l4_matches === false))

// 一句话结论。顺序不能换：库没就位时其它数字全是假象。
const verdict = computed(() => {
  if (!db.value?.ready) {
    return {
      level: 'error' as const,
      text:
        '国家级地理库未就位：主控编不出前缀表，任何区域规则都不会生效。需要安装 ' +
        (db.value?.missing.length ? db.value.missing.join(' / ') : 'DB-IP 国家级库'),
    }
  }
  if (!scope.enabled && !scope.node.enabled) {
    return { level: 'info' as const, text: '区域封禁关着：总闸和整节点策略都没开，节点上一张表都不会装。' }
  }
  // 总闸关着时节点对每个请求直接跳过判定（只累加"规则未执行"），所以这里绝不能因为
  // 表已经编出来就报成功：面板说"已生效"而节点一条都不拦，是最难被发现的那种不一致。
  if (!scope.enabled) {
    return {
      level: 'warning' as const,
      text:
        '平台总闸关着：节点对每个请求都跳过区域判定，' +
        (scope.node.enabled ? '下面那份整节点策略存得住但不会执行，' : '') +
        `域名规则也一样。表仍会下发到节点${plan.value?.total ? `（已编出 ${formatNumber(plan.value.total)} 条前缀）` : ''}，开闸后才真的拦。`,
    }
  }
  if (!plan.value?.total) {
    return { level: 'warning' as const, text: '开关已经打开，但还没有编译出任何前缀：国家清单是空的，或选中的国家在库里没有网段。' }
  }
  if (mismatchNodes.value.length) {
    return {
      level: 'warning' as const,
      text: `表已编译（${formatNumber(plan.value.total)} 条前缀），但 ${mismatchNodes.value.length} 台节点跑的不是这张表：那些节点仍按旧表判定。`,
    }
  }
  // 没上报过的节点既不算"一致"也不算"不一致"，但绝不能算进成功里：
  // 面板这边算出表和下发被接住是两件事，旧版本 cdnedge 或刚装的节点都可能一句都没回。
  if (silentNodes.value.length) {
    return {
      level: 'warning' as const,
      text: `表已编译（${formatNumber(plan.value.total)} 条前缀），但 ${silentNodes.value.length} 台节点没上报过区域读数：面板算好了，节点那边没有任何在用的证据。`,
    }
  }
  return { level: 'success' as const, text: `表已编译并下发一致：${formatNumber(plan.value.total)} 条前缀，覆盖 ${plan.value.countries.length} 个国家。` }
})

const l4Verdict = computed(() => {
  if (!scope.node.enabled) return { level: 'info' as const, text: '整节点丢包未启用：四层不会丢任何包，七层 403 不受影响。' }
  if (!scope.enabled) return { level: 'warning' as const, text: '整节点策略已启用，但平台总闸关着：判定在七层和四层都被跳过，四层也不会装丢包表。' }
  if (scope.node.mode !== 'block') return { level: 'info' as const, text: '整节点策略是观察模式：四层不装丢包表，只记账。' }
  if (!plan.value?.l4_enabled) return { level: 'warning' as const, text: '主控没让四层装载这张表，原因见下面的说明。' }
  if (!l4ArmedNodes.value.length) {
    return {
      level: 'warning' as const,
      text: '已开拦，但没有一台节点报回「四层已挂载」：XDP 没装上网卡，或节点上的 cdnedge 还没有区域 trie。',
    }
  }
  if (l4BadNodes.value.length) {
    return {
      level: 'warning' as const,
      text: `${l4BadNodes.value.length} 台节点的四层装载报错：${l4BadNodes.value.map((n) => n.node).join('、')}。域名级的七层 403 照常执行，但这台节点不会在网络层丢掉封禁国家的包。`,
    }
  }
  if (l4MismatchNodes.value.length) {
    return {
      level: 'warning' as const,
      text: `${l4MismatchNodes.value.length} 台节点网卡上丢包用的表和面板这张不是同一张，正在丢的是已经不该丢的地址。`,
    }
  }
  return { level: 'success' as const, text: `${l4ArmedNodes.value.length} / ${nodes.value.length} 台节点的四层已挂载，且装的是面板这张表。` }
})

function assignScope(s: GeoScope) {
  scope.enabled = s.enabled
  scope.selectable = [...(s.selectable ?? [])]
  scope.node = {
    ...s.node,
    countries: [...(s.node?.countries ?? [])],
    exceptions: [...(s.node?.exceptions ?? [])],
  }
}

function applyPlan(p: GeoPlanView) {
  plan.value = p
}

// 后端 ValidateScope 是"拒绝而不是纠正"，非法值一律 400 并逐字段给原因。
// 界面必须把原因原样摊开，否则改的人只看到一个"保存失败"。
const fieldLabels: Record<string, string> = {
  enabled: '平台总闸',
  selectable: '可选国家',
  mode: '整节点执行模式',
  action: '整节点动作',
  countries: '整节点国家清单',
  exceptions: '整节点例外清单',
}

function errText(e: unknown, fallback: string): string {
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
  return e instanceof ApiClientError ? e.message : fallback
}

async function loadNodes() {
  loadingNodes.value = true
  try {
    const r = await listGeoNodes()
    nodes.value = r.items
    expected.fingerprint = r.expected_fingerprint
    expected.total = r.expected_total
    nodeNotes.value = r.notes ?? []
  } catch (e) {
    ElMessage.error(errText(e, '加载节点装载情况失败'))
  } finally {
    loadingNodes.value = false
  }
}

async function load() {
  loading.value = true
  loadError.value = ''
  try {
    const r = await getGeoScope()
    assignScope(r.scope)
    saved.value = r.saved
    applyPlan(r.plan)
    db.value = r.geo_db
    readings.value = r.readings
    await loadNodes()
  } catch (e) {
    loadError.value = errText(e, '加载区域封禁配置失败')
  } finally {
    loading.value = false
  }
}

function reportPush(r: GeoPushSummary) {
  pushResult.value = r
  if (r.error) {
    ElMessage.error(r.error)
    return
  }
  const failed = r.failed ?? []
  if (failed.length) {
    ElMessage.warning(`已下发 ${r.ok} / ${r.nodes} 台，失败：${failed.join('、')}。逐节点结果见「本次下发结果」`)
  } else {
    ElMessage.success(`已下发到全部 ${r.ok} 台节点${r.total ? `（${formatNumber(r.total)} 条前缀）` : '（当前没有要编的国家）'}`)
  }
}

async function save() {
  const issues = blockingIssues.value
  if (issues.length) {
    ElMessage.error(issues[0])
    return
  }
  saving.value = true
  try {
    const r = await putGeoScope({
      enabled: scope.enabled,
      selectable: [...scope.selectable],
      node: { ...scope.node, countries: [...scope.node.countries], exceptions: [...scope.node.exceptions] },
    })
    assignScope(r.scope)
    applyPlan(r.plan)
    saved.value = true
    reportPush(r.push)
    // 读数要等节点下一轮上报才会变，这里立刻重读一次只是把已经变化的部分先显示出来。
    await loadNodes()
  } catch (e) {
    ElMessage.error(errText(e, '保存失败'))
  } finally {
    saving.value = false
  }
}

async function pushAgain() {
  pushing.value = true
  try {
    reportPush((await pushGeoScope()).push)
    await loadNodes()
  } catch (e) {
    ElMessage.error(errText(e, '重新下发失败'))
  } finally {
    pushing.value = false
  }
}

function refreshAll() {
  load()
}

onMounted(load)
</script>

<template>
  <div>
    <div class="header">
      <div>
        <h1>区域封禁</h1>
        <p class="hint">
          平台侧的三样开关：能力总闸、代理可选的国家范围、整节点的四层丢包。
          域名的区域规则由各代理自己在域名上配，这里决定它开不开、能开多大。
        </p>
      </div>
      <div class="tools">
        <el-button :loading="loading || loadingNodes" @click="refreshAll">刷新</el-button>
        <el-button :loading="pushing" @click="pushAgain">重新下发前缀表</el-button>
        <el-button type="primary" :loading="saving" @click="save">保存并下发全网</el-button>
      </div>
    </div>

    <el-alert v-if="loadError" type="error" :closable="false" show-icon :title="loadError" class="alert" />

    <div class="stat-grid">
      <div class="stat" :class="scope.enabled ? 'ok' : 'off'">
        <div class="label">能力总闸</div>
        <div class="value">{{ scope.enabled ? '已开启' : '已关闭' }}</div>
        <div class="small dim">{{ saved ? '已保存' : '还没保存过，现在是出厂默认值' }}</div>
      </div>
      <div class="stat" :class="db?.ready ? 'ok' : 'danger'">
        <div class="label">国家级地理库</div>
        <div class="value">{{ db?.ready ? '就位' : '未就位' }}</div>
        <div class="small dim">{{ catalogText }}{{ db?.ipv4 ? '' : ' · 缺 IPv4' }}{{ db?.ipv6 ? '' : ' · 缺 IPv6' }}</div>
      </div>
      <div class="stat">
        <div class="label">编译出的表</div>
        <div class="value">{{ formatNumber(plan?.total ?? 0) }}</div>
        <div class="small dim mono">
          {{ plan?.fingerprint || '没有指纹：还没编出表' }} · {{ formatBytes(plan?.gzip_bytes) }}
        </div>
      </div>
      <div class="stat" :class="plan?.l4_enabled ? 'ok' : 'off'">
        <div class="label">四层装载</div>
        <div class="value">{{ plan?.l4_enabled ? '应装载' : '不装载' }}</div>
        <div class="small dim">整节点策略开拦且这张表能装进 trie 时才是「应装载」</div>
      </div>
      <div class="stat" :class="mismatchNodes.length || silentNodes.length ? 'danger' : 'ok'">
        <div class="label">表一致的节点</div>
        <div class="value">{{ nodes.length ? `${nodes.length - mismatchNodes.length - silentNodes.length} / ${nodes.length}` : '—' }}</div>
        <div class="small dim">{{ readings ? `${readings.reported} 台已上报 · ${readings.silent} 台还没上报过` : '读数加载中' }}</div>
      </div>
    </div>

    <el-alert :type="verdict.level" :closable="false" show-icon :title="verdict.text" class="alert" />
    <el-alert :type="l4Verdict.level" :closable="false" show-icon title="整节点四层丢包" class="alert">
      <div class="small">{{ l4Verdict.text }}</div>
    </el-alert>

    <el-alert v-if="plan?.notes?.length" type="info" :closable="false" show-icon title="主控编译这张表时的说明" class="alert">
      <ul class="list">
        <li v-for="n in plan.notes" :key="n">{{ n }}</li>
      </ul>
    </el-alert>

    <el-form v-loading="loading" label-width="120px" @submit.prevent="save">
      <el-card class="card" shadow="never">
        <template #header>平台范围</template>
        <div class="form">
          <el-form-item label="能力总闸">
            <el-switch v-model="scope.enabled" :disabled="saving" />
            <div class="hint">
              关掉后代理不能再把域名规则存成启用（保存会被拒），已经存着的启用规则在节点上一条都不执行、只记「规则未执行」计数；
              下面的整节点策略同理，存得住但不生效。
            </div>
          </el-form-item>

          <el-form-item label="代理可选国家">
            <el-select
              v-model="picked"
              multiple
              filterable
              clearable
              :disabled="saving"
              collapse-tags
              collapse-tags-tooltip
              :max-collapse-tags="6"
              placeholder="留空 = 不限（库里所有国家都能选）"
              class="codes"
            >
              <el-option v-for="c in catalog" :key="c" :label="countryLabel(c)" :value="c" />
            </el-select>
            <div class="hint">
              这一项只约束代理能挑哪些国家，不影响下面管理员自己的整节点策略。留空表示不限。
              范围收窄不会自动删掉代理已经配好的国家，但那些规则再次保存时会被拒。
            </div>
            <div v-if="scope.selectable.length" class="chips">
              <el-tag v-for="c in scope.selectable" :key="c" size="small" type="info">{{ countryLabel(c) }}</el-tag>
            </div>
          </el-form-item>
        </div>
      </el-card>

      <el-card class="card" shadow="never">
        <template #header>整节点策略（四层丢包）</template>
        <p class="hint card-hint">
          作用范围是这台节点上的全部流量，所有代理共用：四层在网卡上按来源 IP 的前缀表直接丢包，
          客户端只看到连接超时，看不到 403，也不会留下任何 HTTP 日志。
          表按面板这张走，命中例外清单的地址（含下面的例外）永远放行。
        </p>
        <GeoPolicyForm
          :policy="scope.node"
          :codes="catalog"
          deny-only
          :busy="saving"
          exceptions-hint="命中例外的地址永远放行。整节点策略必须至少填一条：主控与节点互联的地址如果落在被封的国家里，这台节点会从集群里消失且不报错。裸 IP 会自动补成 /32（IPv6 补 /128）。"
        />
      </el-card>

      <div v-if="blockingIssues.length" class="hint block">现在还不能保存：{{ blockingIssues.join('；') }}</div>
      <el-button type="primary" :loading="saving" native-type="submit" class="save-btn">保存并下发全网</el-button>
      <div class="hint">保存会重算前缀表并立刻下发到全部启用节点；下发耗时随表的大小增长，MB 级载荷在慢链路上要几十秒。</div>
    </el-form>

    <el-card v-if="pushResult" class="card" shadow="never">
      <template #header>本次下发结果</template>
      <p class="hint card-hint">
        {{ pushResult.ok }} / {{ pushResult.nodes }} 台成功。
        「表」这一列 skipped 表示节点上已经是指纹相同的那张表，不是失败；cleared 表示规则都关掉之后把表撤下了。
      </p>
      <el-table :data="Object.entries(pushResult.per_node).map(([node, r]) => ({ node, ...r }))" size="small">
        <el-table-column label="节点" prop="node" min-width="150" />
        <el-table-column label="前缀表" min-width="260">
          <template #default="{ row }">
            <span :class="String(row.table ?? '').startsWith('failed') || String(row.table ?? '').startsWith('rejected') ? 'err' : ''">
              {{ row.table || '—' }}
            </span>
            <div v-if="row.table_not_persisted" class="err small">换表成功但没落盘：这台节点重启会回到旧表</div>
          </template>
        </el-table-column>
        <el-table-column label="节点配置" min-width="220">
          <template #default="{ row }">
            <span :class="String(row.config ?? '').startsWith('failed') || String(row.config ?? '').startsWith('rejected') ? 'err' : ''">
              {{ row.config || '—' }}
            </span>
          </template>
        </el-table-column>
      </el-table>
      <div v-if="pushResult.notes?.length" class="hint">
        {{ pushResult.notes.join('；') }}
      </div>
    </el-card>

    <el-card class="card" shadow="never">
      <template #header>全网读数</template>
      <div class="toolbar">
        <span class="dim">
          数据来自节点定期上报（约 10 秒一轮），主控不回连节点：刚下发的表不会立刻出现在下面。
        </span>
        <span class="grow"></span>
        <el-button :loading="loadingNodes" @click="loadNodes">重新读取节点</el-button>
      </div>

      <div class="counters">
        <div v-for="c in counterRows" :key="c.key" class="counter">
          <div class="k">{{ c.label }}</div>
          <div class="v">{{ formatNumber(readings?.counters?.[c.key] ?? 0) }}</div>
          <div class="hint">{{ c.hint }}</div>
        </div>
      </div>

      <div class="sub-title">按国家（各节点求和）</div>
      <el-table :data="readings?.countries ?? []" size="small" empty-text="暂无国家命中" max-height="320">
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

      <div class="sub-title">节点</div>
      <el-table v-loading="loadingNodes && !nodes.length" :data="nodes" size="small" empty-text="暂无节点">
        <el-table-column label="节点" min-width="150">
          <template #default="{ row }">
            <span
              class="dot"
              :class="row.error ? 'bad' : row.matches_plan_fingerprint === false || row.l4_matches === false ? 'off' : 'on'"
            ></span>
            {{ row.node }}
          </template>
        </el-table-column>
        <el-table-column label="实跑的表" min-width="210">
          <template #default="{ row }">
            <span v-if="row.error" class="dim">未知（没上报过）</span>
            <template v-else-if="row.loaded">
              <div class="mono">{{ row.fingerprint || '—' }}</div>
              <div class="small dim">{{ formatNumber(row.total) }} 条 · {{ row.countries?.length ?? 0 }} 个国家</div>
            </template>
            <span v-else class="dim">未装载</span>
            <div v-if="row.table_error" class="err small">{{ row.table_error }}</div>
          </template>
        </el-table-column>
        <el-table-column label="与面板一致" width="110">
          <template #default="{ row }">
            <el-tag v-if="row.error" size="small" type="info" effect="plain">未上报</el-tag>
            <el-tag v-else-if="row.matches_plan_fingerprint" size="small" type="success" effect="dark">一致</el-tag>
            <el-tag v-else-if="row.matches_plan_fingerprint === false" size="small" type="danger" effect="dark">不一致</el-tag>
            <span v-else class="dim">未知</span>
          </template>
        </el-table-column>
        <el-table-column label="四层丢包" min-width="230">
          <template #default="{ row }">
            <span v-if="row.error" class="dim">未知（没上报过）</span>
            <template v-else>
              <el-tag size="small" :type="row.l4_armed ? 'success' : 'info'" effect="plain">
                {{ row.l4_armed ? '已挂载' : '未挂载' }}
              </el-tag>
              <div class="small dim">
                期望 {{ row.l4_want ? '装载' : '不装' }} · {{ formatNumber(row.l4_entries) }} 条 · 已丢 {{ formatNumber(row.l4_dropped) }}
              </div>
              <!-- 「已挂载」只说明网卡上动过四棵 trie，不说明装的是现在这份表；这行指纹才是答案。 -->
              <div v-if="row.l4_fingerprint" class="mono small dim">网卡表 {{ row.l4_fingerprint }}</div>
              <div v-if="row.l4_matches === false" class="err small">网卡那张表的面板对不上：正在丢已经不该丢的地址</div>
              <div v-if="row.l4_applied" class="small dim">上次装表 {{ formatTime(row.l4_applied) }}</div>
            </template>
            <div v-if="row.l4_error" class="err small">{{ row.l4_error }}</div>
          </template>
        </el-table-column>
        <el-table-column label="未拦 / 已拦" width="120" align="right">
          <template #default="{ row }">
            <span v-if="row.error" class="dim">未知</span>
            <span v-else>{{ formatNumber(row.observe) }} / {{ formatNumber(row.blocked) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="未知 / 例外" width="120" align="right">
          <template #default="{ row }">
            <span v-if="row.error" class="dim">未知</span>
            <span v-else>{{ formatNumber(row.unknown) }} / {{ formatNumber(row.exception) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="上报时间" width="170">
          <template #default="{ row }">{{ formatTime(row.reported_at) }}</template>
        </el-table-column>
        <el-table-column label="错误" min-width="160" show-overflow-tooltip>
          <template #default="{ row }"><span class="err">{{ row.error }}</span></template>
        </el-table-column>
      </el-table>

      <div v-if="nodeNotes.length" class="hint">
        {{ nodeNotes.join('；') }}
      </div>
      <p class="hint">
        期望的表：指纹 <span class="mono">{{ expected.fingerprint || '（还没编出表）' }}</span> ·
        {{ formatNumber(expected.total) }} 条前缀。这一列比的是节点自己上报的指纹，
        某台节点还在跑旧表（下发时不在线、或它是没升级的旧 cdnedge）只有这里能看出来。
      </p>
    </el-card>
  </div>
</template>

<style scoped>
.header {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  justify-content: space-between;
  align-items: flex-start;
}
.header h1 {
  white-space: nowrap;
}
.tools {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  align-items: center;
}
.hint {
  margin: 0 0 12px;
  font-size: 13px;
  color: var(--text-dim);
  line-height: 1.6;
}
.alert {
  margin-bottom: 12px;
}
.card {
  margin-bottom: 16px;
}
.card-hint {
  margin-bottom: 14px;
}
.form {
  max-width: 720px;
}
.codes {
  width: 100%;
}
.chips {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  margin-top: 8px;
}
.list {
  margin: 6px 0 0;
  padding-left: 20px;
  font-size: 12px;
  line-height: 1.7;
}
.block {
  color: var(--el-color-warning, #e6a23c);
  margin-bottom: 10px;
}
.save-btn {
  margin-bottom: 8px;
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
.dim {
  color: var(--text-dim);
}
.counters {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
  gap: 10px;
  margin-bottom: 18px;
}
.counter {
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 10px 12px;
  background: var(--panel-2);
}
.counter .k {
  font-size: 12px;
  color: var(--text-dim);
}
.counter .v {
  font-size: 20px;
  font-weight: 600;
  font-variant-numeric: tabular-nums;
}
.counter .hint {
  margin: 4px 0 0;
  font-size: 11px;
  line-height: 1.5;
}
.sub-title {
  font-size: 13px;
  font-weight: 600;
  margin: 6px 0 8px;
}
.small {
  font-size: 11px;
}
.err {
  color: var(--danger);
}
</style>
