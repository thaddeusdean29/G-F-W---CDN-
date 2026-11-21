<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  activateWafPackage,
  createWafPackage,
  deleteWafPackage,
  getWafPackage,
  listWafNodePackages,
  listWafPackages,
  pushWafPackages,
  updateWafPackage,
  type WafNodeReading,
  type WafPackageList,
  type WafPackageRow,
  type WafPushResult,
} from '@/api/wafPackages'
import { ApiClientError } from '@/api/client'
import { formatBytes, formatTime } from '@/utils/format'

// 平台级 WAF 托管规则包维护页。
//
// 这里改的是"所有代理共用的那份规则"：启用一行会立即下发到全部启用节点，
// 所以每个动作都要把下发结果逐节点摊开给管理员看，不能只报"成功"。
// 规则文本只在本页与主控库之间流动（入库即密文），代理侧只能看到不含正则的目录。

const list = ref<WafPackageList | null>(null)
const nodes = ref<WafNodeReading[]>([])
const expectedVersion = ref('')
const loading = ref(false)
const loadingNodes = ref(false)
const busy = ref<Record<string, boolean>>({})
const pushResult = ref<WafPushResult | null>(null)
const tab = ref('packages')

function errText(e: unknown, fallback: string): string {
  return e instanceof ApiClientError ? e.message : fallback
}

async function load() {
  loading.value = true
  try {
    list.value = await listWafPackages()
  } catch (e) {
    ElMessage.error(errText(e, '加载规则包列表失败'))
  } finally {
    loading.value = false
  }
}

async function loadNodes() {
  loadingNodes.value = true
  try {
    const r = await listWafNodePackages()
    nodes.value = r.items
    expectedVersion.value = r.expected_version
  } catch (e) {
    ElMessage.error(errText(e, '加载节点装载情况失败'))
  } finally {
    loadingNodes.value = false
  }
}

function refreshAll() {
  load()
  loadNodes()
}

// ── 上传 / 编辑 ─────────────────────────────────────────────────────────────
const dialogVisible = ref(false)
const dialogSaving = ref(false)
const loadingDetail = ref(false)
const editing = ref<WafPackageRow | null>(null)
const form = reactive({ notes: '', json: '', activate: false })

// 骨架里带一条真能编译过的规则，是为了让"照着改"这件事不用先猜字段名。
// 上限与取值来自 internal/waf/ruleset.go：改那边必须同步改这里的提示。
const skeleton = JSON.stringify(
  {
    version: '2026.11.01',
    sets: [
      {
        id: 'joomla_compat',
        name: '某 CMS 兼容组',
        description: '这些规则会拦住该 CMS 的正常后台请求，按业务需要勾选',
        recommended: false,
        rules: ['sqli-union'],
      },
    ],
    rules: [
      {
        id: 'sqli-union',
        name: 'SQL 联合查询注入',
        description: '检测 union select 变体',
        tier: 1,
        scopes: ['url', 'body'],
        patterns: ['(?i)union\\s+(all\\s+)?select'],
      },
    ],
  },
  null,
  2,
)

function openCreate() {
  editing.value = null
  form.notes = ''
  form.json = skeleton
  form.activate = false
  dialogVisible.value = true
}

async function openEdit(row: WafPackageRow) {
  editing.value = row
  form.notes = row.notes
  form.json = ''
  form.activate = false
  dialogVisible.value = true
  loadingDetail.value = true
  try {
    const d = await getWafPackage(row.id)
    form.json = JSON.stringify(d.rules, null, 2)
    form.notes = d.package.notes
  } catch (e) {
    ElMessage.error(errText(e, '读取规则包明文失败'))
    dialogVisible.value = false
  } finally {
    loadingDetail.value = false
  }
}

interface LintIssue {
  errors: string[]
}

// 与后端同一套约束的本地预检（internal/waf/ruleset.go 的 CompilePackage）。
// 后端仍然会再校一遍并整包拒绝；这里的作用是让几 MB 的包不必为拼错的字段名跑一趟网络。
function lint(raw: string): LintIssue {
  const errors: string[] = []
  let pkg: any
  try {
    pkg = JSON.parse(raw)
  } catch (e) {
    return { errors: [`JSON 语法错误：${(e as Error).message}`] }
  }
  if (!pkg || typeof pkg !== 'object' || Array.isArray(pkg)) return { errors: ['顶层必须是 JSON 对象'] }
  const idRe = /^[a-z0-9][a-z0-9_-]{0,31}$/
  const verRe = /^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$/
  const scopes = ['url', 'body', 'ua', 'referer', 'cookie', 'ct']
  if (!verRe.test(String(pkg.version ?? ''))) errors.push('version：不能为空，最长 32，只允许字母数字与 . _ -（不能以符号开头）')
  if (!Array.isArray(pkg.rules) || pkg.rules.length === 0) errors.push('rules：至少要有一条规则')
  if (Array.isArray(pkg.rules) && pkg.rules.length > 256) errors.push(`rules：${pkg.rules.length} 条，超过上限 256`)
  const ids = new Set<string>()
  for (const [i, r] of (Array.isArray(pkg.rules) ? pkg.rules : []).entries()) {
    const at = `第 ${i + 1} 条规则`
    if (!idRe.test(String(r?.id ?? ''))) errors.push(`${at}：id 不合法（只允许小写字母、数字、- 和 _，不能以符号开头）`)
    else if (ids.has(r.id)) errors.push(`${at}：id 重复 ${r.id}`)
    else ids.add(r.id)
    if (typeof r?.name !== 'string' || !r.name.length || r.name.length > 64) errors.push(`${at}：name 长度必须在 1~64`)
    if (typeof r?.description === 'string' && r.description.length > 200) errors.push(`${at}：description 最长 200`)
    if (!Number.isInteger(r?.tier) || r.tier < 1 || r.tier > 4) errors.push(`${at}：tier 必须是 1~4 的整数`)
    if (!Array.isArray(r?.scopes) || !r.scopes.length) errors.push(`${at}：scopes 不能为空`)
    else if (r.scopes.some((s: string) => !scopes.includes(s))) errors.push(`${at}：scopes 只能取 ${scopes.join('/')}`)
    if (!Array.isArray(r?.patterns) || !r.patterns.length) errors.push(`${at}：patterns 不能为空`)
    else if (r.patterns.length > 32) errors.push(`${at}：正则数量 ${r.patterns.length} 超过上限 32`)
    else if (r.patterns.some((p: string) => typeof p !== 'string' || !p.length || p.length > 4096))
      errors.push(`${at}：正则有空串或超过 4096 字符`)
  }
  for (const [i, s] of (Array.isArray(pkg.sets) ? pkg.sets : []).entries()) {
    const at = `第 ${i + 1} 个规则集`
    if (!idRe.test(String(s?.id ?? ''))) errors.push(`${at}：id 不合法`)
    if (typeof s?.name !== 'string' || !s.name.length || s.name.length > 64) errors.push(`${at}：name 长度必须在 1~64`)
    if (typeof s?.description === 'string' && s.description.length > 400) errors.push(`${at}：description 最长 400`)
    if (!Array.isArray(s?.rules)) errors.push(`${at}：rules 必须是数组`)
    else for (const rid of s.rules) if (!ids.has(rid)) errors.push(`${at}：引用了不存在的规则 ${rid}`)
  }
  if (raw.length > 2 * 1024 * 1024) errors.push(`包体 ${formatBytes(raw.length)} 超过 2 MiB 上限`)
  return { errors }
}

const lintErrors = computed(() => (form.json.trim() ? lint(form.json).errors : []))

async function submit() {
  if (!form.json.trim()) return ElMessage.error('请填入规则包 JSON')
  const bad = lintErrors.value
  if (bad.length) return ElMessage.error(`规则包有问题：${bad.slice(0, 3).join('；')}${bad.length > 3 ? ` 等 ${bad.length} 处` : ''}`)
  let pkg: unknown
  try {
    pkg = JSON.parse(form.json)
  } catch {
    return ElMessage.error('JSON 解析失败')
  }
  dialogSaving.value = true
  try {
    if (editing.value) {
      const r = await updateWafPackage(editing.value.id, { notes: form.notes.trim(), package: pkg })
      pushResult.value = r.push ?? null
      ElMessage.success(
        r.push ? `规则包 ${r.version} 已更新${r.repushed ? '并重新下发全网' : ''}` : `规则包 ${r.version} 已更新`,
      )
    } else {
      const r = await createWafPackage({ notes: form.notes.trim(), package: pkg, activate: form.activate })
      pushResult.value = r.push ?? null
      ElMessage.success(form.activate ? `规则包 ${r.version} 已上传并启用（${r.rule_count} 条）` : `规则包 ${r.version} 已上传（${r.rule_count} 条）`)
    }
    dialogVisible.value = false
    refreshAll()
  } catch (e) {
    ElMessage.error(errText(e, '保存失败'))
  } finally {
    dialogSaving.value = false
  }
}

// ── 启用 / 删除 / 重推 ──────────────────────────────────────────────────────
async function activate(row: WafPackageRow) {
  try {
    await ElMessageBox.confirm(
      `启用「${row.version}」（${row.rule_count} 条规则）并立即下发到全部启用节点。当前生效的是「${
        list.value?.active.version ?? '未知'
      }」。`,
      '启用并下发',
      { type: 'warning', confirmButtonText: '启用并下发', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  busy.value[row.id] = true
  try {
    const r = await activateWafPackage(row.id)
    pushResult.value = r.push
    reportPush(r.push, `已启用 ${row.version}`)
    refreshAll()
  } catch (e) {
    ElMessage.error(errText(e, '启用失败'))
  } finally {
    delete busy.value[row.id]
  }
}

async function remove(row: WafPackageRow) {
  try {
    await ElMessageBox.confirm(`删除规则包「${row.version}」？删除后无法恢复。`, '删除规则包', {
      type: 'warning',
      confirmButtonText: '删除',
      cancelButtonText: '取消',
    })
  } catch {
    return
  }
  busy.value[row.id] = true
  try {
    await deleteWafPackage(row.id)
    ElMessage.success('已删除')
    refreshAll()
  } catch (e) {
    if (e instanceof ApiClientError && e.code === 'in_use') {
      ElMessage.error('这一份正在启用中：先启用别的包，再删除它')
    } else {
      ElMessage.error(errText(e, '删除失败'))
    }
  } finally {
    delete busy.value[row.id]
  }
}

async function pushAgain() {
  busy.value.__push = true
  try {
    const r = await pushWafPackages()
    pushResult.value = r
    reportPush(r, `已重新下发 ${r.active_version}`)
    loadNodes()
  } catch (e) {
    ElMessage.error(errText(e, '下发失败'))
  } finally {
    delete busy.value.__push
  }
}

function reportPush(res: WafPushResult, okMsg: string) {
  const fails = pushFailures(res)
  if (fails.length) ElMessage.warning(`${okMsg}，但部分节点没接住：${fails.slice(0, 3).join('；')}`)
  else ElMessage.success(`${okMsg}，${res.ok}/${res.nodes} 个节点已装载`)
}

// 逐节点结果：status 不是 ok 的都算失败。applied-not-persisted 尤其要单列出来——
// 那种节点一重启就回到上一份包，等于"现在在防、重启后不防"。
function pushFailures(res: WafPushResult | null): string[] {
  if (!res) return []
  return Object.entries(res.per_node ?? {})
    .filter(([, v]) => v.status !== 'ok')
    .map(([k, v]) => `${k}: ${v.error || v.persist_error || v.status}`)
}

const mismatchedNodes = computed(() => nodes.value.filter((n) => n.matches_active === false))
const failedNodes = computed(() => nodes.value.filter((n) => !!n.error))
const matchedNodes = computed(() => nodes.value.filter((n) => n.matches_active === true).length)

function statusOf(row: WafPackageRow): { label: string; type: 'success' | 'warning' | 'info' } {
  if (row.enabled) return { label: '启用中', type: 'success' }
  if (row.activated_at) return { label: '旧档（可灰度/回滚）', type: 'warning' }
  return { label: '未启用', type: 'info' }
}

onMounted(refreshAll)
</script>

<template>
  <div>
    <div class="header">
      <div>
        <h1>WAF 规则包</h1>
        <p class="hint">托管规则本体由平台维护：上传、启用、灰度与全网下发。代理侧只能看到不含正则的目录。</p>
      </div>
      <div class="tools">
        <el-button :loading="loading || loadingNodes" @click="refreshAll">刷新</el-button>
        <el-button :loading="busy.__push" @click="pushAgain">重新下发当前包</el-button>
        <el-button type="primary" @click="openCreate">上传规则包</el-button>
      </div>
    </div>

    <div class="stat-grid">
      <div class="stat" :class="list?.active.error ? 'danger' : 'ok'">
        <div class="label">当前生效的规则包</div>
        <div class="value mono">{{ list?.active.version || '—' }}</div>
        <div class="small dim">{{ list?.active.from_db ? '库中启用行' : '出厂内置包（还没启用过任何上传的包）' }}</div>
      </div>
      <div class="stat">
        <div class="label">生效规则条数</div>
        <div class="value">{{ list?.active.rule_count ?? '—' }}</div>
      </div>
      <div class="stat">
        <div class="label">旧档（灰度/回滚用）</div>
        <div class="value mono">{{ list?.active.previous_version || '无' }}</div>
      </div>
      <div class="stat">
        <div class="label">出厂包</div>
        <div class="value mono">{{ list?.builtin.version || '—' }}</div>
        <div class="small dim">{{ list?.builtin.rule_count ?? 0 }} 条规则</div>
      </div>
      <div class="stat" :class="mismatchedNodes.length || failedNodes.length ? 'danger' : 'ok'">
        <div class="label">装载一致的节点</div>
        <div class="value">{{ nodes.length ? `${matchedNodes} / ${nodes.length}` : '—' }}</div>
      </div>
    </div>

    <el-alert v-if="list?.active.error" type="error" :closable="false" show-icon title="启用的规则包编译不过，全网仍在按出厂包防护">
      <div class="small mono">{{ list.active.error }}</div>
      <div class="small dim">这一行是绕过接口写进库的：改正内容再启用一次，或先启用别的包。</div>
    </el-alert>

    <el-alert v-if="mismatchedNodes.length" type="warning" :closable="false" show-icon title="这些节点跑的不是当前启用的包">
      <div class="small">
        {{ mismatchedNodes.map((n) => `${n.node}（${n.active_version || '未装载'}）`).join('、') }}
      </div>
      <div class="small dim">
        数据来自节点定期上报。节点不在线、拒收过包、或还没上报过都会落在这里；用「重新下发当前包」补一次，
        再回来看这一列有没有变。
      </div>
    </el-alert>

    <el-alert v-if="pushResult" type="info" :closable="true" show-icon :title="`最近一次下发：${pushResult.active_version}`">
      <div class="small">
        {{ pushResult.ok }} / {{ pushResult.nodes }} 个节点确认装载{{ pushResult.previous_version ? `，旧档 ${pushResult.previous_version}` : '' }}。
      </div>
      <div v-if="pushFailures(pushResult).length" class="small mono">
        {{ pushFailures(pushResult).join('；') }}
      </div>
    </el-alert>

    <el-tabs v-model="tab" type="border-card" class="tabs">
      <el-tab-pane label="规则包" name="packages">
        <el-table v-loading="loading" :data="list?.items ?? []" size="small" empty-text="还没有上传过规则包">
          <el-table-column label="版本" min-width="160">
            <template #default="{ row }">
              <span class="mono">{{ row.version }}</span>
              <div v-if="row.notes" class="sub">{{ row.notes }}</div>
            </template>
          </el-table-column>
          <el-table-column label="状态" width="160">
            <template #default="{ row }">
              <el-tag size="small" :type="statusOf(row).type" effect="dark">{{ statusOf(row).label }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="规则 / 组" width="100" align="right">
            <template #default="{ row }">{{ row.rule_count }} / {{ row.set_count }}</template>
          </el-table-column>
          <el-table-column label="入库大小" width="110" align="right">
            <template #default="{ row }">{{ formatBytes(row.size_bytes) }}</template>
          </el-table-column>
          <el-table-column label="最近激活" width="180">
            <template #default="{ row }">{{ formatTime(row.activated_at) }}</template>
          </el-table-column>
          <el-table-column label="最近更新" width="180">
            <template #default="{ row }">{{ formatTime(row.updated_at) }}</template>
          </el-table-column>
          <el-table-column label="操作" width="230" fixed="right">
            <template #default="{ row }">
              <el-button size="small" type="primary" :disabled="row.enabled" :loading="!!busy[row.id]" @click="activate(row)">
                启用
              </el-button>
              <el-button size="small" :loading="!!busy[row.id]" @click="openEdit(row)">编辑</el-button>
              <el-button size="small" type="danger" :disabled="row.enabled" :loading="!!busy[row.id]" @click="remove(row)">
                删除
              </el-button>
            </template>
          </el-table-column>
        </el-table>
        <p class="hint">
          启用中那一行被改内容时会自动重新下发全网；「旧档」是灰度与整代理回滚的唯一可选项，
          每个代理能在自己的 WAF 页把流量按比例切到它上面。
        </p>
      </el-tab-pane>

      <el-tab-pane label="各节点装载情况" name="nodes">
        <div class="tools">
          <span class="hint">
            期望版本 <span class="mono">{{ expectedVersion || '未知' }}</span>
            （主控不回连节点，读数来自节点定期上报）
          </span>
          <span class="grow"></span>
          <el-button size="small" :loading="loadingNodes" @click="loadNodes">重新读取</el-button>
        </div>
        <el-table :data="nodes" size="small" empty-text="暂无节点" max-height="560">
          <el-table-column label="节点" min-width="160">
            <template #default="{ row }">
              <span class="dot" :class="row.error ? 'bad' : row.matches_active === false ? 'off' : 'on'"></span>
              {{ row.node }}
            </template>
          </el-table-column>
          <el-table-column label="IP" width="140">
            <template #default="{ row }"><span class="mono">{{ row.ip }}</span></template>
          </el-table-column>
          <el-table-column label="活动包" min-width="150">
            <template #default="{ row }">
              <span v-if="row.error" class="hint">未知</span>
              <template v-else>
                <span class="mono">{{ row.active_version || '—' }}</span>
                <el-tag v-if="row.matches_active === false" size="small" type="danger" effect="dark">不是启用的那份</el-tag>
              </template>
            </template>
          </el-table-column>
          <el-table-column label="旧档" min-width="150">
            <template #default="{ row }">
              <span v-if="row.error" class="hint">未知</span>
              <span v-else class="mono">{{ row.previous_version || '无' }}</span>
            </template>
          </el-table-column>
          <el-table-column label="出厂包" min-width="150">
            <template #default="{ row }">
              <span v-if="row.error" class="hint">未知</span>
              <span v-else class="mono">{{ row.builtin_version || '—' }}</span>
            </template>
          </el-table-column>
          <el-table-column label="上报时间" width="180">
            <template #default="{ row }">{{ formatTime(row.reported_at) }}</template>
          </el-table-column>
          <el-table-column label="错误" min-width="160" show-overflow-tooltip>
            <template #default="{ row }"><span class="err">{{ row.error }}</span></template>
          </el-table-column>
        </el-table>
      </el-tab-pane>
    </el-tabs>

    <el-dialog v-model="dialogVisible" :title="editing ? `编辑规则包 · ${editing.version}` : '上传规则包'" width="900px" top="5vh">
      <el-form label-width="110px" @submit.prevent>
        <el-form-item label="备注">
          <el-input v-model="form.notes" maxlength="500" show-word-limit placeholder="这次改了什么，方便回滚时判断" />
        </el-form-item>
        <el-form-item v-if="!editing" label="上传后立即启用">
          <el-switch v-model="form.activate" />
          <span class="hint-inline">打开即等于把这份包下发到全部启用节点；关掉只是先存一份备用。</span>
        </el-form-item>
        <el-form-item label="规则包 JSON">
          <el-input v-model="form.json" type="textarea" :rows="20" class="mono" spellcheck="false" />
        </el-form-item>
      </el-form>

      <el-alert v-if="lintErrors.length" type="error" :closable="false" show-icon :title="`${lintErrors.length} 处会被主控拒绝`">
        <div v-for="m in lintErrors.slice(0, 8)" :key="m" class="small">{{ m }}</div>
        <div v-if="lintErrors.length > 8" class="small dim">其余 {{ lintErrors.length - 8 }} 处从略。</div>
      </el-alert>
      <p class="hint">
        约束：version 最长 32 位字母数字与 <span class="mono">. _ -</span>；规则与规则集 id 只允许小写字母、数字、
        <span class="mono">- _</span>；<span class="mono">tier</span> 取 1~4（对应安全级别「低/中/高/攻击中」）；
        <span class="mono">scopes</span> 只能取 <span class="mono">url / body / ua / referer / cookie / ct</span>
        —— 这是 auth_request 子请求真拿得到的位置，别的要靠改 Tengine 模板；正则是 Go 的 RE2，
        <strong>不支持前后向断言</strong>。上限 256 条规则、每条 32 个正则、单个正则 4096 字符、包体 2 MiB。
      </p>
      <p class="hint">
        任何一条规则编译不过都会整包拒绝：半套规则比旧规则危险，面板会以为新包已经生效。
      </p>

      <template #footer>
        <div class="dialog-footer">
          <el-button @click="form.json = skeleton">填入骨架</el-button>
          <span class="grow"></span>
          <el-button @click="dialogVisible = false">取消</el-button>
          <el-button type="primary" :loading="dialogSaving || loadingDetail" :disabled="!!lintErrors.length || !form.json.trim()" @click="submit">
            {{ editing ? '保存' : form.activate ? '上传并启用' : '上传' }}
          </el-button>
        </div>
      </template>
    </el-dialog>
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
.grow {
  flex: 1;
}
.hint {
  margin: 0 0 16px;
  font-size: 13px;
  color: var(--text-dim);
}
.hint-inline {
  margin-left: 10px;
  font-size: 12px;
  color: var(--text-dim);
}
.tabs {
  background: var(--panel);
  border-color: var(--line);
}
.sub {
  font-size: 12px;
  color: var(--text-dim);
}
.small {
  font-size: 12px;
}
.err {
  color: var(--danger);
}
.dialog-footer {
  display: flex;
  gap: 8px;
  align-items: center;
}
</style>
