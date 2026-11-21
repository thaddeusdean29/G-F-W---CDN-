<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { pollJob, tenantApi } from '@/api/client'
import { listDomains, purgeDomain } from '@/api/domains'
import { getCacheConfig, getCacheStats, putCacheConfig } from '@/api/security'
import type { CacheRule, Domain } from '@/api/types'
import { errMessage, formatBytes, formatNumber, pushFailures } from '@/utils/format'

type CacheStats = Awaited<ReturnType<typeof getCacheStats>>

const stats = ref<CacheStats | null>(null)
const domains = ref<Domain[]>([])
const loading = ref(false)
const q = ref('')
const busy = ref<Record<string, boolean>>({})

const pathsDialog = ref(false)
const pathsTarget = ref<Domain | null>(null)
const pathsText = ref('/')

async function loadStats() {
  try {
    stats.value = await getCacheStats()
  } catch (e) {
    ElMessage.error(errMessage(e, '加载缓存统计失败'))
  }
}

async function loadDomains() {
  const all: Domain[] = []
  for (let page = 1; ; page++) {
    const r = await listDomains({ page, page_size: 200 })
    all.push(...r.items)
    if (all.length >= r.total || r.items.length === 0) break
  }
  domains.value = all
}

// ── 默认缓存规则（本代理）：域名没有自己的缓存规则时使用 ──────────────────────
interface RuleForm {
  extensions: string
  ttl: string
  enabled: boolean
}
const rules = reactive<RuleForm[]>([])
const platformDefault = ref<CacheRule[]>([])
const rulesSaved = ref(false)
const savingRules = ref(false)

function toForm(list: CacheRule[]): RuleForm[] {
  return list.map((r) => ({ extensions: r.extensions.join(', '), ttl: r.ttl, enabled: r.enabled }))
}

async function loadRules() {
  try {
    const r = await getCacheConfig()
    rules.splice(0, rules.length, ...toForm(r.config.rules))
    platformDefault.value = r.platform_default.rules
    rulesSaved.value = r.saved
  } catch (e) {
    ElMessage.error(errMessage(e, '加载缓存规则失败'))
  }
}

function buildRules(): CacheRule[] | null {
  const out: CacheRule[] = []
  for (const [i, r] of rules.entries()) {
    const exts = r.extensions
      .split(/[,，\s]+/)
      .map((x) => x.trim().replace(/^\./, '').toLowerCase())
      .filter(Boolean)
    if (!exts.length) {
      ElMessage.error(`规则 ${i + 1}：请填写扩展名`)
      return null
    }
    if (!/^\d+[smhd]$/.test(r.ttl.trim())) {
      ElMessage.error(`规则 ${i + 1}：缓存时长格式如 30d、7d、1h、60m`)
      return null
    }
    out.push({ extensions: exts, ttl: r.ttl.trim(), enabled: r.enabled })
  }
  return out
}

async function saveRules() {
  const list = buildRules()
  if (!list) return
  savingRules.value = true
  try {
    const r = await putCacheConfig({ rules: list })
    rules.splice(0, rules.length, ...toForm(r.config.rules))
    rulesSaved.value = true
    const fails = pushFailures(r.push)
    if (fails.length) ElMessage.warning(`已保存，但部分节点下发失败：${fails.join('；')}`)
    else ElMessage.success('默认缓存规则已保存并下发到节点')
    window.setTimeout(loadStats, 65000) // 节点每 60 秒上报一次缓存占用
  } catch (e) {
    ElMessage.error(errMessage(e, '保存缓存规则失败'))
  } finally {
    savingRules.value = false
  }
}

function restorePlatformDefault() {
  rules.splice(0, rules.length, ...toForm(platformDefault.value))
}

async function load() {
  loading.value = true
  try {
    await Promise.all([loadStats(), loadDomains(), loadRules()])
  } catch (e) {
    ElMessage.error(errMessage(e, '加载域名失败'))
  } finally {
    loading.value = false
  }
}

async function purge(d: Domain, paths: string[] = ['/']) {
  busy.value[d.id] = true
  try {
    const job = await purgeDomain(d.id, paths)
    const done = await pollJob(tenantApi, job.id)
    if (done.status === 'failed') ElMessage.error(`${d.domain} 清除失败：${done.message || '未知错误'}`)
    else if (done.warning) ElMessage.warning(`${d.domain} 部分节点清除失败：${done.warning}`)
    else ElMessage.success(`${d.domain} 缓存已清除`)
    loadStats()
  } catch (e) {
    ElMessage.error(errMessage(e, '清除缓存失败'))
  } finally {
    busy.value[d.id] = false
  }
}

function openPaths(d: Domain) {
  pathsTarget.value = d
  pathsText.value = '/'
  pathsDialog.value = true
}

async function submitPaths() {
  const d = pathsTarget.value
  if (!d) return
  const paths = pathsText.value
    .split('\n')
    .map((s) => s.trim())
    .filter(Boolean)
  if (!paths.length) return
  pathsDialog.value = false
  await purge(d, paths)
}

const filtered = computed(() => {
  const kw = q.value.trim().toLowerCase()
  return kw ? domains.value.filter((d) => d.domain.toLowerCase().includes(kw)) : domains.value
})

onMounted(load)
</script>

<template>
  <div class="page">
    <div class="page-header">
      <div>
        <h1>缓存</h1>
        <p class="sub">本代理节点上的缓存占用 · 按域名清除缓存</p>
      </div>
      <div class="actions">
        <el-button :loading="loading" @click="load">刷新</el-button>
      </div>
    </div>

    <div class="stat-grid">
      <div class="stat">
        <div class="label">缓存占用</div>
        <div class="value">{{ formatBytes(stats?.bytes) }}</div>
      </div>
      <div class="stat ok">
        <div class="label">缓存文件</div>
        <div class="value">{{ formatNumber(stats?.files) }}</div>
      </div>
      <div class="stat">
        <div class="label">节点数</div>
        <div class="value">{{ formatNumber(stats?.nodes.length) }}</div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-title">
        <span>默认缓存规则</span>
        <el-tag v-if="!rulesSaved" size="small" type="info">平台默认</el-tag>
      </div>
      <p class="dim desc">
        没有单独设置缓存规则的域名都使用这里的规则。按文件扩展名缓存静态资源；HTML 页面和接口请求不缓存。
        保存后会立即把本代理全部域名重新下发到节点。
      </p>
      <div v-for="(r, i) in rules" :key="i" class="rule-row">
        <el-input v-model="r.extensions" placeholder="扩展名，逗号分隔：jpg, png, css, js" :aria-label="`规则 ${i + 1} 扩展名`" />
        <el-input v-model="r.ttl" placeholder="7d" class="ttl" :aria-label="`规则 ${i + 1} 缓存时长`" />
        <el-switch v-model="r.enabled" :aria-label="`规则 ${i + 1} 启用`" />
        <el-button @click="rules.splice(i, 1)">删除</el-button>
      </div>
      <div v-if="!rules.length" class="dim desc">没有规则：未单独设置的域名将不缓存任何内容。</div>
      <div class="rule-actions">
        <el-button size="small" @click="rules.push({ extensions: '', ttl: '7d', enabled: true })">添加规则</el-button>
        <el-button size="small" @click="restorePlatformDefault">恢复平台默认</el-button>
        <span class="dim">缓存时长：30s / 60m / 1h / 7d</span>
        <span class="spacer"></span>
        <el-button type="primary" :loading="savingRules" @click="saveRules">保存并下发</el-button>
      </div>
    </div>

    <div class="panel">
      <div class="panel-title"><span>节点缓存</span></div>
      <el-table :data="stats?.nodes ?? []" size="small" empty-text="暂无节点">
        <el-table-column label="节点" min-width="160">
          <template #default="{ row }">
            <span class="dot" :class="row.error ? 'bad' : 'on'"></span>{{ row.node }}
          </template>
        </el-table-column>
        <el-table-column label="IP" width="150">
          <template #default="{ row }"><span class="mono">{{ row.ip }}</span></template>
        </el-table-column>
        <el-table-column label="占用" width="130" align="right">
          <template #default="{ row }">{{ row.error ? '-' : formatBytes(row.bytes) }}</template>
        </el-table-column>
        <el-table-column label="文件" width="120" align="right">
          <template #default="{ row }">{{ row.error ? '-' : formatNumber(row.files) }}</template>
        </el-table-column>
        <el-table-column label="错误" min-width="160" show-overflow-tooltip>
          <template #default="{ row }"><span class="err">{{ row.error }}</span></template>
        </el-table-column>
      </el-table>
    </div>

    <div class="panel">
      <div class="panel-title">
        <span>按域名清除</span>
        <el-input v-model="q" placeholder="搜索域名" clearable size="small" style="width: 200px" />
      </div>
      <el-table v-loading="loading" :data="filtered" size="small" empty-text="暂无域名" max-height="560">
        <el-table-column type="index" width="50" />
        <el-table-column label="域名" prop="domain" min-width="220" />
        <el-table-column label="缓存规则" min-width="200" show-overflow-tooltip>
          <template #default="{ row }">
            <span v-if="!row.cache_rules?.length" class="dim">使用默认规则</span>
            <span v-else>{{ row.cache_rules.length }} 条</span>
          </template>
        </el-table-column>
        <el-table-column label="操作" width="200" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" :loading="busy[row.id]" @click="purge(row)">清除全部</el-button>
            <el-button link :disabled="busy[row.id]" @click="openPaths(row)">按路径清除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>

    <el-dialog v-model="pathsDialog" :title="`按路径清除 · ${pathsTarget?.domain ?? ''}`" width="480px">
      <el-input v-model="pathsText" type="textarea" :rows="6" class="mono" placeholder="每行一个路径，如 /static/app.js" />
      <template #footer>
        <el-button @click="pathsDialog = false">取消</el-button>
        <el-button type="primary" @click="submitPaths">清除</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.err {
  color: var(--danger);
}
.desc {
  margin: 0 0 12px;
  font-size: 12px;
}
.rule-row {
  display: flex;
  gap: 8px;
  align-items: center;
  margin-bottom: 8px;
}
.rule-row .ttl {
  width: 110px;
  flex: none;
}
.rule-actions {
  display: flex;
  gap: 8px;
  align-items: center;
  font-size: 12px;
}
.rule-actions .spacer {
  flex: 1;
}
</style>
