<script setup lang="ts">
import { useRoute } from 'vue-router'
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  listDomains,
  getDomain,
  createDomain,
  patchDomain,
  deleteDomain,
  purgeDomain,
  resyncDomain,
  switchToDefense,
  switchToCluster,
  getCertificate,
  uploadCertificate,
  requestAcmeCertificate,
} from '@/api/domains'
import { tenantApi, pollJob, ApiClientError } from '@/api/client'
import { getGeoOptions } from '@/api/security'
import { listClusters } from '@/api/clusters'
import { listTags } from '@/api/tags'
import GeoPolicyForm from '@/components/GeoPolicyForm.vue'
import { geoPolicyIssues } from '@/utils/geo'
import type {
  CacheRule,
  CCPolicy,
  Certificate,
  Cluster,
  Domain,
  GeoOptionsResponse,
  GeoPolicy,
  Job,
  Upstream,
} from '@/api/types'

const domains = ref<Domain[]>([])
const clusters = ref<Cluster[]>([])
const tagOptions = ref<string[]>([])
const clusterName = computed(() => {
  const m: Record<string, string> = {}
  for (const c of clusters.value) m[c.id] = c.name
  return m
})
const loading = ref(true)
const error = ref('')
const search = ref('')
// 从「标签分类」页跳过来时带 ?tag=xxx
const route = useRoute()
const tagFilter = ref(typeof route.query.tag === 'string' ? route.query.tag : '')

// 按添加顺序（created_at 升序）展示；筛选只在前端做，不改变顺序。
const filtered = computed(() =>
  domains.value.filter(
    (d) =>
      (!search.value || d.domain.includes(search.value.trim().toLowerCase())) &&
      (!tagFilter.value || d.tags.includes(tagFilter.value)),
  ),
)

const actionLoading = reactive<Record<string, string>>({})
const jobProgress = reactive<Record<string, { progress: number; message: string }>>({})

async function loadAllDomains(): Promise<Domain[]> {
  const out: Domain[] = []
  for (let page = 1; ; page++) {
    const res = await listDomains({ page, page_size: 200 })
    out.push(...res.items)
    if (!res.items.length || out.length >= res.total) break
  }
  return out
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const [ds, cl, tags] = await Promise.all([loadAllDomains(), listClusters(), listTags().catch(() => [])])
    domains.value = ds
    clusters.value = cl.items
    tagOptions.value = tags.map((t) => t.tag)
  } catch (e) {
    error.value = errMessage(e, '加载失败')
  } finally {
    loading.value = false
  }
}

function errMessage(e: unknown, fallback = '操作失败'): string {
  return e instanceof ApiClientError ? e.message : fallback
}

function replaceDomain(updated: Domain) {
  const idx = domains.value.findIndex((d) => d.id === updated.id)
  if (idx >= 0) domains.value[idx] = updated
  if (editing.value?.id === updated.id) editing.value = updated
}

async function withAction(d: Domain, name: string, fn: () => Promise<void>) {
  actionLoading[d.id] = name
  try {
    await fn()
  } catch (e) {
    ElMessage.error(errMessage(e))
  } finally {
    delete actionLoading[d.id]
  }
}

function handleSwitchToDefense(d: Domain) {
  return withAction(d, 'defense', async () => {
    replaceDomain(await switchToDefense(d.id))
    ElMessage.success('已切换到高防')
  })
}

function handleSwitchToCluster(d: Domain) {
  return withAction(d, 'cluster', async () => {
    replaceDomain(await switchToCluster(d.id))
    ElMessage.success('已切回集群')
  })
}

function runJob(domainId: string, job: Job): Promise<Job> {
  return pollJob(tenantApi, job.id, {
    onProgress: (j) => {
      jobProgress[domainId] = { progress: j.progress, message: j.message }
    },
  })
}

async function handlePurge(d: Domain) {
  jobProgress[d.id] = { progress: 0, message: '正在提交任务...' }
  await withAction(d, 'purge', async () => {
    const done = await runJob(d.id, await purgeDomain(d.id))
    if (done.status === 'done') ElMessage.success('缓存已清除')
    else ElMessage.error(done.message || '清缓存失败')
  })
  delete jobProgress[d.id]
}

// 保存配置后调用：PATCH 只改库，要 resync 才会推到边缘节点和 DNS。
async function resync(d: Domain, quiet = false) {
  jobProgress[d.id] = { progress: 0, message: '正在下发到节点...' }
  try {
    const done = await runJob(d.id, await resyncDomain(d.id))
    if (done.status === 'done') {
      if (done.warning) ElMessage.warning({ message: done.warning, duration: 8000 })
      else if (!quiet) ElMessage.success('已重新同步')
    } else {
      ElMessage.warning(done.message || '部分节点同步失败')
    }
  } finally {
    delete jobProgress[d.id]
    try {
      const res = await listDomains({ q: d.domain, page_size: 20 })
      const fresh = res.items.find((x) => x.id === d.id)
      if (fresh) replaceDomain(fresh)
    } catch {
      /* 刷新失败不影响结果 */
    }
  }
}

function handleResync(d: Domain) {
  return withAction(d, 'resync', () => resync(d))
}

async function handleDelete(d: Domain) {
  try {
    await ElMessageBox.confirm(`确定删除域名「${d.domain}」？边缘节点上的配置和 DNS 记录会一并移除。`, '删除域名', {
      type: 'warning',
      confirmButtonText: '删除',
      cancelButtonText: '取消',
    })
  } catch {
    return
  }
  await withAction(d, 'delete', async () => {
    await deleteDomain(d.id)
    domains.value = domains.value.filter((x) => x.id !== d.id)
    ElMessage.success('已删除')
  })
}

// ---------------------------------------------------------------------------
// 添加 / 编辑
// ---------------------------------------------------------------------------

function defaultCC(): CCPolicy {
  return {
    challenge_enabled: false,
    challenge_always: false,
    challenge_mode: '',
    challenge_bind_scope: '',
    challenge_threshold: 0,
    challenge_hold_seconds: 0,
    challenge_rps: 0,
    challenge_rpm: 0,
    verified_rps: 0,
    verified_rpm: 0,
    strict_enabled: false,
    strict_threshold: 0,
    fingerprint_threshold: 0,
  }
}

// 与 internal/geo.DefaultPolicy 一致：默认观察、默认 deny、空清单。
// 新域名的区域规则一律从观察起步，这和后端拒绝"启用但没选国家"是同一套考虑——
// 一开就拦的国家清单，误伤的是真实访客而不只是攻击者。
function defaultGeo(): GeoPolicy {
  return { enabled: false, mode: 'observe', action: 'deny', countries: [], exceptions: [] }
}

// 区域封禁的国家清单由平台侧决定（管理员开范围、地理库决定有没有网段），
// 所以这一页必须先问到清单才能给选择框。没问到之前控件是禁用的。
const geoOptions = ref<GeoOptionsResponse | null>(null)
const geoOptionsLoading = ref(false)
const geoOptionsError = ref('')
// 可选国家 = 管理员划的范围 ∩ 库里真有网段的。范围空表示不限，此时用整份目录。
const geoSelectable = computed(() => {
  const o = geoOptions.value
  if (!o) return []
  return o.selectable.length ? o.available : o.catalog
})

async function loadGeoOptions() {
  if (geoOptions.value || geoOptionsLoading.value) return
  geoOptionsLoading.value = true
  geoOptionsError.value = ''
  try {
    geoOptions.value = await getGeoOptions()
  } catch (e) {
    geoOptionsError.value = errMessage(e, '区域封禁的国家清单读取失败')
  } finally {
    geoOptionsLoading.value = false
  }
}

interface CacheRuleForm {
  extensions: string
  ttl: string
  enabled: boolean
}

const editVisible = ref(false)
const editSaving = ref(false)
const editing = ref<Domain | null>(null)
const activeTab = ref('site')
const form = reactive({
  domain: '',
  cluster_id: '',
  origin_scheme: 'http' as 'http' | 'https',
  upstreams: [] as Upstream[],
  defense_cname: '',
  enabled: true,
  static_public: false,
  cache_rules: [] as CacheRuleForm[],
  ssl_mode: 'off' as 'off' | 'manual',
  cc: defaultCC(),
  cache_busting_params: '',
  tags: [] as string[],
  geo: defaultGeo(),
})

const cert = ref<Certificate | null>(null)
const certLoading = ref(false)
const certForm = reactive({ cert_pem: '', key_pem: '' })
const certUploading = ref(false)
// 自助签发是异步 Job（要等 CA 查 DNS），点一次可能跑几十秒到几分钟。
const certApplying = ref(false)

function openCreate() {
  editing.value = null
  activeTab.value = 'site'
  Object.assign(form, {
    domain: '',
    cluster_id: clusters.value[0]?.id ?? '',
    origin_scheme: 'http',
    upstreams: [{ address: '', weight: 1 }],
    defense_cname: '',
    enabled: true,
    static_public: false,
    cache_rules: [],
    ssl_mode: 'off',
    cc: defaultCC(),
    cache_busting_params: '',
    tags: [],
    geo: defaultGeo(),
  })
  cert.value = null
  void loadGeoOptions()
  editVisible.value = true
}

function openEdit(d: Domain) {
  editing.value = d
  activeTab.value = 'site'
  Object.assign(form, {
    domain: d.domain,
    cluster_id: d.cluster_id ?? '',
    origin_scheme: d.origin_scheme,
    upstreams: d.upstreams.length ? d.upstreams.map((u) => ({ ...u })) : [{ address: '', weight: 1 }],
    defense_cname: d.defense_cname,
    enabled: d.enabled,
    // !! 是必需的：老版本主控的响应里没有这个键，undefined 直接进 switch 会显示成
    // "既不是开也不是关"的中间态，而实际下发的是 false。
    static_public: !!d.static_public,
    cache_rules: (d.cache_rules ?? []).map((r) => ({
      extensions: r.extensions.join(', '),
      ttl: r.ttl,
      enabled: r.enabled,
    })),
    ssl_mode: d.ssl?.mode === 'manual' ? 'manual' : 'off',
    cc: { ...defaultCC(), ...(d.cc_policy ?? {}) },
    cache_busting_params: (d.cc_policy?.cache_busting?.whitelist_params ?? []).join(', '),
    tags: [...(d.tags ?? [])],
    // 后端回显的 geo_policy 已经把缺的字段补成默认值，数组仍要拷一份：
    // 直接引用的话弹窗里的编辑会改到列表里那一行，用户取消也撤不回来。
    geo: {
      ...defaultGeo(),
      ...(d.geo_policy ?? {}),
      countries: [...(d.geo_policy?.countries ?? [])],
      exceptions: [...(d.geo_policy?.exceptions ?? [])],
    },
  })
  certForm.cert_pem = ''
  certForm.key_pem = ''
  cert.value = null
  void loadGeoOptions()
  editVisible.value = true
  loadCert(d)
}

// 不管 ssl.mode 都查：HTTPS 被「关闭」保存过时证书仍在库里，要能看到并重新启用。
async function loadCert(d: Domain) {
  certLoading.value = true
  try {
    cert.value = await getCertificate(d.id)
  } catch {
    cert.value = null
  } finally {
    certLoading.value = false
  }
}

const splitList = (s: string) =>
  s
    .split(/[\s,，]+/)
    .map((x) => x.trim())
    .filter(Boolean)

function buildCacheRules(): CacheRule[] | null {
  const out: CacheRule[] = []
  for (const [i, r] of form.cache_rules.entries()) {
    const exts = splitList(r.extensions).map((e) => e.replace(/^\./, '').toLowerCase())
    if (!exts.length) {
      ElMessage.error(`缓存规则 ${i + 1}：请填写扩展名`)
      return null
    }
    if (!/^\d+[smhd]$/.test(r.ttl.trim())) {
      ElMessage.error(`缓存规则 ${i + 1}：TTL 格式如 30d、7d、1h、60m`)
      return null
    }
    out.push({ extensions: exts, ttl: r.ttl.trim(), enabled: r.enabled })
  }
  return out
}

function buildCC(): CCPolicy {
  const cc: CCPolicy = { ...form.cc }
  const params = splitList(form.cache_busting_params)
  if (params.length) cc.cache_busting = { whitelist_params: params }
  else delete cc.cache_busting
  return cc
}

async function saveEdit() {
  const upstreams = form.upstreams
    .map((u) => ({ address: u.address.trim(), weight: u.weight }))
    .filter((u) => u.address)
  if (!editing.value && !form.domain.trim()) {
    activeTab.value = 'site'
    ElMessage.error('请填写域名')
    return
  }
  if (!upstreams.length) {
    activeTab.value = 'site'
    ElMessage.error('至少需要一个源站地址')
    return
  }
  const cache_rules = buildCacheRules()
  if (!cache_rules) {
    activeTab.value = 'cache'
    return
  }
  // 区域规则在服务端是当场拒绝的（见 cleanDomainGeoPolicy），这里先拦一次：
  // 让人在弹窗里看到"缺哪一项"，而不是保存失败后去猜。
  const geoIssues = geoPolicyIssues(form.geo)
  if (geoIssues.length) {
    activeTab.value = 'geo'
    ElMessage.error(geoIssues[0])
    return
  }
  // 总闸关着时服务端不会让这条规则存成启用（见 cleanGeoPolicy），而这份表单每次保存都带上
  // geo_policy——不先拦一次，代理会发现自己连改个源站地址都保存不了，还以为是区域页坏了。
  if (form.geo.enabled && geoOptions.value && !geoOptions.value.enabled) {
    activeTab.value = 'geo'
    ElMessage.error('平台还没开启区域封禁：这条区域规则得先关掉才能保存，等管理员开闸后再打开。')
    return
  }
  const base = {
    cluster_id: form.cluster_id || null,
    origin_scheme: form.origin_scheme,
    upstreams,
    defense_cname: form.defense_cname.trim(),
    enabled: form.enabled,
    static_public: form.static_public,
  }
  editSaving.value = true
  try {
    let d: Domain
    const patch: Parameters<typeof patchDomain>[1] = {
      ...base,
      cache_rules,
      cc_policy: buildCC(),
      geo_policy: form.geo,
      tags: form.tags,
    }
    if (editing.value) {
      // 关掉 HTTPS 走 PATCH；开启只能通过上传证书（certificate_id 由服务端生成）。
      if (form.ssl_mode === 'off' && editing.value.ssl?.mode === 'manual') {
        patch.ssl = { mode: 'off', certificate_id: null, force_https: true }
      } else if (form.ssl_mode === 'manual' && cert.value && !cert.value.in_use) {
        // 证书已上传但未启用（之前关闭过）：引用库里的证书重新开启 HTTPS
        patch.ssl = { mode: 'manual', certificate_id: cert.value.id, force_https: true }
      }
      d = await patchDomain(editing.value.id, patch, editing.value.version)
      replaceDomain(d)
    } else {
      const created = await createDomain({ domain: form.domain.trim().toLowerCase(), ...base })
      domains.value.push(created)
      d = await patchDomain(created.id, { cache_rules, cc_policy: buildCC(), geo_policy: form.geo, tags: form.tags }, created.version)
      replaceDomain(d)
    }
    editVisible.value = false
    // 区域规则的下发结果必须让人看见：保存成功只说明落库了，节点没接住的话
    // 面板上那条"已封禁"就是假话。skipped 同样要说——一个可下发的节点都没有等于哪儿都没生效。
    const gp = d.geo_push
    if (gp && (gp.error || gp.skipped)) {
      ElMessage({
        type: 'warning',
        message: '区域规则已保存，但没能全部生效：' + (gp.error || gp.skipped),
        duration: 8000,
        showClose: true,
      })
    } else {
      ElMessage.success(editing.value ? '已保存，正在下发到节点' : '已添加，正在下发到节点')
    }
    await withAction(d, 'resync', () => resync(d, true))
  } catch (e) {
    if (e instanceof ApiClientError && e.status === 412) {
      ElMessage.error('该域名已被其他操作修改，请刷新后重试')
    } else {
      ElMessage.error(errMessage(e))
    }
  } finally {
    editSaving.value = false
  }
}

function readFile(ev: Event, field: 'cert_pem' | 'key_pem') {
  const file = (ev.target as HTMLInputElement).files?.[0]
  if (!file) return
  const reader = new FileReader()
  reader.onload = () => {
    certForm[field] = String(reader.result ?? '')
  }
  reader.readAsText(file)
}

async function handleUploadCert() {
  const d = editing.value
  if (!d) return
  if (!certForm.cert_pem.includes('BEGIN CERTIFICATE') || !certForm.key_pem.includes('PRIVATE KEY')) {
    ElMessage.error('请粘贴 PEM 格式的证书和私钥')
    return
  }
  certUploading.value = true
  try {
    const res = await uploadCertificate(d.id, { cert_pem: certForm.cert_pem, key_pem: certForm.key_pem })
    replaceDomain(res.domain)
    cert.value = res.certificate
    form.ssl_mode = 'manual'
    certForm.cert_pem = ''
    certForm.key_pem = ''
    ElMessage.success('证书已保存，正在下发到节点')
    await withAction(res.domain, 'resync', () => resync(res.domain, true))
  } catch (e) {
    ElMessage.error(errMessage(e, '证书上传失败'))
  } finally {
    certUploading.value = false
  }
}

// 自助申请：dns-01 全流程在服务端跑（写 TXT → 等 CA 校验 → 签发 → 入库 → 下发），这里只提交并轮询 Job。
// 失败时把后端原文透出来：「Cloudflare 未配置」「域名不在该 Zone」「CA 拒绝校验」要走的操作完全不同，
// 统一压成"申请失败"等于让用户自己猜。
async function handleApplyCert() {
  const d = editing.value
  if (!d) return
  certApplying.value = true
  jobProgress[d.id] = { progress: 0, message: '正在提交申请...' }
  try {
    const done = await runJob(d.id, await requestAcmeCertificate(d.id))
    if (done.status === 'done') {
      form.ssl_mode = 'manual'
      await loadCert(d)
      // 签发在服务端就把 ssl.mode 改成了 manual，列表里那个 HTTPS 角标得跟着刷新，
      // 否则用户申请完还得点一次「刷新」才看得见自己刚拿到的证书。
      replaceDomain(await getDomain(d.id))
      ElMessage.success('证书已签发并启用')
      if (done.warning) ElMessage.warning({ message: done.warning, duration: 8000 })
    } else {
      ElMessage.error(done.message || '证书申请失败')
    }
  } catch (e) {
    ElMessage.error(errMessage(e, '证书申请失败'))
  } finally {
    delete jobProgress[d.id]
    certApplying.value = false
  }
}

// 到期时间是自己拼的，不用 toLocaleString：同一行里它会给出 "2026-11-15" 和 "2027/2/13"
// 两种分隔符，用户要盯的就是"到底哪天到期"。
function fmtDate(s?: string | null) {
  if (!s) return '-'
  const d = new Date(s)
  if (Number.isNaN(d.getTime())) return s
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

function certDaysLeft(c: Certificate) {
  return Math.floor((new Date(c.not_after).getTime() - Date.now()) / 86400000)
}

onMounted(load)
</script>

<template>
  <div class="page">
    <div class="page-header">
      <div>
        <h1>域名管理</h1>
        <p class="sub">按添加顺序排列 · 共 {{ domains.length }} 个</p>
      </div>
      <div class="actions">
        <el-input v-model="search" placeholder="搜索域名" clearable style="width: 200px" />
        <el-select v-model="tagFilter" placeholder="按标签筛选" clearable style="width: 150px">
          <el-option v-for="t in tagOptions" :key="t" :label="t" :value="t" />
        </el-select>
        <el-button @click="load">刷新</el-button>
        <el-button type="primary" @click="openCreate">添加域名</el-button>
      </div>
    </div>
    <el-alert v-if="error" :title="error" type="error" show-icon :closable="false" class="alert" />

    <div class="panel">
      <el-table v-loading="loading" :data="filtered" style="width: 100%">
        <el-table-column type="index" label="#" width="56" />
        <el-table-column label="域名" min-width="200">
          <template #default="{ row }">
            <div class="domain-cell">
              <span class="mono">{{ row.domain }}</span>
              <el-tag v-if="row.ssl?.mode === 'manual'" size="small" type="success" effect="plain">HTTPS</el-tag>
            </div>
            <div v-if="row.tags?.length" class="tags">
              <el-tag v-for="t in row.tags" :key="t" size="small" effect="dark" type="info">{{ t }}</el-tag>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="集群" min-width="110">
          <template #default="{ row }">
            {{ row.cluster_id ? clusterName[row.cluster_id] ?? row.cluster_id : '未分配' }}
          </template>
        </el-table-column>
        <el-table-column label="解析" min-width="170">
          <template #default="{ row }">
            <el-tag v-if="row.dns?.on_defense" type="danger" effect="dark" size="small">
              {{ row.dns.defense_by_failover ? '故障切换·高防' : '高防' }}
            </el-tag>
            <el-tag v-else type="primary" effect="plain" size="small">集群</el-tag>
            <div class="mono dim small">{{ row.dns?.active_target || row.dns?.cname_target || '-' }}</div>
          </template>
        </el-table-column>
        <!-- 「同步」列换成源站地址列：后端 state 只可能是 pending/error，旧列对任何人都恒显
             "待同步"，而源站地址本来就该在这一行看到。下发进度仍留在本列。 -->
        <el-table-column label="源站地址" min-width="170">
          <template #default="{ row }">
            <div v-for="(u, i) in row.upstreams" :key="i" class="mono small">
              {{ u.address }}<span v-if="u.weight > 1" class="dim"> · 权重 {{ u.weight }}</span>
            </div>
            <div v-if="!row.upstreams?.length" class="dim small">未配置</div>
            <div v-if="jobProgress[row.id]" class="job-progress">
              <el-progress :percentage="jobProgress[row.id].progress" :stroke-width="4" />
              <span class="dim small">{{ jobProgress[row.id].message }}</span>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="状态" width="80">
          <template #default="{ row }">
            <span :class="['dot', row.enabled ? 'on' : 'off']" />{{ row.enabled ? '启用' : '停用' }}
          </template>
        </el-table-column>
        <el-table-column label="操作" width="330" fixed="right">
          <template #default="{ row }">
            <el-button size="small" :disabled="!!actionLoading[row.id]" @click="openEdit(row)">编辑</el-button>
            <el-button
              v-if="!row.dns?.on_defense"
              size="small"
              type="danger"
              plain
              :loading="actionLoading[row.id] === 'defense'"
              :disabled="!!actionLoading[row.id]"
              @click="handleSwitchToDefense(row)"
            >
              切高防
            </el-button>
            <el-button
              v-else
              size="small"
              type="success"
              plain
              :loading="actionLoading[row.id] === 'cluster'"
              :disabled="!!actionLoading[row.id]"
              @click="handleSwitchToCluster(row)"
            >
              切回集群
            </el-button>
            <el-dropdown trigger="click" :disabled="!!actionLoading[row.id]">
              <el-button size="small" :loading="['purge', 'resync', 'delete'].includes(actionLoading[row.id])">
                更多
              </el-button>
              <template #dropdown>
                <el-dropdown-menu>
                  <el-dropdown-item @click="handlePurge(row)">清除缓存</el-dropdown-item>
                  <el-dropdown-item @click="handleResync(row)">重新同步</el-dropdown-item>
                  <el-dropdown-item divided @click="handleDelete(row)">
                    <span style="color: var(--el-color-danger)">删除域名</span>
                  </el-dropdown-item>
                </el-dropdown-menu>
              </template>
            </el-dropdown>
          </template>
        </el-table-column>
        <template #empty>暂无域名</template>
      </el-table>
    </div>

    <el-dialog v-model="editVisible" :title="editing ? '编辑域名 · ' + editing.domain : '添加域名'" width="760px" top="6vh">
      <el-tabs v-model="activeTab">
        <!-- 站点与回源：添加域名必填的两项（域名、源站）必须同屏，不让人在 tab 之间找 -->
        <el-tab-pane label="站点与回源" name="site">
          <el-form label-width="110px" @submit.prevent>
            <el-form-item label="域名" required>
              <el-input v-model="form.domain" :disabled="!!editing" placeholder="www.example.com" />
            </el-form-item>
            <el-form-item label="集群">
              <el-select v-model="form.cluster_id" placeholder="不分配" clearable style="width: 100%">
                <el-option v-for="c in clusters" :key="c.id" :label="c.name" :value="c.id" />
              </el-select>
            </el-form-item>
            <el-form-item label="启用">
              <el-switch v-model="form.enabled" />
            </el-form-item>
            <el-form-item label="回源协议">
              <el-radio-group v-model="form.origin_scheme">
                <el-radio value="http">HTTP</el-radio>
                <el-radio value="https">HTTPS</el-radio>
              </el-radio-group>
            </el-form-item>
            <el-form-item label="源站" required>
              <div class="full">
                <div v-for="(u, i) in form.upstreams" :key="i" class="row">
                  <el-input v-model="u.address" placeholder="1.2.3.4:80 或 origin.example.com" />
                  <el-input-number v-model="u.weight" :min="1" :max="100" controls-position="right" />
                  <el-button :disabled="form.upstreams.length <= 1" @click="form.upstreams.splice(i, 1)">删除</el-button>
                </div>
                <el-button size="small" @click="form.upstreams.push({ address: '', weight: 1 })">添加源站</el-button>
                <div class="hint">权重 1-100，按比例分配回源流量</div>
              </div>
            </el-form-item>
            <el-form-item label="高防 CNAME">
              <el-input v-model="form.defense_cname" placeholder="第三方高防给的 CNAME，留空则使用集群默认" />
              <div class="hint">切换到高防后，DNS 灰云 CNAME 指向这里；域名配置优先于集群默认。</div>
            </el-form-item>
            <el-form-item v-if="editing" label="当前解析">
              <div class="defense-row">
                <el-tag v-if="editing.dns?.on_defense" type="danger" effect="dark">
                  {{ editing.dns.defense_by_failover ? '故障自动切换 · 高防' : '高防' }}
                </el-tag>
                <el-tag v-else type="primary">集群</el-tag>
                <span class="mono dim">{{ editing.dns?.active_target || editing.dns?.cname_target || '-' }}</span>
                <el-button
                  v-if="!editing.dns?.on_defense"
                  size="small"
                  type="danger"
                  :loading="actionLoading[editing.id] === 'defense'"
                  @click="handleSwitchToDefense(editing)"
                >
                  切换到高防
                </el-button>
                <el-button
                  v-else
                  size="small"
                  type="success"
                  :loading="actionLoading[editing.id] === 'cluster'"
                  @click="handleSwitchToCluster(editing)"
                >
                  切回集群
                </el-button>
              </div>
              <div class="hint">切换会立即修改 DNS，不需要点保存。先保存高防 CNAME 再切换。</div>
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <!-- 缓存：可选调优，不参与"添加域名"的最小必填 -->
        <el-tab-pane label="缓存" name="cache">
          <el-form label-width="110px" @submit.prevent>
            <el-form-item label="缓存规则">
              <div class="full">
                <div v-for="(r, i) in form.cache_rules" :key="i" class="row">
                  <el-input v-model="r.extensions" placeholder="扩展名：jpg, png, css, js" />
                  <el-input v-model="r.ttl" placeholder="7d" style="width: 110px" />
                  <el-switch v-model="r.enabled" />
                  <el-button @click="form.cache_rules.splice(i, 1)">删除</el-button>
                </div>
                <el-button size="small" @click="form.cache_rules.push({ extensions: '', ttl: '7d', enabled: true })">
                  添加规则
                </el-button>
                <div class="hint">TTL 格式：30s / 60m / 1h / 7d。不配置则使用平台默认缓存策略。</div>
              </div>
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <!-- SSL -->
        <el-tab-pane label="SSL 证书" name="ssl">
          <el-alert
            v-if="!editing"
            type="info"
            :closable="false"
            show-icon
            title="先添加域名，再到编辑页上传证书。"
          />
          <el-form v-else label-width="110px" @submit.prevent>
            <el-form-item label="HTTPS">
              <el-radio-group v-model="form.ssl_mode">
                <el-radio value="off">关闭</el-radio>
                <el-radio value="manual" :disabled="!cert && editing.ssl?.mode !== 'manual'">启用证书</el-radio>
              </el-radio-group>
              <div class="hint">上传证书后自动开启 HTTPS；选择「关闭」并保存即停用 443。</div>
            </el-form-item>
            <el-form-item label="当前证书">
              <div v-loading="certLoading" class="full">
                <div v-if="cert" class="cert-card">
                  <el-alert
                    v-if="!cert.in_use"
                    type="warning"
                    :closable="false"
                    show-icon
                    title="证书已上传但 HTTPS 未启用，访问会被拒绝（ERR_EMPTY_RESPONSE）。选择「启用证书」后保存即可。"
                  />
                  <div><span class="dim">主体</span> <span class="mono">{{ cert.subject || '-' }}</span></div>
                  <div><span class="dim">域名</span> <span class="mono">{{ cert.dns_names.join(', ') || '-' }}</span></div>
                  <div><span class="dim">签发</span> {{ cert.issuer || '-' }}</div>
                  <div>
                    <span class="dim">有效期</span> {{ fmtDate(cert.not_before) }} ~ {{ fmtDate(cert.not_after) }}
                    <el-tag :type="certDaysLeft(cert) < 15 ? 'danger' : 'success'" size="small">
                      剩余 {{ certDaysLeft(cert) }} 天
                    </el-tag>
                  </div>
                </div>
                <span v-else class="dim">未上传</span>
                <div class="hint">
                  证书到期不会自动续期。剩余不足 15 天时请重新点「申请」或上传新证书，否则 443 会因证书过期报错。
                </div>
              </div>
            </el-form-item>
            <el-form-item label="自助申请">
              <div class="full">
                <el-button :loading="certApplying" @click="handleApplyCert">申请 Let's Encrypt 证书</el-button>
                <div v-if="certApplying && jobProgress[editing.id]" class="job-progress">
                  <el-progress :percentage="jobProgress[editing.id].progress" :stroke-width="4" />
                  <span class="dim small">{{ jobProgress[editing.id].message }}</span>
                </div>
                <div class="hint">
                  用「设置 → Cloudflare 凭证」里保存的那份凭证，在域名所在 Zone 写一条 DNS 校验记录（TXT）
                  完成验证，约 90 天有效，成功后直接启用 HTTPS。要求域名已完成所有权验证且在本 Zone 内；
                  不符合条件时点按钮会说明缺哪一项。
                </div>
              </div>
            </el-form-item>
            <el-form-item label="证书 (PEM)">
              <div class="full">
                <el-input
                  v-model="certForm.cert_pem"
                  type="textarea"
                  :rows="5"
                  class="mono"
                  placeholder="-----BEGIN CERTIFICATE-----（含中间证书链）"
                />
                <input type="file" accept=".pem,.crt,.cer" class="file" @change="readFile($event, 'cert_pem')" />
              </div>
            </el-form-item>
            <el-form-item label="私钥 (PEM)">
              <div class="full">
                <el-input
                  v-model="certForm.key_pem"
                  type="textarea"
                  :rows="5"
                  class="mono"
                  placeholder="-----BEGIN PRIVATE KEY-----"
                />
                <input type="file" accept=".pem,.key" class="file" @change="readFile($event, 'key_pem')" />
                <div class="hint">私钥加密存储，任何接口都不会返回；上传新证书会替换旧证书。</div>
              </div>
            </el-form-item>
            <el-form-item>
              <el-button type="primary" :loading="certUploading" @click="handleUploadCert">上传并启用</el-button>
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <!-- CC 防御 -->
        <el-tab-pane label="CC 防御" name="cc">
          <el-form label-width="150px" @submit.prevent>
            <el-form-item label="静态资源免检">
              <el-switch v-model="form.static_public" />
              <span class="hint inline">纯图片、音视频域名给 App 与小程序无凭证直连用</span>
              <div class="hint">
                开启后静态资源赛道不再挂逐请求校验：没有访客指纹采集、不参与 CC 判定、不命中 WAF 规则，
                随机查询参数打穿缓存的洪水会直达源站，边缘只剩单 IP 并发数与速率闸兜底。
                业务主域名不要开启。动态接口与 WebSocket 不受本开关影响。
              </div>
            </el-form-item>
            <el-form-item label="人机验证">
              <el-switch v-model="form.cc.challenge_enabled" />
              <span class="hint inline">受到强攻击时对访客做浏览器验证</span>
              <div class="hint">
                自适应触发：业务空闲期不带凭证的访客直接放行，搜索引擎与合规爬虫不会被等待页挡住；
                域名秒级请求数越过下面的「攻击判定 QPS」才自动举盾，举盾期间所有无凭证访客都要先过一次验证，
                冷却期走满后自动收盾回到放行。
              </div>
            </el-form-item>
            <el-form-item label="始终验证">
              <el-switch v-model="form.cc.challenge_always" />
              <span class="hint inline">不等攻击，所有无有效凭证的访客先验证一次</span>
              <div class="hint">给确实被持续盯上的域名用。开了它，无论流量高低一律先验证，「攻击判定 QPS」这道门槛不再参与放行判定；第三层指纹判定照常。</div>
            </el-form-item>
            <el-form-item label="验证模式">
              <el-radio-group v-model="form.cc.challenge_mode">
                <el-radio-button value="">无感 JS</el-radio-button>
                <el-radio-button value="shield">3 秒盾</el-radio-button>
                <el-radio-button value="slider">滑块</el-radio-button>
                <el-radio-button value="text">文字/算术</el-radio-button>
              </el-radio-group>
            </el-form-item>
            <el-form-item label="凭证绑定">
              <el-radio-group v-model="form.cc.challenge_bind_scope">
                <el-radio value="">完整 IP</el-radio>
                <el-radio value="subnet">同网段 (/24, /48)</el-radio>
                <el-radio value="none">不绑定地址</el-radio>
              </el-radio-group>
              <div class="hint">移动网络出口 IP 经常漂移时选「同网段」或「不绑定」。</div>
            </el-form-item>
            <el-divider content-position="left">阈值（0 = 使用系统默认/全局值）</el-divider>
            <div class="grid">
              <el-form-item label="攻击判定 QPS">
                <el-input-number v-model="form.cc.challenge_threshold" :min="0" controls-position="right" />
              </el-form-item>
              <el-form-item label="开盾冷却（秒）">
                <el-input-number v-model="form.cc.challenge_hold_seconds" :min="0" :max="900" controls-position="right" />
                <div class="hint">举盾后至少保持这么久，期间流量回落也不收盾；到点自动降级回放行。</div>
              </el-form-item>
              <el-form-item label="高强度判定 QPS">
                <el-input-number v-model="form.cc.strict_threshold" :min="0" controls-position="right" />
              </el-form-item>
              <el-form-item label="攻击态单 IP 每秒">
                <el-input-number v-model="form.cc.challenge_rps" :min="0" controls-position="right" />
              </el-form-item>
              <el-form-item label="攻击态单 IP 每分钟">
                <el-input-number v-model="form.cc.challenge_rpm" :min="0" controls-position="right" />
              </el-form-item>
              <el-form-item label="已验证用户每秒">
                <el-input-number v-model="form.cc.verified_rps" :min="0" controls-position="right" />
              </el-form-item>
              <el-form-item label="已验证用户每分钟">
                <el-input-number v-model="form.cc.verified_rpm" :min="0" controls-position="right" />
              </el-form-item>
            </div>
            <el-form-item label="指纹检测">
              <el-switch v-model="form.cc.strict_enabled" />
              <span class="hint inline">高强度攻击时按客户端指纹统计，识别换 IP 的攻击源</span>
            </el-form-item>
            <el-form-item label="单指纹每秒阈值">
              <el-input-number v-model="form.cc.fingerprint_threshold" :min="0" controls-position="right" />
            </el-form-item>
            <el-form-item label="缓存绕过白名单参数">
              <el-input v-model="form.cache_busting_params" placeholder="token, session_id（逗号分隔）" />
              <div class="hint">这些查询参数的变化不计入缓存绕过攻击信号。</div>
            </el-form-item>
          </el-form>
        </el-tab-pane>

        <!-- 区域封禁 -->
        <el-tab-pane label="区域封禁" name="geo">
          <div v-loading="geoOptionsLoading" class="geo-pane">
            <el-alert v-if="geoOptionsError" type="error" show-icon :closable="false" :title="geoOptionsError" class="geo-note" />
            <!-- 平台总闸没开时这一句必须是"存下了但不执行"，不能写得像规则已经生效 -->
            <el-alert
              v-else-if="geoOptions && !geoOptions.enabled"
              type="info"
              show-icon
              :closable="false"
              :title="geoOptions.note"
              class="geo-note"
            />
            <el-alert
              v-else-if="geoOptions?.note"
              type="warning"
              show-icon
              :closable="false"
              :title="geoOptions.note"
              class="geo-note"
            />
            <p class="hint">
              按来源 IP 的归属国家放行或拒绝。判定在节点上完成，命中拦截的请求直接返回 403，不会回源。
              国家归属来自平台安装的国家级地理库，库没覆盖的地址（含内网、保留段）一律放行并单独计入「归属未知」。
            </p>

            <GeoPolicyForm
              v-if="geoOptions"
              :policy="form.geo"
              :codes="geoSelectable"
              :unavailable="geoOptions.unavailable"
              :used="geoOptions.used"
              :busy="editSaving"
              hint="只作用于这个域名（七层 403）。整节点的四层丢包由平台管理员配置，不在这里。"
            />
            <el-button v-else :disabled="geoOptionsLoading" @click="loadGeoOptions">重新读取国家清单</el-button>

            <p class="hint">
              保存后主控会重算前缀表并补发给节点：新选中的国家如果还没进表，规则会把它查成「归属未知」然后放行。
              读数来自节点的周期性上报（十秒级），改完不会立刻变化，去「WAF 防护 → 区域规则」核对下发结果。
            </p>
          </div>
        </el-tab-pane>

        <!-- 标签 -->
        <el-tab-pane label="标签分类" name="tags">
          <el-form label-width="110px" @submit.prevent>
            <el-form-item label="标签">
              <el-select
                v-model="form.tags"
                multiple
                filterable
                allow-create
                default-first-option
                placeholder="选择或输入新标签"
                style="width: 100%"
              >
                <el-option v-for="t in tagOptions" :key="t" :label="t" :value="t" />
              </el-select>
              <div class="hint">标签只在本代理内可见，可在「标签分类」页统一管理。</div>
            </el-form-item>
          </el-form>
        </el-tab-pane>
      </el-tabs>
      <template #footer>
        <el-button @click="editVisible = false">取消</el-button>
        <el-button type="primary" :loading="editSaving" @click="saveEdit">保存并下发</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.domain-cell {
  display: flex;
  align-items: center;
  gap: 6px;
}
.tags {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  margin-top: 4px;
}
.full {
  width: 100%;
}
.row {
  display: flex;
  gap: 8px;
  margin-bottom: 8px;
  align-items: center;
}
.hint {
  font-size: 12px;
  color: var(--text-dim);
  line-height: 1.6;
  width: 100%;
}
.hint.inline {
  width: auto;
  margin-left: 10px;
}
.geo-pane {
  max-width: 760px;
}
.geo-note {
  margin-bottom: 12px;
}
.job-progress {
  margin-top: 6px;
  width: 150px;
}
.defense-row {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
}
.cert-card {
  padding: 10px 14px;
  border: 1px solid var(--line);
  border-radius: 6px;
  background: var(--panel-2);
  line-height: 1.9;
  font-size: 13px;
}
.cert-card .dim {
  display: inline-block;
  width: 52px;
}
.file {
  margin-top: 6px;
  font-size: 12px;
  color: var(--text-dim);
}
.grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
}
.small {
  font-size: 12px;
}
.alert {
  margin-bottom: 16px;
}
</style>
