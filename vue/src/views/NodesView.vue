<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  listNodes,
  createNode,
  patchNode,
  deleteNode,
  deployNode,
  installXdp,
  onboardNode,
  getEdgeRegisterInfo,
  rotateEdgeRegisterSecret,
} from '@/api/nodes'
import { listClusters } from '@/api/clusters'
import { tenantApi, pollJob, ApiClientError } from '@/api/client'
import type { Cluster, Job, Node } from '@/api/types'

const nodes = ref<Node[]>([])
const clusters = ref<Cluster[]>([])
const loading = ref(true)
const error = ref('')

// 每个节点同一时刻最多一个动作在跑：key 是节点 id，value 是动作名，用来给按钮加 loading。
const actionLoading = reactive<Record<string, string>>({})
// install-xdp / onboard 是异步 Job，需要展示进度条；key 是节点 id。
const jobProgress = reactive<Record<string, { progress: number; message: string }>>({})

const clusterName = computed(() => {
  const m: Record<string, string> = {}
  for (const c of clusters.value) m[c.id] = c.name
  return m
})

function errMessage(e: unknown): string {
  return e instanceof ApiClientError ? e.message : '操作失败'
}

async function load(silent = false) {
  if (!silent) loading.value = true
  error.value = ''
  try {
    const [n, c] = await Promise.all([listNodes(), listClusters()])
    nodes.value = n.items
    clusters.value = c.items
  } catch (e) {
    error.value = e instanceof ApiClientError ? e.message : '加载失败'
  } finally {
    loading.value = false
  }
}

// 在线状态由心跳/主控探测维护，列表页每 10 秒静默刷新一次。
let refreshTimer: ReturnType<typeof setInterval> | undefined
onMounted(() => {
  load()
  loadRegisterInfo()
  refreshTimer = setInterval(() => load(true), 10000)
})
onBeforeUnmount(() => clearInterval(refreshTimer))

function formatHeartbeat(ts: string | null): string {
  if (!ts) return '从未'
  const sec = Math.max(0, Math.round((Date.now() - new Date(ts).getTime()) / 1000))
  if (sec < 60) return `${sec} 秒前`
  if (sec < 3600) return `${Math.round(sec / 60)} 分钟前`
  return new Date(ts).toLocaleString()
}

// armed=false 的两种原因分开讲：enabled=0 是有人在 XDP 页把 L4 总开关关了，
// config_error 是写内核失败（cdn_xdp.o 与二进制字段对不上等）。后者必须原样带出来，
// 否则运维只能上节点翻 journal 才知道"面板显示已加载"为什么不等于在拦包。
function xdpNotArmedHint(n: Node): string {
  const x = n.status.xdp
  if (!x) return 'XDP 状态未知'
  const why: string[] = []
  if (!x.enabled) why.push('内核里的 enabled=0，L4 总开关是关的（在 XDP 页打开并保存）')
  if (x.config_error) why.push('最近一次写内核参数失败：' + x.config_error)
  if (!why.length) why.push('内核参数未确认生效，请重新下发一次 XDP 配置')
  return why.join('；') + '。程序仍挂在网卡上，但此时 L4 不拦任何包。'
}

// ---------------------------------------------------------------------------
// 版本可见性
// ---------------------------------------------------------------------------
//
// 「一致 / 落后 / 未知」的判据只有一份，在服务端（internal/apiv2/node_version.go），
// 这里只按 status.version_state 渲染。面板绝不自己比字符串：两份定义迟早分叉，
// 而分叉的后果是"看着标了最新，其实节点跑的是旧版"。
//
// 三种「未知」的处置动作完全不同，所以把原因翻成人话，不停在一个词上：
// 面板侧缺 cdnedge 是出包/上传问题（重装会直接失败），节点侧不上报是边缘太旧（重装一次就好）。
function versionLabel(n: Node): string {
  switch (n.status.version_state) {
    case 'match':
      return '已是最新'
    case 'outdated':
      return '版本落后'
    default:
      return '版本未知'
  }
}

function versionTagType(n: Node): 'success' | 'danger' | 'info' {
  switch (n.status.version_state) {
    case 'match':
      return 'success'
    case 'outdated':
      return 'danger'
    default:
      return 'info'
  }
}

function versionHint(n: Node): string {
  const st = n.status
  if (st.version_state === 'match') {
    return `节点上的 cdnedge 与面板准备下发的这份是同一个构建（${st.version}）。`
  }
  if (st.version_state === 'outdated') {
    return `节点跑的是 ${st.version}，面板这份 cdnedge 是 ${st.package_version}。点「重装最新版」把它换成面板这份。`
  }
  if (!st.package_version) {
    return '面板二进制同目录没有 cdnedge，或那个文件里没有 cdn-YYYYMMDD-HHMM 构建标识（不是 build.sh 出的包）。' +
      '这时无法判断节点是否最新，点「重装最新版」也会直接失败——先把新版 cdnedge 和 cdnpanel 一起传上去。'
  }
  if (!st.version) {
    return '该节点的 cdnedge 是旧版，不向上级上报自己的构建标识，所以判不出是否落后。' +
      '点「重装最新版」装上带标识的新版后，这一列就会开始说实话。'
  }
  if (st.version === 'dev' || st.package_version === 'dev') {
    const side = st.version === 'dev' ? '节点上那份' : '面板同目录那份'
    return `${side}的构建标识是 dev，说明它是本地 go build 的直接产物、没走 build.sh 打标，不能当作交付版本比对，所以不判「一致」。`
  }
  return '版本信息不足，无法判断。'
}

// ---------------------------------------------------------------------------
// 行内动作
// ---------------------------------------------------------------------------

function runJob(nodeId: string, job: Job, timeoutMs?: number): Promise<Job> {
  return pollJob(tenantApi, job.id, {
    timeoutMs,
    onProgress: (j) => {
      jobProgress[nodeId] = { progress: j.progress, message: j.message }
    },
  })
}

async function handleJob(n: Node, action: 'install-xdp' | 'onboard') {
  actionLoading[n.id] = action
  jobProgress[n.id] = { progress: 0, message: '正在提交任务...' }
  try {
    const job = action === 'install-xdp' ? await installXdp(n.id) : await onboardNode(n.id)
    const done = await runJob(n.id, job)
    if (done.status === 'done') {
      ElMessage.success(action === 'install-xdp' ? 'XDP 安装完成' : '配置已补发')
      if (done.warning) ElMessage.warning(done.warning)
      await load(true)
    } else {
      ElMessage.error(done.message || '任务失败')
    }
  } catch (e) {
    ElMessage.error(errMessage(e))
  } finally {
    delete actionLoading[n.id]
    delete jobProgress[n.id]
  }
}

async function handleToggle(n: Node) {
  actionLoading[n.id] = 'toggle'
  try {
    const updated = await patchNode(n.id, { enabled: !n.enabled }, n.version)
    replaceNode(updated)
    ElMessage.success(updated.enabled ? '已启用' : '已停用')
  } catch (e) {
    ElMessage.error(errMessage(e))
  } finally {
    delete actionLoading[n.id]
  }
}

async function handleDelete(n: Node) {
  try {
    await ElMessageBox.confirm(`确定删除节点「${n.name}」？删除后面板不再向它推送配置。`, '删除节点', {
      type: 'warning',
      confirmButtonText: '删除',
      cancelButtonText: '取消',
    })
  } catch {
    return
  }
  actionLoading[n.id] = 'delete'
  try {
    await deleteNode(n.id)
    nodes.value = nodes.value.filter((x) => x.id !== n.id)
    ElMessage.success('已删除')
  } catch (e) {
    ElMessage.error(errMessage(e))
  } finally {
    delete actionLoading[n.id]
  }
}

function replaceNode(updated: Node) {
  const idx = nodes.value.findIndex((x) => x.id === updated.id)
  if (idx >= 0) nodes.value[idx] = updated
}

// ---------------------------------------------------------------------------
// 手动添加 / 编辑
// ---------------------------------------------------------------------------

const editVisible = ref(false)
const editSaving = ref(false)
const editing = ref<Node | null>(null)
const editForm = reactive({
  name: '',
  address: '',
  token: '',
  ip: '',
  cert_fingerprint: '',
  cluster_id: '' as string,
})

function openCreate() {
  editing.value = null
  Object.assign(editForm, {
    name: '',
    address: 'https://',
    token: '',
    ip: '',
    cert_fingerprint: '',
    cluster_id: '',
  })
  editVisible.value = true
}

function openEdit(n: Node) {
  editing.value = n
  Object.assign(editForm, {
    name: n.name,
    address: n.address,
    token: '',
    ip: n.ip ?? '',
    cert_fingerprint: n.cert_fingerprint,
    cluster_id: n.cluster_id ?? '',
  })
  editVisible.value = true
}

async function saveEdit() {
  if (!editForm.name.trim() || !editForm.address.trim()) {
    ElMessage.error('名称和地址为必填项')
    return
  }
  editSaving.value = true
  try {
    if (editing.value) {
      const patch: Parameters<typeof patchNode>[1] = {
        name: editForm.name.trim(),
        address: editForm.address.trim(),
        ip: editForm.ip.trim() || null,
        cluster_id: editForm.cluster_id || null,
      }
      // token 留空表示不修改
      if (editForm.token) patch.token = editForm.token
      // 指纹同理：留空是"不改"，不能把已经登记好的指纹抹成空串 —— 那会让主控拒绝对
      // 该节点的一切推送，而用户只是点了个保存。清空指纹的唯一入口是填一个新值。
      const fp = editForm.cert_fingerprint.trim()
      if (fp) patch.cert_fingerprint = fp
      replaceNode(await patchNode(editing.value.id, patch, editing.value.version))
      ElMessage.success('已保存')
    } else {
      if (!editForm.token) {
        ElMessage.error('请填写节点 token')
        return
      }
      const created = await createNode({
        name: editForm.name.trim(),
        address: editForm.address.trim(),
        token: editForm.token,
        ip: editForm.ip.trim() || undefined,
        cert_fingerprint: editForm.cert_fingerprint.trim() || undefined,
        cluster_id: editForm.cluster_id || null,
      })
      nodes.value.unshift(created)
      ElMessage.success('已添加')
    }
    editVisible.value = false
  } catch (e) {
    ElMessage.error(errMessage(e))
  } finally {
    editSaving.value = false
  }
}

// ---------------------------------------------------------------------------
// SSH 一键部署
// ---------------------------------------------------------------------------

const deployVisible = ref(false)
const deploying = ref(false)
const deployJob = ref<{ progress: number; message: string; status: string } | null>(null)
// deployTarget 非空 = 从某个节点行进来的「重装最新版」。走的是同一个部署接口、同一个弹窗，
// 只是预填本机已知的地址/端口/网卡，并把后果在按钮之前讲清楚 —— 故意不做"无确认的一键升级"：
// 这条通道每次都会轮换节点 Token、重建该节点的数据库记录，是要人知情后点下去的动作。
const deployTarget = ref<Node | null>(null)
const deployForm = reactive({
  host: '',
  port: 22,
  user: 'root',
  auth: 'password' as 'password' | 'key',
  password: '',
  private_key: '',
  name: '',
  cluster_id: '',
  edge_port: 9090,
  xdp_iface: '',
})

// 面板能下发的那份 cdnedge 的构建标识（同一批数据里各行相同，取第一个说得清的）。
const packageVersion = computed(() => nodes.value.find((n) => n.status.package_version)?.status.package_version || '')

// 面板同目录那份 cdnedge 读不出构建标识时，后端一定是在"未找到 cdnedge 二进制文件"上失败。
// 既然本地就已经知道会失败，就别让人白等一次 SSH 连接 —— 按钮直接禁用，原因写在上面那段提示里。
const reinstallBlocked = computed(() => !!deployTarget.value && !packageVersion.value)

// SSH 主机：公网 IP 是解析用的，部署要用节点登记的地址；address 形如 https://1.2.3.4:9090。
function sshHostOf(n: Node): string {
  const raw = (n.ip || n.address || '').trim()
  if (!raw) return ''
  try {
    return new URL(raw.includes('://') ? raw : `https://${raw}`).hostname
  } catch {
    return raw
  }
}

function sshPortOf(n: Node, fallback: number): number {
  const raw = (n.address || '').trim()
  if (!raw) return fallback
  try {
    const p = new URL(raw.includes('://') ? raw : `https://${raw}`).port
    return p ? Number(p) : fallback
  } catch {
    return fallback
  }
}

function openDeploy(node?: Node) {
  deployTarget.value = node ?? null
  if (node) {
    Object.assign(deployForm, {
      host: sshHostOf(node),
      port: 22,
      user: 'root',
      auth: 'password',
      password: '',
      private_key: '',
      name: node.name,
      cluster_id: node.cluster_id || '',
      edge_port: sshPortOf(node, 9090),
      // 心跳里带回来的就是当前挂载的网卡，沿用它是为了不在重装时把 XDP 挪到别的口上。
      xdp_iface: node.status.xdp?.iface || '',
    })
    deployJob.value = null
    deployVisible.value = true
    return
  }
  Object.assign(deployForm, {
    host: '',
    port: 22,
    user: 'root',
    auth: 'password',
    password: '',
    private_key: '',
    name: '',
    cluster_id: '',
    edge_port: 9090,
    xdp_iface: '',
  })
  deployJob.value = null
  deployVisible.value = true
}

async function submitDeploy() {
  if (!deployForm.host.trim()) {
    ElMessage.error('请填写服务器地址')
    return
  }
  if (deployForm.auth === 'password' ? !deployForm.password : !deployForm.private_key.trim()) {
    ElMessage.error(deployForm.auth === 'password' ? '请填写 SSH 密码' : '请填写 SSH 私钥')
    return
  }
  const reinstall = deployTarget.value
  deploying.value = true
  deployJob.value = { progress: 0, message: '正在连接 SSH...', status: 'running' }
  try {
    const job = await deployNode({
      host: deployForm.host.trim(),
      port: deployForm.port,
      user: deployForm.user.trim() || 'root',
      password: deployForm.auth === 'password' ? deployForm.password : undefined,
      private_key: deployForm.auth === 'key' ? deployForm.private_key : undefined,
      name: deployForm.name.trim() || deployForm.host.trim(),
      cluster_id: deployForm.cluster_id || null,
      edge_port: deployForm.edge_port,
      xdp_iface: deployForm.xdp_iface.trim() || undefined,
    })
    // 凭据已经提交给后端（只在内存里用一次），前端也立即清掉。
    deployForm.password = ''
    deployForm.private_key = ''
    const done = await pollJob(tenantApi, job.id, {
      timeoutMs: 15 * 60 * 1000,
      onProgress: (j) => {
        deployJob.value = { progress: j.progress, message: j.message, status: j.status }
      },
    })
    deployJob.value = { progress: done.progress, message: done.message, status: done.status }
    if (done.status === 'done') {
      // 这台机器以前装过：后端已把旧节点记录删掉换成新的（等同删除后重装）。
      const replaced = (done.result as { replaced_node_id?: string } | null)?.replaced_node_id
      ElMessage.success(
        reinstall
          ? '重装完成，该节点已换成面板这份 cdnedge'
          : replaced
            ? '部署完成（检测到该机器已安装过，已替换原节点记录）'
            : '部署完成',
      )
      if (done.warning) ElMessage.warning(done.warning)
      deployVisible.value = false
      deployTarget.value = null
      await load(true)
    } else {
      ElMessage.error(done.message || '部署失败')
    }
  } catch (e) {
    deployJob.value = { progress: 0, message: errMessage(e), status: 'failed' }
    ElMessage.error(errMessage(e))
  } finally {
    deploying.value = false
  }
}

// ---------------------------------------------------------------------------
// 自动注册（install.sh）
// ---------------------------------------------------------------------------

const registerInfo = ref<{ secret_set: boolean; secret_hint: string; install_command: string } | null>(null)
// 轮换后的明文密钥只有这一次能看到，关页面就没了。
const freshSecret = ref('')
const rotating = ref(false)
const registerCluster = ref('')

async function loadRegisterInfo() {
  try {
    registerInfo.value = await getEdgeRegisterInfo()
  } catch {
    registerInfo.value = null
  }
}

const installCommand = computed(() => {
  const cmd = registerInfo.value?.install_command ?? ''
  return registerCluster.value ? `CLUSTER_ID=${registerCluster.value} ${cmd}` : cmd
})

async function handleRotate() {
  if (registerInfo.value?.secret_set) {
    try {
      await ElMessageBox.confirm(
        '生成新密钥后旧密钥立即失效，尚未注册的节点需要换成新命令（已注册节点不受影响）。',
        '重新生成注册密钥',
        { type: 'warning', confirmButtonText: '生成', cancelButtonText: '取消' },
      )
    } catch {
      return
    }
  }
  rotating.value = true
  try {
    const res = await rotateEdgeRegisterSecret()
    freshSecret.value = res.secret
    registerInfo.value = {
      secret_set: true,
      secret_hint: registerInfo.value?.secret_hint ?? '',
      install_command: res.install_command,
    }
    await loadRegisterInfoHintOnly()
    ElMessage.success('已生成新密钥，请立即复制保存')
  } catch (e) {
    ElMessage.error(errMessage(e))
  } finally {
    rotating.value = false
  }
}

// 刷新 hint，但保留带明文密钥的安装命令。
async function loadRegisterInfoHintOnly() {
  try {
    const info = await getEdgeRegisterInfo()
    if (registerInfo.value) registerInfo.value.secret_hint = info.secret_hint
  } catch {
    /* 忽略 */
  }
}

async function copy(text: string) {
  try {
    await navigator.clipboard.writeText(text)
    ElMessage.success('已复制')
  } catch {
    ElMessage.error('复制失败，请手动选中复制')
  }
}
</script>

<template>
  <div>
    <div class="header">
      <h1>节点</h1>
      <div>
        <el-button @click="load()">刷新</el-button>
        <el-button @click="openCreate">手动添加</el-button>
        <el-button type="primary" @click="openDeploy()">SSH 一键部署</el-button>
      </div>
    </div>
    <el-alert v-if="error" :title="error" type="error" show-icon :closable="false" class="alert" />

    <el-table v-loading="loading" :data="nodes" style="width: 100%">
      <el-table-column prop="name" label="名称" min-width="130" />
      <el-table-column label="地址" min-width="180">
        <template #default="{ row }">
          <div>{{ row.address }}</div>
          <div class="sub">Token: {{ row.token_set ? '••••' + (row.token_hint || '') : '未设置' }}</div>
          <!-- 控制面通道钉没钉扎要在这里说：没登记指纹的节点，主控会拒绝它的一切推送
               （CC/XDP 阈值、封禁名单、域名私钥都走这条路）。不提前标出来，用户只会在点
               「保存」之后撞上一条看起来和这台机器状态无关的失败。 -->
          <el-tooltip
            v-if="!row.tls_pinned"
            content="该节点没有登记证书指纹，主控无法对这条控制面通道做证书钉扎，因此拒绝向它推送任何配置。恢复：在边缘节点执行 journalctl -u cdnedge | grep 'Certificate fingerprint' 取 SHA-256 指纹，填进本节点的「证书指纹」后保存；用「SSH 一键部署」或以 --master 启动的 cdnedge 会在注册时自动上报，无需手填。"
            placement="top"
          >
            <div class="sub warn">控制面未钉扎 · 推送已被拒绝</div>
          </el-tooltip>
        </template>
      </el-table-column>
      <el-table-column label="集群" min-width="100">
        <template #default="{ row }">
          {{ row.cluster_id ? clusterName[row.cluster_id] ?? row.cluster_id : '未分配' }}
        </template>
      </el-table-column>
      <el-table-column label="状态" min-width="120">
        <template #default="{ row }">
          <el-tag :type="!row.enabled ? 'info' : row.status.online ? 'success' : 'danger'">
            {{ !row.enabled ? '已停用' : row.status.online ? '在线' : '离线' }}
          </el-tag>
          <el-tooltip v-if="row.dns_paused" content="带宽持续打满，已暂时从集群解析摘除，带宽恢复 10 分钟后自动加回" placement="top">
            <el-tag type="warning" class="dns-paused">已摘除解析</el-tag>
          </el-tooltip>
          <div class="sub">{{ formatHeartbeat(row.status.last_heartbeat_at) }}</div>
        </template>
      </el-table-column>
      <!-- 版本列紧跟状态，且刻意不做成右侧固定列。它固定过一次，量出来的结果是窄屏上
           「版本 + 操作」两块固定列合计 480px，会把最左边的名称列整个盖住 —— 连这是哪台
           机器都认不出来，比藏掉版本号更糟。放到状态后面、并把前面几列的 min-width 各收
           10px，是为了让它在常见桌面宽度下不进横向滚动区就能看到。 -->
      <el-table-column label="版本" min-width="180">
        <template #default="{ row }">
          <el-tooltip :content="versionHint(row)" :trigger="['hover', 'click']" placement="top">
            <el-tag :type="versionTagType(row)">{{ versionLabel(row) }}</el-tag>
          </el-tooltip>
          <!-- 两个标识各占一行且不拆开：构建号本身就是"哪一次出包"，折成两截就没人能对得上了。
               落后与否一眼看标签，具体差在哪个包看这两行。 -->
          <div class="sub ver">节点 {{ row.status.version || '未上报' }}</div>
          <div class="sub ver">面板 {{ row.status.package_version || '无 cdnedge' }}</div>
        </template>
      </el-table-column>
      <el-table-column label="负载" min-width="150">
        <template #default="{ row }">
          <template v-if="row.status.online">
            <div class="sub">CPU {{ row.status.cpu_percent.toFixed(1) }}%</div>
            <div class="sub">内存 {{ row.status.mem_percent.toFixed(1) }}%</div>
            <div class="sub">连接 {{ row.status.connections }}</div>
          </template>
          <span v-else class="sub">-</span>
        </template>
      </el-table-column>
      <el-table-column label="XDP" min-width="150">
        <template #default="{ row }">
          <template v-if="row.status.xdp?.attached">
            <!-- 挂着 ≠ 在拦包：内核 enabled=0 或最近一次写 xdp_config 失败时，程序仍在
                 网卡上但一个包都不判。以前这种节点显示"已加载"，运维以为洪水已被挡在
                 内核外，实际 L4 裸奔——所以 armed=false 单独一档，并把原因原样给出。 -->
            <el-tooltip
              v-if="row.status.xdp.armed === false"
              :content="xdpNotArmedHint(row)"
              placement="top"
            >
              <el-tag type="danger">已加载 · 未生效</el-tag>
            </el-tooltip>
            <el-tooltip
              v-else-if="row.status.xdp.mode === 'generic'"
              content="网卡驱动不支持原生 XDP，已回落 SKB(generic) 模式：每个包仍要先分配内核 skb，大流量下 CPU 会先于带宽打满"
              placement="top"
            >
              <el-tag type="warning">已生效 · 兼容模式</el-tag>
            </el-tooltip>
            <el-tag v-else-if="row.status.xdp.mode === 'native'" type="success">已生效 · 原生</el-tag>
            <el-tooltip
              v-else
              :content="
                row.status.xdp.armed == null
                  ? '该节点的 cdnedge 是旧版本，只上报「挂在网卡上」，不上报阈值是否真的写进了内核；请用新版 cdnedge 重新部署后确认 L4 是否在生效'
                  : '该节点的 cdnedge 是旧版本，不上报挂载模式与网卡；请用新版 cdnedge 重新部署后再判断是否为原生模式'
              "
              placement="top"
            >
              <el-tag :type="row.status.xdp.armed ? 'success' : 'warning'">
                {{ row.status.xdp.armed ? '已生效 · 模式未知' : '已加载 · 模式未知' }}
              </el-tag>
            </el-tooltip>
            <div v-if="row.status.xdp.iface" class="sub">网卡 {{ row.status.xdp.iface }}</div>
            <div v-else-if="!row.status.xdp.mode" class="sub">边缘版本过旧</div>
            <!-- 每 CPU 的新连接总量闸门：面板上要能还原成"这台机器一秒放行多少个新建连接"，
                 否则调了 cpu_syn_limit 也看不出实际效果。0 与"旧边缘没上报"要分开显示：
                 0 是一条有效结论（闸门关着），多数来自升级前存下的阈值存档。 -->
            <el-tooltip
              v-if="row.status.xdp.armed && row.status.xdp.cpu_syn_limit === 0"
              content="cpu_syn_limit=0：每包换一个伪造源的 SYN 洪水在 L4 没有总量闸门（per-IP 阈值对它永远碰不到）。通常是节点的 xdp_config 存档里带着旧默认值，到 XDP 页重新保存一次阈值即可按总预算下发。"
              placement="top"
            >
              <div class="sub warn">SYN 总量闸门关闭</div>
            </el-tooltip>
            <div v-else-if="row.status.xdp.cpu_syn_limit" class="sub">
              SYN 总量 {{ row.status.xdp.cpu_syn_limit }} ×
              {{ row.status.xdp.rx_queues || 1 }} 核/s
            </div>
          </template>
          <el-tag v-else type="info">未加载</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="操作" min-width="300" fixed="right">
        <template #default="{ row }">
          <el-button size="small" :disabled="!!actionLoading[row.id]" @click="openEdit(row)">编辑</el-button>
          <el-button
            size="small"
            :loading="actionLoading[row.id] === 'toggle'"
            :disabled="!!actionLoading[row.id] && actionLoading[row.id] !== 'toggle'"
            @click="handleToggle(row)"
          >
            {{ row.enabled ? '停用' : '启用' }}
          </el-button>
          <el-button
            size="small"
            type="primary"
            :disabled="!!actionLoading[row.id]"
            @click="openDeploy(row)"
          >
            重装最新版
          </el-button>
          <!-- 补发配置 / 安装 XDP / 删除收进「更多」：这一列要放得下新按钮，而规则是不砍字、
               挤不下就折叠（和域名列表同一套）。动作本身没变，都还带文字。 -->
          <el-dropdown trigger="click" :disabled="!!actionLoading[row.id]">
            <el-button size="small" :loading="['onboard', 'install-xdp', 'delete'].includes(actionLoading[row.id])">
              更多
            </el-button>
            <template #dropdown>
              <el-dropdown-menu>
                <el-dropdown-item @click="handleJob(row, 'onboard')">补发配置</el-dropdown-item>
                <el-dropdown-item @click="handleJob(row, 'install-xdp')">安装 XDP</el-dropdown-item>
                <el-dropdown-item divided @click="handleDelete(row)">
                  <span style="color: var(--el-color-danger)">删除节点</span>
                </el-dropdown-item>
              </el-dropdown-menu>
            </template>
          </el-dropdown>
          <div v-if="jobProgress[row.id]" class="job-progress">
            <el-progress :percentage="jobProgress[row.id].progress" :stroke-width="4" />
            <span class="job-message">{{ jobProgress[row.id].message }}</span>
          </div>
        </template>
      </el-table-column>
      <template #empty>暂无节点</template>
    </el-table>

    <el-card class="register-card" shadow="never">
      <template #header>自动注册（在边缘服务器上执行安装脚本）</template>
      <p class="sub">
        在边缘服务器的项目源码目录执行下面的命令，节点装好后会用注册密钥自动加入本租户并开始心跳。
        注册密钥只保存哈希，明文只在生成时显示一次。
      </p>
      <div class="register-row">
        <span>注册密钥：</span>
        <el-tag v-if="registerInfo?.secret_set" type="success">已设置 {{ registerInfo.secret_hint }}</el-tag>
        <el-tag v-else type="warning">未设置</el-tag>
        <el-button size="small" :loading="rotating" @click="handleRotate">
          {{ registerInfo?.secret_set ? '重新生成' : '生成密钥' }}
        </el-button>
      </div>
      <el-alert v-if="freshSecret" type="warning" :closable="false" show-icon class="alert">
        <template #title>
          新密钥（仅显示这一次）：<code>{{ freshSecret }}</code>
          <el-button link type="primary" @click="copy(freshSecret)">复制</el-button>
        </template>
      </el-alert>
      <div class="register-row">
        <span>加入集群：</span>
        <el-select v-model="registerCluster" placeholder="不指定" clearable style="width: 220px">
          <el-option v-for="c in clusters" :key="c.id" :label="c.name" :value="c.id" />
        </el-select>
      </div>
      <div v-if="registerInfo" class="command">
        <code>{{ installCommand }}</code>
        <el-button size="small" @click="copy(installCommand)">复制命令</el-button>
      </div>
      <p v-if="registerInfo && !freshSecret" class="sub">
        命令里的 &lt;注册密钥&gt; 需替换为生成时保存的密钥；忘记了就重新生成。
      </p>
    </el-card>

    <!-- 手动添加 / 编辑 -->
    <el-dialog v-model="editVisible" :title="editing ? '编辑节点' : '手动添加节点'" width="520px">
      <el-form label-width="90px" @submit.prevent>
        <el-form-item label="名称" required>
          <el-input v-model="editForm.name" />
        </el-form-item>
        <el-form-item label="地址" required>
          <el-input v-model="editForm.address" placeholder="https://1.2.3.4:9090" />
        </el-form-item>
        <el-form-item label="Token" :required="!editing">
          <el-input
            v-model="editForm.token"
            type="password"
            show-password
            autocomplete="new-password"
            :placeholder="editing ? '留空表示不修改' : '边缘节点 /etc/cdnpanel/edge.token 的内容'"
          />
        </el-form-item>
        <el-form-item label="公网 IP">
          <el-input v-model="editForm.ip" placeholder="用于 DNS 解析，可留空" />
        </el-form-item>
        <!-- 恢复路径要在界面上真的存在：推送被拒后主控让人"填入证书指纹"，可这个字段
             之前只有 API 有、面板没有，手动添加的节点就死在无入口上。 -->
        <el-form-item label="证书指纹">
          <el-input v-model="editForm.cert_fingerprint" placeholder="AA:BB:CC:...，64 位十六进制也可" />
          <div class="field-hint">
            主控只向登记了指纹的节点推送配置 —— 没有钉扎时中间人可以改写下发的 CC/XDP 阈值、封禁名单和域名私钥。
            取指纹：在边缘节点执行
            <code>journalctl -u cdnedge | grep 'Certificate fingerprint'</code>。
            经「SSH 一键部署」或以 --master 启动的 cdnedge 会在注册时自动上报，无需手填；编辑时留空表示不修改。
          </div>
        </el-form-item>
        <el-form-item label="集群">
          <el-select v-model="editForm.cluster_id" placeholder="不分配" clearable style="width: 100%">
            <el-option v-for="c in clusters" :key="c.id" :label="c.name" :value="c.id" />
          </el-select>
          <div class="field-hint">节点会加入该集群，并在代理的 Cloudflare 上自动建一条灰云 A 记录（集群子域名 → 节点 IP）</div>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="editVisible = false">取消</el-button>
        <el-button type="primary" :loading="editSaving" @click="saveEdit">保存</el-button>
      </template>
    </el-dialog>

    <!-- SSH 一键部署 / 重装最新版（同一个弹窗、同一个接口） -->
    <el-dialog
      v-model="deployVisible"
      :title="deployTarget ? `重装最新版：${deployTarget.name}` : 'SSH 一键部署边缘节点'"
      width="560px"
      :close-on-click-modal="!deploying"
      :close-on-press-escape="!deploying"
      :show-close="!deploying"
    >
      <!-- 重装的后果必须点在按钮之前，而不是做完再解释：这条通道每次都会换掉节点 Token、
           用同 IP 重建节点记录（ID 会变）、重写边缘的 config.json。它不是"原地换个二进制"。 -->
      <el-alert v-if="deployTarget" type="warning" :closable="false" show-icon class="alert">
        <template #title>这将重跑一次完整部署，不只是换个二进制文件</template>
        <div class="consequences">
          <div>· 下发的 cdnedge：{{ packageVersion || '面板同目录读不到构建标识，本次重装会在连接后立即失败' }}</div>
          <div>· 节点 Token 重新生成并下发；面板与该机器的旧记录按同 IP 替换，节点 ID 会变（旧 ID 的引用失效）</div>
          <div>· 重写边缘的 /etc/cdnpanel/config.json；cdnedge 服务会重启，Tengine 走平滑 reload，站点不中断</div>
          <div>· 节点上若缺 lua-nginx-module 会触发 Tengine 重新编译，整轮 5–15 分钟</div>
          <div>· 不做卸载：不停 Tengine、不删站点、不清防火墙；部署成功后面板会自动补发该集群的域名配置</div>
          <div>· 已登记的 SSH 凭据不会被保存，所以每次都要重填一次</div>
        </div>
      </el-alert>
      <el-form label-width="100px" :disabled="deploying" @submit.prevent>
        <el-form-item label="服务器地址" required>
          <el-input v-model="deployForm.host" placeholder="IP 或主机名" />
        </el-form-item>
        <el-form-item label="SSH 端口">
          <el-input-number v-model="deployForm.port" :min="1" :max="65535" controls-position="right" />
        </el-form-item>
        <el-form-item label="用户名">
          <el-input v-model="deployForm.user" />
        </el-form-item>
        <el-form-item label="认证方式">
          <el-radio-group v-model="deployForm.auth">
            <el-radio value="password">密码</el-radio>
            <el-radio value="key">私钥</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item v-if="deployForm.auth === 'password'" label="密码" required>
          <el-input v-model="deployForm.password" type="password" show-password autocomplete="new-password" />
        </el-form-item>
        <el-form-item v-else label="私钥" required>
          <el-input
            v-model="deployForm.private_key"
            type="textarea"
            :rows="4"
            placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
          />
        </el-form-item>
        <el-form-item label="节点名称">
          <el-input v-model="deployForm.name" placeholder="默认为服务器地址" />
        </el-form-item>
        <el-form-item label="集群">
          <el-select v-model="deployForm.cluster_id" placeholder="不分配" clearable style="width: 100%">
            <el-option v-for="c in clusters" :key="c.id" :label="c.name" :value="c.id" />
          </el-select>
          <div class="field-hint">节点会加入该集群，并在代理的 Cloudflare 上自动建一条灰云 A 记录（集群子域名 → 节点 IP）</div>
        </el-form-item>
        <el-form-item label="边缘端口">
          <el-input-number v-model="deployForm.edge_port" :min="1" :max="65535" controls-position="right" />
        </el-form-item>
        <el-form-item label="XDP 网卡">
          <el-input v-model="deployForm.xdp_iface" placeholder="留空自动检测" />
        </el-form-item>
      </el-form>
      <p class="sub">SSH 凭据只用于本次部署，不会保存到服务器或数据库。</p>
      <div v-if="deployJob" class="deploy-progress">
        <el-progress
          :percentage="deployJob.progress"
          :status="deployJob.status === 'done' ? 'success' : deployJob.status === 'failed' ? 'exception' : undefined"
        />
        <div class="job-message">{{ deployJob.message }}</div>
      </div>
      <template #footer>
        <el-button :disabled="deploying" @click="deployVisible = false">关闭</el-button>
        <el-button
          type="primary"
          :loading="deploying"
          :disabled="reinstallBlocked"
          @click="submitDeploy"
        >
          {{ deployTarget ? '重装最新版' : '开始部署' }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
.field-hint {
  font-size: 12px;
  line-height: 1.6;
  margin-top: 4px;
  color: var(--text-dim, #999);
}
.header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.alert {
  margin-bottom: 16px;
}
.sub {
  font-size: 12px;
  color: #999;
}
.sub.warn {
  color: var(--el-color-danger);
}
.job-progress {
  margin-top: 6px;
  width: 220px;
}
.job-message {
  font-size: 12px;
  color: #999;
}
.dns-paused {
  margin-left: 6px;
}
.register-card {
  margin-top: 24px;
}
.register-row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 10px 0;
}
.command {
  display: flex;
  align-items: center;
  gap: 8px;
  background: #1f2430;
  color: #e6e6e6;
  padding: 10px 12px;
  border-radius: 6px;
  margin-top: 8px;
}
.command code {
  flex: 1;
  word-break: break-all;
  font-size: 13px;
}
.deploy-progress {
  margin-top: 12px;
}
.consequences {
  font-size: 12px;
  line-height: 1.7;
  font-weight: 400;
}
.ver {
  white-space: nowrap;
}
</style>
