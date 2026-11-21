<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { listClusters, createCluster, patchCluster, deleteCluster, triggerFailover } from '@/api/clusters'
import type { Cluster } from '@/api/types'
import { ApiClientError } from '@/api/client'

const clusters = ref<Cluster[]>([])
const loading = ref(true)
const error = ref('')

// 每个集群同一时刻最多一个动作在跑：key 是集群 id，value 是动作名，用来给按钮加 loading。
const actionLoading = reactive<Record<string, string>>({})

const healthLabel: Record<string, string> = {
  active: '正常',
  degraded: '降级',
  failed: '故障',
  failover_in_progress: '切换中',
  failover_complete: '已切换',
}
const healthTag: Record<string, 'success' | 'warning' | 'danger' | 'info'> = {
  active: 'success',
  degraded: 'warning',
  failed: 'danger',
  failover_in_progress: 'warning',
  failover_complete: 'info',
}
const roleLabel: Record<string, string> = {
  primary: '主集群',
  backup: '备用集群',
  normal: '普通',
}

const clusterName = computed(() => {
  const m: Record<string, string> = {}
  for (const c of clusters.value) m[c.id] = c.name
  return m
})

async function load() {
  loading.value = true
  error.value = ''
  try {
    const res = await listClusters()
    clusters.value = res.items
  } catch (e) {
    error.value = e instanceof ApiClientError ? e.message : '加载失败'
  } finally {
    loading.value = false
  }
}

function errMessage(e: unknown): string {
  return e instanceof ApiClientError ? e.message : '操作失败'
}

function replaceCluster(updated: Cluster) {
  const idx = clusters.value.findIndex((x) => x.id === updated.id)
  if (idx >= 0) clusters.value[idx] = updated
}

async function handleFailover(c: Cluster, action: 'trigger' | 'cancel') {
  if (action === 'trigger') {
    try {
      await ElMessageBox.confirm(`确定把集群「${c.name}」的流量切走？`, '触发故障转移', {
        type: 'warning',
        confirmButtonText: '触发',
        cancelButtonText: '取消',
      })
    } catch {
      return
    }
  }
  actionLoading[c.id] = 'failover'
  try {
    replaceCluster(await triggerFailover(c.id, action))
    ElMessage.success(action === 'trigger' ? '已触发故障转移' : '已取消故障转移')
  } catch (e) {
    ElMessage.error(errMessage(e))
  } finally {
    delete actionLoading[c.id]
  }
}

async function handleDelete(c: Cluster) {
  try {
    await ElMessageBox.confirm(`确定删除集群「${c.name}」？`, '删除集群', {
      type: 'warning',
      confirmButtonText: '删除',
      cancelButtonText: '取消',
    })
  } catch {
    return
  }
  actionLoading[c.id] = 'delete'
  try {
    await deleteCluster(c.id)
    clusters.value = clusters.value.filter((x) => x.id !== c.id)
    ElMessage.success('已删除')
  } catch (e) {
    if (e instanceof ApiClientError && e.code === 'in_use') {
      ElMessage.error('集群下仍有节点或域名，请先把它们移到其他集群或删除')
    } else {
      ElMessage.error(errMessage(e))
    }
  } finally {
    delete actionLoading[c.id]
  }
}

// ---------------------------------------------------------------------------
// 新建 / 编辑
// ---------------------------------------------------------------------------

const editVisible = ref(false)
const editSaving = ref(false)
const editing = ref<Cluster | null>(null)
const editForm = reactive({
  name: '',
  description: '',
  defense_cname: '',
  role: 'normal' as Cluster['role'],
  auto: false,
  threshold: 50,
  target_cluster_id: '',
  bw_limit: 0,
  bw_danger: 90,
})

// 带宽占用百分比（相对单节点上限），没设上限或没有上报时返回 null。
function bwPercent(c: Cluster): number | null {
  const limit = c.bandwidth?.limit_mbps ?? 0
  const peak = c.health.bw_peak_mbps
  if (!limit || peak == null) return null
  return Math.min(100, Math.round((peak / limit) * 100))
}
function bwStatus(c: Cluster): 'success' | 'warning' | 'exception' {
  const p = bwPercent(c) ?? 0
  const danger = c.bandwidth?.danger_percent || 90
  if (p >= danger) return 'exception'
  if (p >= danger * 0.75) return 'warning'
  return 'success'
}

// 故障转移目标只能是其他集群。
const targetOptions = computed(() => clusters.value.filter((c) => c.id !== editing.value?.id))

function openCreate() {
  editing.value = null
  Object.assign(editForm, {
    name: '',
    description: '',
    defense_cname: '',
    role: 'normal',
    auto: false,
    threshold: 50,
    target_cluster_id: '',
    bw_limit: 0,
    bw_danger: 90,
  })
  editVisible.value = true
}

function openEdit(c: Cluster) {
  editing.value = c
  Object.assign(editForm, {
    name: c.name,
    description: c.description,
    defense_cname: c.defense_cname,
    role: c.role,
    auto: c.failover.auto,
    threshold: c.failover.threshold || 50,
    target_cluster_id: c.failover.target_cluster_id ?? '',
    bw_limit: c.bandwidth?.limit_mbps ?? 0,
    bw_danger: c.bandwidth?.danger_percent || 90,
  })
  editVisible.value = true
}

async function saveEdit() {
  if (!editing.value && !editForm.name.trim()) {
    ElMessage.error('请填写集群名称')
    return
  }
  // 名称同时是 CF 子域名前缀，必须是合法 DNS label（与后端 validClusterName 一致）。
  if (!editing.value && !/^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$/.test(editForm.name.trim())) {
    ElMessage.error('集群名称只能用小写字母、数字和 -，不能以 - 开头或结尾，最长 63 位')
    return
  }
  editSaving.value = true
  try {
    const body = {
      description: editForm.description.trim(),
      defense_cname: editForm.defense_cname.trim(),
      role: editForm.role,
      failover: {
        auto: editForm.auto,
        threshold: editForm.threshold,
        target_cluster_id: editForm.target_cluster_id || null,
      },
      bandwidth: {
        limit_mbps: editForm.bw_limit || 0,
        danger_percent: editForm.bw_danger || 90,
      },
    }
    if (editing.value) {
      // name 不可修改（子域名由它派生），PATCH 只能带可写字段。
      replaceCluster(await patchCluster(editing.value.id, body, editing.value.version))
      ElMessage.success('已保存')
    } else {
      clusters.value.push(await createCluster({ name: editForm.name.trim(), ...body }))
      ElMessage.success('已创建')
    }
    editVisible.value = false
  } catch (e) {
    ElMessage.error(errMessage(e))
  } finally {
    editSaving.value = false
  }
}

// 监控每 30 秒检查一次，页面跟着刷新带宽与连续超限次数。
let timer: number | undefined
onMounted(() => {
  load()
  timer = window.setInterval(async () => {
    try {
      clusters.value = (await listClusters()).items
    } catch {
      /* 静默刷新失败时保留上一次数据 */
    }
  }, 30000)
})
onBeforeUnmount(() => window.clearInterval(timer))
</script>

<template>
  <div>
    <div class="header">
      <h1>集群</h1>
      <div>
        <el-button @click="load">刷新</el-button>
        <el-button type="primary" @click="openCreate">新建集群</el-button>
      </div>
    </div>
    <el-alert v-if="error" :title="error" type="error" show-icon :closable="false" class="alert" />
    <el-table v-loading="loading" :data="clusters" style="width: 100%">
      <el-table-column label="名称" min-width="140">
        <template #default="{ row }">
          <div>{{ row.name }}</div>
          <div v-if="row.description" class="sub">{{ row.description }}</div>
        </template>
      </el-table-column>
      <el-table-column prop="subdomain" label="子域名" min-width="180" />
      <el-table-column label="角色" min-width="100">
        <template #default="{ row }">{{ roleLabel[row.role] ?? row.role }}</template>
      </el-table-column>
      <el-table-column label="状态" min-width="110">
        <template #default="{ row }">
          <el-tag :type="healthTag[row.health.status] ?? 'info'">
            {{ healthLabel[row.health.status] ?? row.health.status }}
          </el-tag>
          <div v-if="row.health.auto_switched" class="sub">自动切换，稳定 1 小时后自动切回</div>
          <el-tooltip v-if="row.health.last_reason" :content="row.health.last_reason" placement="top">
            <div class="sub warn-text">{{ row.health.fail_streak > 0 ? `超限 ${row.health.fail_streak}/3` : '查看原因' }}</div>
          </el-tooltip>
        </template>
      </el-table-column>
      <el-table-column label="带宽（峰值节点）" min-width="190">
        <template #default="{ row }">
          <template v-if="row.bandwidth?.limit_mbps">
            <template v-if="bwPercent(row) !== null">
              <el-progress
                :percentage="bwPercent(row) ?? 0"
                :status="bwStatus(row)"
                :stroke-width="8"
                :aria-label="`峰值节点带宽占上限 ${bwPercent(row)}%`"
              />
              <div class="sub">
                {{ row.health.bw_peak_mbps?.toFixed(1) }} / {{ row.bandwidth.limit_mbps }} Mbps
                <span v-if="row.health.bw_peak_node"> · {{ row.health.bw_peak_node }}</span>
              </div>
            </template>
            <span v-else class="sub">上限 {{ row.bandwidth.limit_mbps }} Mbps · 等待节点上报</span>
            <div class="sub">
              打满 {{ row.health.bw_saturated_nodes ?? 0 }}/{{ row.health.total_nodes }} 台 · 可用率 &lt; {{ row.failover.threshold }}% 连续 3 次切高防
            </div>
            <div v-if="row.health.dns_paused_nodes" class="sub warn-text">
              {{ row.health.dns_paused_nodes }} 台已暂时摘除解析，恢复后自动加回
            </div>
          </template>
          <span v-else class="sub">未设置</span>
        </template>
      </el-table-column>
      <el-table-column label="在线节点" min-width="100">
        <template #default="{ row }">{{ row.health.online_nodes }} / {{ row.health.total_nodes }}</template>
      </el-table-column>
      <el-table-column label="自动故障转移" min-width="150">
        <template #default="{ row }">
          <template v-if="row.failover.auto">
            <div>在线率 &lt; {{ row.failover.threshold }}%</div>
            <div class="sub">
              切到
              {{
                row.failover.target_cluster_id
                  ? clusterName[row.failover.target_cluster_id] ?? row.failover.target_cluster_id
                  : '高防 CNAME'
              }}
            </div>
          </template>
          <span v-else class="sub">关闭</span>
        </template>
      </el-table-column>
      <el-table-column label="操作" min-width="280" fixed="right">
        <template #default="{ row }">
          <el-button size="small" :disabled="!!actionLoading[row.id]" @click="openEdit(row)">编辑</el-button>
          <el-button
            v-if="row.health.status !== 'failover_in_progress'"
            size="small"
            type="warning"
            :loading="actionLoading[row.id] === 'failover'"
            :disabled="!!actionLoading[row.id] && actionLoading[row.id] !== 'failover'"
            @click="handleFailover(row, 'trigger')"
          >
            触发故障转移
          </el-button>
          <el-button
            v-else
            size="small"
            :loading="actionLoading[row.id] === 'failover'"
            :disabled="!!actionLoading[row.id] && actionLoading[row.id] !== 'failover'"
            @click="handleFailover(row, 'cancel')"
          >
            取消故障转移
          </el-button>
          <el-button
            size="small"
            type="danger"
            :loading="actionLoading[row.id] === 'delete'"
            :disabled="!!actionLoading[row.id] && actionLoading[row.id] !== 'delete'"
            @click="handleDelete(row)"
          >
            删除
          </el-button>
        </template>
      </el-table-column>
      <template #empty>暂无集群</template>
    </el-table>

    <el-dialog v-model="editVisible" :title="editing ? '编辑集群' : '新建集群'" width="560px">
      <el-form label-width="110px" @submit.prevent>
        <el-form-item label="名称" required>
          <el-input v-model="editForm.name" :disabled="!!editing" placeholder="小写字母/数字/-，如 hk-01，创建后不可修改" />
        </el-form-item>
        <el-form-item label="描述">
          <el-input v-model="editForm.description" />
        </el-form-item>
        <el-form-item label="高防 CNAME">
          <el-input v-model="editForm.defense_cname" placeholder="第三方高防提供的 CNAME，可留空" />
        </el-form-item>
        <el-form-item label="角色">
          <el-radio-group v-model="editForm.role">
            <el-radio value="normal">普通</el-radio>
            <el-radio value="primary">主集群</el-radio>
            <el-radio value="backup">备用集群</el-radio>
          </el-radio-group>
        </el-form-item>
        <el-form-item label="自动故障转移">
          <el-switch v-model="editForm.auto" />
        </el-form-item>
        <el-form-item label="单节点带宽">
          <el-input-number v-model="editForm.bw_limit" :min="0" :max="1000000" controls-position="right" />
          <span class="sub unit">Mbps，0 表示不监控</span>
        </el-form-item>
        <el-form-item v-if="editForm.bw_limit > 0" label="危险值">
          <el-input-number v-model="editForm.bw_danger" :min="1" :max="100" controls-position="right" />
          <span class="sub unit">% 以上视为打满：该节点连续 3 次打满先摘除解析，恢复 10 分钟后加回</span>
        </el-form-item>
        <el-form-item v-if="editForm.bw_limit > 0" label="可用率阈值">
          <el-input-number v-model="editForm.threshold" :min="1" :max="100" controls-position="right" />
          <span class="sub unit">%，可用节点（未打满且在线）占比连续 3 次（约 90 秒）低于此值切高防 CNAME</span>
        </el-form-item>
        <el-alert
          v-if="editForm.bw_limit > 0 && !editForm.defense_cname.trim()"
          type="warning"
          :closable="false"
          show-icon
          class="alert"
          title="未填写集群高防 CNAME：只有自己填了高防 CNAME 的域名会被切换"
        />
        <template v-if="editForm.auto">
          <el-form-item v-if="!(editForm.bw_limit > 0)" label="在线率阈值">
            <el-input-number v-model="editForm.threshold" :min="1" :max="100" controls-position="right" />
            <span class="sub unit">% 以下触发</span>
          </el-form-item>
          <el-form-item label="切换目标">
            <el-select
              v-model="editForm.target_cluster_id"
              placeholder="不指定则切到高防 CNAME"
              clearable
              style="width: 100%"
            >
              <el-option v-for="c in targetOptions" :key="c.id" :label="c.name" :value="c.id" />
            </el-select>
          </el-form-item>
        </template>
      </el-form>
      <template #footer>
        <el-button @click="editVisible = false">取消</el-button>
        <el-button type="primary" :loading="editSaving" @click="saveEdit">保存</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<style scoped>
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
.unit {
  margin-left: 8px;
}
.warn-text {
  color: var(--warn, #e6a23c);
  cursor: help;
}
</style>
