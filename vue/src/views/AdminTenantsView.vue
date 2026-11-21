<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  listTenants,
  createTenant,
  patchTenant,
  deleteTenant,
  listTenantUsers,
  createTenantUser,
  patchTenantUser,
  listPlans,
  type TenantPatchInput,
} from '@/api/admin'
import type { AdminPlan, AdminTenant, AdminTenantUser } from '@/api/types'
import { ApiClientError } from '@/api/client'

// 每个代理 = 一个租户 = 一套独立后台。这里只负责开户、套餐、停用与登录账号，
// 代理自己的域名/节点/集群只有代理登录后才看得到，彼此互不相通。

const tenants = ref<AdminTenant[]>([])
const total = ref(0)
const page = ref(1)
const pageSize = ref(20)
const keyword = ref('')
const loading = ref(true)
const error = ref('')
const plans = ref<AdminPlan[]>([])
const actionLoading = reactive<Record<string, string>>({})

function errMessage(e: unknown): string {
  return e instanceof ApiClientError ? e.message : '操作失败'
}

function formatTime(s: string | null): string {
  if (!s) return '—'
  return new Date(s).toLocaleString('zh-CN', { hour12: false })
}

// 后端把「YYYY-MM-DD」解释为北京时间当天 23:59:59，这里反向换算回日期给日期选择器用。
function toCnDate(s: string | null): string {
  if (!s) return ''
  return new Date(new Date(s).getTime() + 8 * 3600 * 1000).toISOString().slice(0, 10)
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const res = await listTenants({
      q: keyword.value.trim() || undefined,
      page: page.value,
      page_size: pageSize.value,
    })
    tenants.value = res.items
    total.value = res.total
  } catch (e) {
    error.value = e instanceof ApiClientError ? e.message : '加载失败'
  } finally {
    loading.value = false
  }
}

async function loadPlans() {
  try {
    plans.value = (await listPlans()).items
  } catch (e) {
    ElMessage.error('套餐加载失败：' + errMessage(e))
  }
}

function search() {
  page.value = 1
  load()
}

function replaceTenant(t: AdminTenant) {
  const idx = tenants.value.findIndex((x) => x.id === t.id)
  if (idx >= 0) tenants.value[idx] = t
}

function statusOf(t: AdminTenant): { label: string; type: 'success' | 'warning' | 'danger' | 'info' } {
  if (t.status === 'suspended') return { label: '已停用', type: 'danger' }
  if (t.expired) return { label: '已到期', type: 'warning' }
  return { label: '正常', type: 'success' }
}

async function toggleStatus(t: AdminTenant) {
  const next = t.status === 'active' ? 'suspended' : 'active'
  if (next === 'suspended') {
    try {
      await ElMessageBox.confirm(
        `停用后代理「${t.name}」仍可登录查看，但不能再新增域名、节点和集群。确定停用？`,
        '停用代理',
        { type: 'warning', confirmButtonText: '停用', cancelButtonText: '取消' },
      )
    } catch {
      return
    }
  }
  actionLoading[t.id] = 'status'
  try {
    replaceTenant(await patchTenant(t.id, { status: next }))
    ElMessage.success(next === 'active' ? '已恢复' : '已停用')
  } catch (e) {
    ElMessage.error(errMessage(e))
  } finally {
    delete actionLoading[t.id]
  }
}

async function handleDelete(t: AdminTenant) {
  try {
    await ElMessageBox.confirm(
      `确定删除代理「${t.name}」？其所有登录账号会一并删除，且不可恢复。`,
      '删除代理',
      { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  actionLoading[t.id] = 'delete'
  try {
    await deleteTenant(t.id)
    ElMessage.success('已删除')
    load()
  } catch (e) {
    if (e instanceof ApiClientError && e.code === 'in_use') {
      ElMessage.error('该代理下仍有域名、节点或集群，需代理先删除这些资源（或改为停用）')
    } else {
      ElMessage.error(errMessage(e))
    }
  } finally {
    delete actionLoading[t.id]
  }
}

// ---------------------------------------------------------------------------
// 新建 / 编辑代理
// ---------------------------------------------------------------------------

const editVisible = ref(false)
const editSaving = ref(false)
const editing = ref<AdminTenant | null>(null)
const editForm = reactive({
  name: '',
  plan_id: 0,
  expires_at: '',
  email: '',
  password: '',
})

function openCreate() {
  editing.value = null
  Object.assign(editForm, {
    name: '',
    plan_id: plans.value[0]?.id ?? 0,
    expires_at: '',
    email: '',
    password: '',
  })
  editVisible.value = true
}

function openEdit(t: AdminTenant) {
  editing.value = t
  Object.assign(editForm, {
    name: t.name,
    plan_id: t.plan.id,
    expires_at: toCnDate(t.expires_at),
    email: '',
    password: '',
  })
  editVisible.value = true
}

async function saveEdit() {
  if (!editForm.name.trim()) return ElMessage.error('请填写代理名称')
  if (!editForm.plan_id) return ElMessage.error('请选择套餐')
  editSaving.value = true
  try {
    if (editing.value) {
      const cur = editing.value
      // 只提交改动的字段：到期日没动就不回写，避免把原来精确到秒的时间抹成当天 23:59:59。
      const patch: TenantPatchInput = {}
      if (editForm.name.trim() !== cur.name) patch.name = editForm.name.trim()
      if (editForm.plan_id !== cur.plan.id) patch.plan_id = editForm.plan_id
      if (editForm.expires_at !== toCnDate(cur.expires_at)) patch.expires_at = editForm.expires_at || null
      if (Object.keys(patch).length > 0) replaceTenant(await patchTenant(cur.id, patch))
      ElMessage.success('已保存')
    } else {
      if (!editForm.email.trim()) return ElMessage.error('请填写登录账号')
      if (editForm.password.length < 8) return ElMessage.error('密码至少 8 位')
      await createTenant({
        name: editForm.name.trim(),
        plan_id: editForm.plan_id,
        expires_at: editForm.expires_at || null,
        owner: { email: editForm.email.trim(), password: editForm.password },
      })
      ElMessage.success('代理已开通，可用该账号登录控制台')
      page.value = 1
      load()
      loadPlans()
    }
    editVisible.value = false
  } catch (e) {
    ElMessage.error(errMessage(e))
  } finally {
    editSaving.value = false
  }
}

// ---------------------------------------------------------------------------
// 代理登录账号
// ---------------------------------------------------------------------------

const usersVisible = ref(false)
const usersLoading = ref(false)
const usersTenant = ref<AdminTenant | null>(null)
const users = ref<AdminTenantUser[]>([])
const userAction = reactive<Record<string, boolean>>({})
const newUser = reactive({ email: '', password: '', role: 'member' as AdminTenantUser['role'] })
const newUserSaving = ref(false)

const roleLabel: Record<string, string> = { owner: '所有者', member: '成员', readonly: '只读' }

async function openUsers(t: AdminTenant) {
  usersTenant.value = t
  users.value = []
  Object.assign(newUser, { email: '', password: '', role: 'member' })
  usersVisible.value = true
  usersLoading.value = true
  try {
    users.value = (await listTenantUsers(t.id)).items
  } catch (e) {
    ElMessage.error(errMessage(e))
  } finally {
    usersLoading.value = false
  }
}

function replaceUser(u: AdminTenantUser) {
  const idx = users.value.findIndex((x) => x.id === u.id)
  if (idx >= 0) users.value[idx] = u
}

async function resetPassword(u: AdminTenantUser) {
  let password: string
  try {
    const res = await ElMessageBox.prompt(`为「${u.email}」设置新密码（至少 8 位），该账号现有登录会被踢下线。`, '重置密码', {
      inputType: 'password',
      inputValidator: (v: string) => (v && v.length >= 8 && v.length <= 72) || '密码长度 8–72 位',
      confirmButtonText: '重置',
      cancelButtonText: '取消',
    })
    password = res.value
  } catch {
    return
  }
  userAction[u.id] = true
  try {
    replaceUser(await patchTenantUser(u.id, { password }))
    ElMessage.success('密码已重置')
  } catch (e) {
    ElMessage.error(errMessage(e))
  } finally {
    delete userAction[u.id]
  }
}

async function toggleUser(u: AdminTenantUser) {
  userAction[u.id] = true
  try {
    replaceUser(await patchTenantUser(u.id, { status: u.status === 'active' ? 'disabled' : 'active' }))
  } catch (e) {
    ElMessage.error(errMessage(e))
  } finally {
    delete userAction[u.id]
  }
}

async function addUser() {
  if (!usersTenant.value) return
  if (!newUser.email.trim()) return ElMessage.error('请填写登录账号')
  if (newUser.password.length < 8) return ElMessage.error('密码至少 8 位')
  newUserSaving.value = true
  try {
    users.value.push(
      await createTenantUser(usersTenant.value.id, {
        email: newUser.email.trim(),
        password: newUser.password,
        role: newUser.role,
      }),
    )
    Object.assign(newUser, { email: '', password: '', role: 'member' })
    ElMessage.success('账号已添加')
  } catch (e) {
    ElMessage.error(errMessage(e))
  } finally {
    newUserSaving.value = false
  }
}

onMounted(() => {
  load()
  loadPlans()
})
</script>

<template>
  <div>
    <div class="header">
      <h1>代理管理</h1>
      <div class="tools">
        <el-input
          v-model="keyword"
          placeholder="搜索代理名称或登录账号"
          clearable
          style="width: 240px"
          @keyup.enter="search"
          @clear="search"
        />
        <el-button @click="load">刷新</el-button>
        <el-button type="primary" @click="openCreate">新建代理</el-button>
      </div>
    </div>
    <p class="hint">每个代理是一套独立后台：各自的域名、节点、集群互不可见。新代理登录后是空的。</p>
    <el-alert v-if="error" :title="error" type="error" show-icon :closable="false" class="alert" />
    <el-table v-loading="loading" :data="tenants" style="width: 100%">
      <el-table-column label="代理" min-width="160">
        <template #default="{ row }">
          <div>{{ row.name }}</div>
          <div class="sub">{{ row.owner_email || '无所有者账号' }}</div>
        </template>
      </el-table-column>
      <el-table-column label="套餐" min-width="100">
        <template #default="{ row }">{{ row.plan.name }}</template>
      </el-table-column>
      <el-table-column label="状态" min-width="90">
        <template #default="{ row }">
          <el-tag :type="statusOf(row).type">{{ statusOf(row).label }}</el-tag>
        </template>
      </el-table-column>
      <el-table-column label="用量" min-width="170">
        <template #default="{ row }">
          <div class="usage">
            <span>节点 {{ row.usage.nodes }}/{{ row.plan.max_nodes }}</span>
            <span>域名 {{ row.usage.domains }}/{{ row.plan.max_domains }}</span>
            <span>集群 {{ row.usage.clusters }}/{{ row.plan.max_clusters }}</span>
          </div>
        </template>
      </el-table-column>
      <el-table-column label="到期时间" min-width="160">
        <template #default="{ row }">{{ row.expires_at ? formatTime(row.expires_at) : '永久' }}</template>
      </el-table-column>
      <el-table-column label="开通时间" min-width="160">
        <template #default="{ row }">{{ formatTime(row.created_at) }}</template>
      </el-table-column>
      <el-table-column label="操作" min-width="280" fixed="right">
        <template #default="{ row }">
          <el-button size="small" :disabled="!!actionLoading[row.id]" @click="openEdit(row)">编辑</el-button>
          <el-button size="small" :disabled="!!actionLoading[row.id]" @click="openUsers(row)">账号</el-button>
          <el-button
            size="small"
            :type="row.status === 'active' ? 'warning' : 'success'"
            :loading="actionLoading[row.id] === 'status'"
            :disabled="!!actionLoading[row.id] && actionLoading[row.id] !== 'status'"
            @click="toggleStatus(row)"
          >
            {{ row.status === 'active' ? '停用' : '恢复' }}
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
    </el-table>
    <div class="pager" v-if="total > pageSize">
      <el-pagination
        v-model:current-page="page"
        :page-size="pageSize"
        :total="total"
        layout="prev, pager, next, total"
        @current-change="load"
      />
    </div>

    <el-dialog v-model="editVisible" :title="editing ? '编辑代理' : '新建代理'" width="480px">
      <el-form label-width="90px" @submit.prevent>
        <el-form-item label="代理名称" required>
          <el-input v-model="editForm.name" maxlength="128" placeholder="例如：代理 A" />
        </el-form-item>
        <el-form-item label="套餐" required>
          <el-select v-model="editForm.plan_id" placeholder="选择套餐" style="width: 100%">
            <el-option
              v-for="p in plans"
              :key="p.id"
              :label="`${p.name}（节点 ${p.max_nodes} / 域名 ${p.max_domains} / 集群 ${p.max_clusters}）`"
              :value="p.id"
            />
          </el-select>
        </el-form-item>
        <el-form-item label="到期日">
          <el-date-picker
            v-model="editForm.expires_at"
            type="date"
            value-format="YYYY-MM-DD"
            placeholder="留空为永久"
            clearable
            style="width: 100%"
          />
        </el-form-item>
        <template v-if="!editing">
          <el-form-item label="登录账号" required>
            <el-input v-model="editForm.email" maxlength="255" placeholder="代理登录控制台用的邮箱/账号" autocomplete="off" />
          </el-form-item>
          <el-form-item label="初始密码" required>
            <el-input
              v-model="editForm.password"
              type="password"
              show-password
              maxlength="72"
              placeholder="至少 8 位"
              autocomplete="new-password"
            />
          </el-form-item>
        </template>
      </el-form>
      <template #footer>
        <el-button @click="editVisible = false">取消</el-button>
        <el-button type="primary" :loading="editSaving" @click="saveEdit">
          {{ editing ? '保存' : '开通' }}
        </el-button>
      </template>
    </el-dialog>

    <el-dialog v-model="usersVisible" :title="`登录账号 — ${usersTenant?.name ?? ''}`" width="720px">
      <el-table v-loading="usersLoading" :data="users" style="width: 100%">
        <el-table-column prop="email" label="账号" min-width="180" />
        <el-table-column label="角色" min-width="80">
          <template #default="{ row }">{{ roleLabel[row.role] ?? row.role }}</template>
        </el-table-column>
        <el-table-column label="状态" min-width="80">
          <template #default="{ row }">
            <el-tag :type="row.status === 'active' ? 'success' : 'info'">
              {{ row.status === 'active' ? '正常' : '已禁用' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="最近登录" min-width="150">
          <template #default="{ row }">{{ formatTime(row.last_login_at) }}</template>
        </el-table-column>
        <el-table-column label="操作" min-width="170">
          <template #default="{ row }">
            <el-button size="small" :disabled="!!userAction[row.id]" @click="resetPassword(row)">重置密码</el-button>
            <el-button size="small" :loading="!!userAction[row.id]" @click="toggleUser(row)">
              {{ row.status === 'active' ? '禁用' : '启用' }}
            </el-button>
          </template>
        </el-table-column>
      </el-table>
      <div class="add-user">
        <el-input v-model="newUser.email" placeholder="新账号" maxlength="255" autocomplete="off" />
        <el-input
          v-model="newUser.password"
          type="password"
          show-password
          placeholder="密码（至少 8 位）"
          maxlength="72"
          autocomplete="new-password"
        />
        <el-select v-model="newUser.role" style="width: 110px">
          <el-option label="成员" value="member" />
          <el-option label="只读" value="readonly" />
          <el-option label="所有者" value="owner" />
        </el-select>
        <el-button type="primary" :loading="newUserSaving" @click="addUser">添加</el-button>
      </div>
    </el-dialog>
  </div>
</template>

<style scoped>
.header {
  display: flex;
  flex-wrap: wrap;
  gap: 12px;
  justify-content: space-between;
  align-items: center;
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
  margin: 0 0 16px;
  font-size: 13px;
  color: #888;
}
.alert {
  margin-bottom: 16px;
}
.sub {
  font-size: 12px;
  color: #999;
}
.usage {
  display: flex;
  flex-direction: column;
  font-size: 12px;
  color: #555;
}
.pager {
  margin-top: 16px;
  display: flex;
  justify-content: flex-end;
}
.add-user {
  margin-top: 16px;
  display: flex;
  gap: 8px;
}
</style>
