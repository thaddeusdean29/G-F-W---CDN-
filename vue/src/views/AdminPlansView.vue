<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { listPlans, createPlan, patchPlan, deletePlan } from '@/api/admin'
import type { AdminPlan } from '@/api/types'
import { ApiClientError } from '@/api/client'

// 套餐只决定配额（节点/域名/集群上限），不计费。改上限对已开通的代理即时生效。

const plans = ref<AdminPlan[]>([])
const loading = ref(true)
const error = ref('')
const actionLoading = reactive<Record<number, boolean>>({})

function errMessage(e: unknown): string {
  return e instanceof ApiClientError ? e.message : '操作失败'
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    plans.value = (await listPlans()).items
  } catch (e) {
    error.value = e instanceof ApiClientError ? e.message : '加载失败'
  } finally {
    loading.value = false
  }
}

async function handleDelete(p: AdminPlan) {
  try {
    await ElMessageBox.confirm(`确定删除套餐「${p.name}」？`, '删除套餐', {
      type: 'warning',
      confirmButtonText: '删除',
      cancelButtonText: '取消',
    })
  } catch {
    return
  }
  actionLoading[p.id] = true
  try {
    await deletePlan(p.id)
    plans.value = plans.value.filter((x) => x.id !== p.id)
    ElMessage.success('已删除')
  } catch (e) {
    if (e instanceof ApiClientError && e.code === 'in_use') {
      ElMessage.error('仍有代理在用这个套餐，请先把它们换到其他套餐')
    } else {
      ElMessage.error(errMessage(e))
    }
  } finally {
    delete actionLoading[p.id]
  }
}

const editVisible = ref(false)
const editSaving = ref(false)
const editing = ref<AdminPlan | null>(null)
const editForm = reactive({ code: '', name: '', max_nodes: 20, max_domains: 100, max_clusters: 5 })

function openCreate() {
  editing.value = null
  Object.assign(editForm, { code: '', name: '', max_nodes: 20, max_domains: 100, max_clusters: 5 })
  editVisible.value = true
}

function openEdit(p: AdminPlan) {
  editing.value = p
  Object.assign(editForm, {
    code: p.code,
    name: p.name,
    max_nodes: p.max_nodes,
    max_domains: p.max_domains,
    max_clusters: p.max_clusters,
  })
  editVisible.value = true
}

async function saveEdit() {
  if (!editForm.name.trim()) return ElMessage.error('请填写套餐名称')
  if (!editing.value && !/^[a-z0-9_-]{1,32}$/.test(editForm.code)) {
    return ElMessage.error('编码为 1–32 位小写字母、数字、- 或 _')
  }
  const limits = {
    name: editForm.name.trim(),
    max_nodes: editForm.max_nodes,
    max_domains: editForm.max_domains,
    max_clusters: editForm.max_clusters,
  }
  editSaving.value = true
  try {
    if (editing.value) {
      const updated = await patchPlan(editing.value.id, limits)
      const idx = plans.value.findIndex((x) => x.id === updated.id)
      if (idx >= 0) plans.value[idx] = updated
    } else {
      await createPlan({ code: editForm.code, ...limits })
      await load()
    }
    ElMessage.success('已保存')
    editVisible.value = false
  } catch (e) {
    if (e instanceof ApiClientError && e.code === 'conflict') {
      ElMessage.error('套餐编码已存在')
    } else {
      ElMessage.error(errMessage(e))
    }
  } finally {
    editSaving.value = false
  }
}

onMounted(load)
</script>

<template>
  <div>
    <div class="header">
      <h1>套餐</h1>
      <div>
        <el-button @click="load">刷新</el-button>
        <el-button type="primary" @click="openCreate">新建套餐</el-button>
      </div>
    </div>
    <el-alert v-if="error" :title="error" type="error" show-icon :closable="false" class="alert" />
    <el-table v-loading="loading" :data="plans" style="width: 100%">
      <el-table-column label="名称" min-width="140">
        <template #default="{ row }">
          <div>{{ row.name }}</div>
          <div class="sub">{{ row.code }}</div>
        </template>
      </el-table-column>
      <el-table-column prop="max_nodes" label="节点上限" min-width="100" />
      <el-table-column prop="max_domains" label="域名上限" min-width="100" />
      <el-table-column prop="max_clusters" label="集群上限" min-width="100" />
      <el-table-column prop="tenants" label="使用中的代理" min-width="110" />
      <el-table-column label="操作" min-width="160" fixed="right">
        <template #default="{ row }">
          <el-button size="small" :disabled="!!actionLoading[row.id]" @click="openEdit(row)">编辑</el-button>
          <el-button
            size="small"
            type="danger"
            :loading="!!actionLoading[row.id]"
            :disabled="row.tenants > 0"
            @click="handleDelete(row)"
          >
            删除
          </el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="editVisible" :title="editing ? '编辑套餐' : '新建套餐'" width="440px">
      <el-form label-width="90px" @submit.prevent>
        <el-form-item label="编码" required>
          <el-input v-model="editForm.code" :disabled="!!editing" maxlength="32" placeholder="例如 vip3" />
        </el-form-item>
        <el-form-item label="名称" required>
          <el-input v-model="editForm.name" maxlength="64" />
        </el-form-item>
        <el-form-item label="节点上限">
          <el-input-number v-model="editForm.max_nodes" :min="0" :max="100000" />
        </el-form-item>
        <el-form-item label="域名上限">
          <el-input-number v-model="editForm.max_domains" :min="0" :max="100000" />
        </el-form-item>
        <el-form-item label="集群上限">
          <el-input-number v-model="editForm.max_clusters" :min="0" :max="100000" />
        </el-form-item>
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
  flex-wrap: wrap;
  gap: 12px;
  justify-content: space-between;
  align-items: center;
}
.header h1 {
  white-space: nowrap;
}
.alert {
  margin-bottom: 16px;
}
.sub {
  font-size: 12px;
  color: #999;
}
</style>
