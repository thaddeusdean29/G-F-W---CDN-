<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { ElMessage, ElMessageBox } from 'element-plus'
import { createTag, deleteTag, listTags } from '@/api/tags'
import type { TagItem } from '@/api/types'
import { errMessage } from '@/utils/format'

const router = useRouter()
const tags = ref<TagItem[]>([])
const loading = ref(false)
const creating = ref(false)
const name = ref('')
const busy = ref<Record<string, boolean>>({})

async function load() {
  loading.value = true
  try {
    tags.value = await listTags()
  } catch (e) {
    ElMessage.error(errMessage(e, '加载标签失败'))
  } finally {
    loading.value = false
  }
}

async function create() {
  const t = name.value.trim()
  if (!t) return
  creating.value = true
  try {
    await createTag(t)
    name.value = ''
    ElMessage.success(`已创建标签 ${t}`)
    await load()
  } catch (e) {
    ElMessage.error(errMessage(e, '创建失败'))
  } finally {
    creating.value = false
  }
}

async function remove(t: TagItem) {
  try {
    await ElMessageBox.confirm(
      t.domains ? `删除标签「${t.tag}」会从 ${t.domains} 个域名上移除它（域名本身不受影响）。` : `删除标签「${t.tag}」？`,
      '删除标签',
      { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  busy.value[t.tag] = true
  try {
    const r = await deleteTag(t.tag)
    ElMessage.success(`已删除，更新了 ${r.domains_updated} 个域名`)
    await load()
  } catch (e) {
    ElMessage.error(errMessage(e, '删除失败'))
  } finally {
    busy.value[t.tag] = false
  }
}

function viewDomains(t: TagItem) {
  router.push({ path: '/domains', query: { tag: t.tag } })
}

onMounted(load)
</script>

<template>
  <div class="page">
    <div class="page-header">
      <div>
        <h1>标签分类</h1>
        <p class="sub">给域名打标签便于分组筛选；在「域名 → 编辑 → 标签分类」中给域名分配标签</p>
      </div>
      <div class="actions">
        <el-input v-model="name" placeholder="新标签名" maxlength="64" style="width: 200px" @keyup.enter="create" />
        <el-button type="primary" :loading="creating" :disabled="!name.trim()" @click="create">新建标签</el-button>
      </div>
    </div>

    <div class="panel">
      <el-table v-loading="loading" :data="tags" empty-text="还没有标签">
        <el-table-column label="标签" min-width="200">
          <template #default="{ row }">
            <el-tag effect="dark" round>{{ row.tag }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="域名数" width="120" align="right" prop="domains" sortable />
        <el-table-column label="操作" width="180" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" :disabled="!row.domains" @click="viewDomains(row)">查看域名</el-button>
            <el-button link type="danger" :loading="busy[row.tag]" @click="remove(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
    </div>
  </div>
</template>
