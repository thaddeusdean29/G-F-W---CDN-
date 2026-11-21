<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { ArrowDown, ArrowUp, Delete, Plus } from '@element-plus/icons-vue'
import { fetchFAQ, saveFAQ, type FAQConfig, type FAQGroup } from '@/api/faq'
import { ApiClientError } from '@/api/client'

// 首页「常见问题」区块：价格之后、联系我们之前。访客点问题展开解答。保存后立即生效。

// 和后端 internal/apiv2/docs.go 的限制一致
const LIMIT = { intro: 120, groups: 10, groupTitle: 16, items: 100, question: 80, answer: 2000 }

const form = reactive<FAQConfig>({ intro: '', groups: [] })
const saved = ref(false)
const loading = ref(true)
const saving = ref(false)
const error = ref('')
// 当前展开编辑的问题，key 为「分类序号-问题序号」
const open = reactive<Record<string, boolean>>({})

const total = computed(() => form.groups.reduce((n, g) => n + g.items.length, 0))

// 首页上的问题编号是全局连续的（Q1、Q2…），这里显示同样的编号，方便对照。
function qNo(gi: number, ii: number) {
  let n = 0
  for (let i = 0; i < gi; i++) n += form.groups[i].items.length
  return n + ii + 1
}

function apply(cfg: FAQConfig) {
  form.intro = cfg.intro
  form.groups = (cfg.groups ?? []).map((g) => ({ title: g.title, items: g.items.map((it) => ({ ...it })) }))
  for (const k of Object.keys(open)) delete open[k]
}

function move<T>(list: T[], i: number, delta: number) {
  const j = i + delta
  if (j < 0 || j >= list.length) return
  ;[list[i], list[j]] = [list[j], list[i]]
}

function addGroup() {
  if (form.groups.length >= LIMIT.groups) return
  form.groups.push({ title: '', items: [{ question: '', answer: '' }] })
  open[`${form.groups.length - 1}-0`] = true
}

function addItem(g: FAQGroup, gi: number) {
  if (total.value >= LIMIT.items) return
  g.items.push({ question: '', answer: '' })
  open[`${gi}-${g.items.length - 1}`] = true
}

async function removeGroup(gi: number) {
  const g = form.groups[gi]
  if (g.items.some((it) => it.question.trim() || it.answer.trim())) {
    try {
      await ElMessageBox.confirm(`删除分类「${g.title || '未命名'}」和其中 ${g.items.length} 个问题？`, '删除分类', {
        type: 'warning',
        confirmButtonText: '删除',
        cancelButtonText: '取消',
      })
    } catch {
      return
    }
  }
  form.groups.splice(gi, 1)
}

function removeItem(g: FAQGroup, ii: number) {
  g.items.splice(ii, 1)
}

// 保存前先查必填项，给出能直接定位的提示；最终以服务端校验为准。
function build(): FAQConfig | null {
  const groups: FAQGroup[] = []
  for (const [gi, g] of form.groups.entries()) {
    const title = g.title.trim()
    if (!title) {
      ElMessage.error(`第 ${gi + 1} 个分类的名称必填`)
      return null
    }
    if (!g.items.length) {
      ElMessage.error(`分类「${title}」至少要有一个问题，或者删除这个分类`)
      return null
    }
    const items = g.items.map((it) => ({ question: it.question.trim(), answer: it.answer.trim() }))
    const bad = items.findIndex((it) => !it.question || !it.answer)
    if (bad >= 0) {
      open[`${gi}-${bad}`] = true
      ElMessage.error(`分类「${title}」的 Q${qNo(gi, bad)} 需要同时填写问题和解答`)
      return null
    }
    groups.push({ title, items })
  }
  return { intro: form.intro.trim(), groups }
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const r = await fetchFAQ()
    saved.value = r.saved
    apply(r.config)
  } catch (e) {
    error.value = e instanceof ApiClientError ? e.message : '加载失败'
  } finally {
    loading.value = false
  }
}

async function save() {
  const cfg = build()
  if (!cfg) return
  saving.value = true
  try {
    const r = await saveFAQ(cfg)
    saved.value = r.saved
    apply(r.config)
    ElMessage.success(cfg.groups.length ? '常见问题已保存，刷新首页即可看到' : '已保存，首页不再显示常见问题')
  } catch (e) {
    ElMessage.error(e instanceof ApiClientError ? e.message : '保存失败')
  } finally {
    saving.value = false
  }
}

onMounted(load)
</script>

<template>
  <div>
    <div class="header">
      <div>
        <h1>常见问题</h1>
        <p class="hint">
          显示在首页价格之后、联系我们之前，访客点问题展开解答。{{ saved ? '' : '当前是默认问答，可以直接修改。' }}
        </p>
      </div>
      <a class="preview" href="/#faq" target="_blank" rel="noopener">在新窗口查看首页</a>
    </div>
    <el-alert v-if="error" :title="error" type="error" show-icon :closable="false" class="alert" />

    <el-form v-loading="loading" label-width="90px" @submit.prevent="save">
      <el-card class="card" shadow="never">
        <el-form-item label="说明">
          <el-input
            v-model="form.intro"
            :maxlength="LIMIT.intro"
            show-word-limit
            placeholder="显示在「常见问题」标题下方，可留空"
          />
        </el-form-item>
        <div class="hint rules">
          解答的写法：空一行另起一段；以「- 」开头的行显示为列表；以「1. 」开头的行显示为编号列表。只支持纯文本。
          只有一个分类时，首页不显示分类名。
        </div>
      </el-card>

      <el-card v-for="(g, gi) in form.groups" :key="gi" class="card" shadow="never">
        <template #header>
          <div class="group-head">
            <el-input
              v-model="g.title"
              class="group-title"
              :maxlength="LIMIT.groupTitle"
              placeholder="分类名称，如 接入使用"
              :aria-label="`第 ${gi + 1} 个分类名称`"
            />
            <span class="hint">{{ g.items.length }} 个问题</span>
            <span class="spacer"></span>
            <el-button :icon="ArrowUp" text :disabled="gi === 0" :aria-label="`上移分类 ${gi + 1}`" @click="move(form.groups, gi, -1)" />
            <el-button
              :icon="ArrowDown"
              text
              :disabled="gi === form.groups.length - 1"
              :aria-label="`下移分类 ${gi + 1}`"
              @click="move(form.groups, gi, 1)"
            />
            <el-button :icon="Delete" text type="danger" :aria-label="`删除分类 ${gi + 1}`" @click="removeGroup(gi)" />
          </div>
        </template>

        <div v-for="(it, ii) in g.items" :key="ii" class="item" :class="{ open: open[`${gi}-${ii}`] }">
          <div class="item-head">
            <button
              type="button"
              class="toggle"
              :aria-expanded="!!open[`${gi}-${ii}`]"
              :aria-controls="`faq-${gi}-${ii}`"
              @click="open[`${gi}-${ii}`] = !open[`${gi}-${ii}`]"
            >
              <span class="qn">Q{{ qNo(gi, ii) }}</span>
              <span class="q" :class="{ empty: !it.question.trim() }">{{ it.question.trim() || '未填写问题' }}</span>
              <el-icon class="chev"><ArrowDown /></el-icon>
            </button>
            <div class="ops">
              <el-button :icon="ArrowUp" text :disabled="ii === 0" :aria-label="`上移 Q${qNo(gi, ii)}`" @click="move(g.items, ii, -1)" />
              <el-button
                :icon="ArrowDown"
                text
                :disabled="ii === g.items.length - 1"
                :aria-label="`下移 Q${qNo(gi, ii)}`"
                @click="move(g.items, ii, 1)"
              />
              <el-button :icon="Delete" text type="danger" :aria-label="`删除 Q${qNo(gi, ii)}`" @click="removeItem(g, ii)" />
            </div>
          </div>
          <div v-show="open[`${gi}-${ii}`]" :id="`faq-${gi}-${ii}`" class="item-body">
            <el-form-item label="问题" required>
              <el-input v-model="it.question" :maxlength="LIMIT.question" show-word-limit placeholder="访客常问的问题" />
            </el-form-item>
            <el-form-item label="解答" required>
              <el-input
                v-model="it.answer"
                type="textarea"
                :autosize="{ minRows: 4, maxRows: 16 }"
                :maxlength="LIMIT.answer"
                show-word-limit
                placeholder="大概解答一下。空一行分段，「- 」开头为列表，「1. 」开头为编号列表"
              />
            </el-form-item>
          </div>
        </div>
        <el-button size="small" :icon="Plus" :disabled="total >= LIMIT.items" @click="addItem(g, gi)">添加问题</el-button>
      </el-card>

      <div v-if="!form.groups.length && !loading" class="empty">没有问题，首页不显示常见问题。</div>

      <div class="actions">
        <el-button :icon="Plus" :disabled="form.groups.length >= LIMIT.groups" @click="addGroup">添加分类</el-button>
        <span class="hint">最多 {{ LIMIT.groups }} 个分类、共 {{ LIMIT.items }} 个问题，当前 {{ total }} 个</span>
        <span class="spacer"></span>
        <el-button type="primary" native-type="submit" :loading="saving">保存常见问题</el-button>
      </div>
    </el-form>
  </div>
</template>

<style scoped>
.header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
}
.header h1 {
  margin-bottom: 4px;
}
.preview {
  margin-top: 8px;
  color: var(--accent);
  font-size: 14px;
  white-space: nowrap;
}
.alert {
  margin-bottom: 16px;
}
.card {
  max-width: 960px;
  margin-bottom: 16px;
}
.hint {
  font-size: 12px;
  color: var(--text-dim, #999);
  line-height: 1.6;
}
.rules {
  margin-left: 90px;
}
.group-head {
  display: flex;
  align-items: center;
  gap: 10px;
}
.group-title {
  width: 240px;
}
.spacer {
  flex: 1;
}
.group-head .el-button + .el-button,
.ops .el-button + .el-button {
  margin-left: 0;
}
.item {
  border-bottom: 1px solid var(--line, #2a3a57);
  margin-bottom: 4px;
}
.item-head {
  display: flex;
  align-items: center;
  gap: 8px;
}
.toggle {
  flex: 1;
  min-width: 0;
  display: flex;
  align-items: baseline;
  gap: 10px;
  padding: 12px 0;
  background: none;
  border: 0;
  color: inherit;
  font: inherit;
  text-align: left;
  cursor: pointer;
}
.toggle:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 2px;
  border-radius: 4px;
}
.qn {
  flex: none;
  width: 3em;
  color: var(--accent);
  font-weight: 600;
  font-variant-numeric: tabular-nums;
}
.q {
  flex: 1;
  min-width: 0;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-weight: 600;
}
.q.empty {
  color: var(--text-dim, #999);
  font-weight: 400;
}
.chev {
  flex: none;
  align-self: center;
  color: var(--text-dim, #999);
  transition: transform 0.2s ease;
}
.item.open .chev {
  transform: rotate(180deg);
}
.ops {
  display: flex;
  flex: none;
}
.item-body {
  padding: 4px 0 6px;
}
.empty {
  max-width: 960px;
  padding: 16px 0;
  color: var(--text-dim, #999);
  font-size: 13px;
}
.actions {
  max-width: 960px;
  display: flex;
  align-items: center;
  gap: 12px;
}
@media (max-width: 760px) {
  .rules {
    margin-left: 0;
  }
  .group-title {
    width: auto;
    flex: 1;
  }
  .actions {
    flex-wrap: wrap;
  }
}
@media (prefers-reduced-motion: reduce) {
  .chev {
    transition: none;
  }
}
</style>
