<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { ArrowDown, ArrowUp, Delete, Plus } from '@element-plus/icons-vue'
import { fetchHomepage, saveHomepage, type ContactType, type HomepageConfig, type PlanRow } from '@/api/homepage'
import type { LoginFeature } from '@/api/branding'
import { ApiClientError } from '@/api/client'
import { featureIconNames, featureIcons } from '@/utils/featureIcons'

// 公开首页（根路径 /）：首屏、产品能力、价格、联系方式、页脚备案。保存后立即生效。

// 和后端 internal/apiv2/homepage.go 的限制一致
const LIMIT = {
  title: 40,
  subtitle: 120,
  features: 9,
  featureTitle: 16,
  featureDesc: 60,
  note: 80,
  plans: 6,
  planName: 16,
  price: 16,
  period: 8,
  planDesc: 60,
  planItems: 10,
  planItem: 30,
  contacts: 8,
  contactLabel: 12,
  contactValue: 64,
  icp: 40,
  footer: 100,
}

interface PlanForm {
  name: string
  price: string
  period: string
  desc: string
  plan_code: string
  items: string // 每行一条
  highlight: boolean
}

interface ContactForm {
  type: ContactType
  label: string
  value: string
}

const contactTypes: { value: ContactType; label: string; placeholder: string }[] = [
  { value: 'wechat', label: '微信', placeholder: '微信号' },
  { value: 'qq', label: 'QQ', placeholder: 'QQ 号' },
  { value: 'telegram', label: 'Telegram', placeholder: '@用户名' },
  { value: 'email', label: '邮箱', placeholder: 'sales@example.com' },
  { value: 'phone', label: '电话', placeholder: '+86 138 0000 0000' },
  { value: 'other', label: '其他', placeholder: '显示的文字' },
]
const contactMeta = Object.fromEntries(contactTypes.map((t) => [t.value, t]))

const form = reactive({
  enabled: true,
  hero_title: '',
  hero_subtitle: '',
  features: [] as LoginFeature[],
  plans_note: '',
  plans: [] as PlanForm[],
  contact_note: '',
  contacts: [] as ContactForm[],
  icp: '',
  footer_note: '',
})
const plans = ref<PlanRow[]>([])
const saved = ref(false)
const loading = ref(true)
const saving = ref(false)
const error = ref('')

const planByCode = computed(() => Object.fromEntries(plans.value.map((p) => [p.code, p])))

function planLimits(code: string): string {
  const p = planByCode.value[code]
  if (!p) return ''
  const parts: string[] = []
  if (p.max_nodes > 0) parts.push(`节点 ${p.max_nodes} 台`)
  if (p.max_domains > 0) parts.push(`域名 ${p.max_domains} 个`)
  if (p.max_clusters > 0) parts.push(`集群 ${p.max_clusters} 个`)
  return parts.join('、')
}

function apply(cfg: HomepageConfig) {
  Object.assign(form, {
    enabled: cfg.enabled,
    hero_title: cfg.hero_title,
    hero_subtitle: cfg.hero_subtitle,
    features: (cfg.features ?? []).map((f) => ({ ...f })),
    plans_note: cfg.plans_note,
    plans: (cfg.plans ?? []).map((p) => ({ ...p, items: (p.items ?? []).join('\n') })),
    contact_note: cfg.contact_note,
    contacts: (cfg.contacts ?? []).map((c) => ({ ...c })),
    icp: cfg.icp,
    footer_note: cfg.footer_note,
  })
}

function move<T>(list: T[], i: number, delta: number) {
  const j = i + delta
  if (j < 0 || j >= list.length) return
  ;[list[i], list[j]] = [list[j], list[i]]
}

function addFeature() {
  if (form.features.length < LIMIT.features) form.features.push({ icon: 'Star', title: '', desc: '' })
}
function addPlan() {
  if (form.plans.length < LIMIT.plans)
    form.plans.push({ name: '', price: '', period: '月', desc: '', plan_code: '', items: '', highlight: false })
}
function addContact() {
  if (form.contacts.length < LIMIT.contacts) form.contacts.push({ type: 'wechat', label: '', value: '' })
}

function lines(s: string): string[] {
  return s
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
}

// 保存前在前端先查一遍必填项，给出能直接定位的提示；最终以服务端校验为准。
function build(): HomepageConfig | null {
  const title = lines(form.hero_title)
  if (!title.length) {
    ElMessage.error('请填写首屏标题')
    return null
  }
  if (title.length > 2) {
    ElMessage.error('首屏标题最多两行')
    return null
  }
  const features = form.features.map((f) => ({ icon: f.icon, title: f.title.trim(), desc: f.desc.trim() }))
  const ef = features.findIndex((f) => !f.title)
  if (ef >= 0) {
    ElMessage.error(`第 ${ef + 1} 项产品能力的标题必填`)
    return null
  }
  const planList = form.plans.map((p) => ({
    name: p.name.trim(),
    price: p.price.trim(),
    period: p.period.trim(),
    desc: p.desc.trim(),
    plan_code: p.plan_code,
    items: lines(p.items),
    highlight: p.highlight,
  }))
  const ep = planList.findIndex((p) => !p.name)
  if (ep >= 0) {
    ElMessage.error(`第 ${ep + 1} 个套餐的名称必填`)
    return null
  }
  const tooMany = planList.findIndex((p) => p.items.length > LIMIT.planItems)
  if (tooMany >= 0) {
    ElMessage.error(`第 ${tooMany + 1} 个套餐最多 ${LIMIT.planItems} 条说明`)
    return null
  }
  const contacts = form.contacts.map((c) => ({ type: c.type, label: c.label.trim(), value: c.value.trim() }))
  const ec = contacts.findIndex((c) => !c.value)
  if (ec >= 0) {
    ElMessage.error(`第 ${ec + 1} 个联系方式的内容必填`)
    return null
  }
  return {
    enabled: form.enabled,
    hero_title: title.join('\n'),
    hero_subtitle: form.hero_subtitle.trim(),
    features,
    plans_note: form.plans_note.trim(),
    plans: planList,
    contact_note: form.contact_note.trim(),
    contacts,
    icp: form.icp.trim(),
    footer_note: form.footer_note.trim(),
  }
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    const r = await fetchHomepage()
    plans.value = r.plans
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
    const r = await saveHomepage(cfg)
    plans.value = r.plans
    saved.value = r.saved
    apply(r.config)
    ElMessage.success(cfg.enabled ? '首页已保存，刷新首页即可看到' : '已保存，首页已关闭，访问根路径会直接进入控制台')
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
        <h1>首页设置</h1>
        <p class="hint">网站根路径的公开首页。未保存过时显示默认内容{{ saved ? '' : '（当前就是默认内容）' }}。</p>
      </div>
      <a class="preview" href="/" target="_blank" rel="noopener">在新窗口查看首页</a>
    </div>
    <el-alert v-if="error" :title="error" type="error" show-icon :closable="false" class="alert" />

    <el-form v-loading="loading" label-width="110px" @submit.prevent="save">
      <el-card class="card" shadow="never">
        <template #header>首屏</template>
        <div class="form">
          <el-form-item label="显示首页">
            <el-switch v-model="form.enabled" />
            <div class="hint">关闭后访问根路径直接进入控制台登录页</div>
          </el-form-item>
          <el-form-item label="标题" required>
            <el-input
              v-model="form.hero_title"
              type="textarea"
              :rows="2"
              :maxlength="LIMIT.title"
              show-word-limit
              resize="none"
              placeholder="回车换行，最多两行"
            />
          </el-form-item>
          <el-form-item label="副标题">
            <el-input
              v-model="form.hero_subtitle"
              type="textarea"
              :rows="3"
              :maxlength="LIMIT.subtitle"
              show-word-limit
              resize="none"
              placeholder="一两句话说明你提供什么服务"
            />
          </el-form-item>
        </div>
      </el-card>

      <el-card class="card" shadow="never">
        <template #header>产品能力</template>
        <div v-for="(f, i) in form.features" :key="i" class="row">
          <el-select v-model="f.icon" class="w-icon" :aria-label="`第 ${i + 1} 项图标`">
            <template #prefix>
              <el-icon><component :is="featureIcons[f.icon]" /></el-icon>
            </template>
            <el-option v-for="name in featureIconNames" :key="name" :label="name" :value="name">
              <span class="opt">
                <el-icon><component :is="featureIcons[name]" /></el-icon>
                {{ name }}
              </span>
            </el-option>
          </el-select>
          <el-input
            v-model="f.title"
            class="w-title"
            :maxlength="LIMIT.featureTitle"
            placeholder="标题（必填）"
            :aria-label="`第 ${i + 1} 项标题`"
          />
          <el-input
            v-model="f.desc"
            class="grow"
            :maxlength="LIMIT.featureDesc"
            placeholder="一句话说明"
            :aria-label="`第 ${i + 1} 项说明`"
          />
          <div class="ops">
            <el-button :icon="ArrowUp" text :disabled="i === 0" :aria-label="`上移第 ${i + 1} 项`" @click="move(form.features, i, -1)" />
            <el-button
              :icon="ArrowDown"
              text
              :disabled="i === form.features.length - 1"
              :aria-label="`下移第 ${i + 1} 项`"
              @click="move(form.features, i, 1)"
            />
            <el-button :icon="Delete" text type="danger" :aria-label="`删除第 ${i + 1} 项`" @click="form.features.splice(i, 1)" />
          </div>
        </div>
        <div v-if="!form.features.length" class="empty">没有产品能力，首页不显示这一块</div>
        <el-button :icon="Plus" :disabled="form.features.length >= LIMIT.features" @click="addFeature">添加一项</el-button>
        <span class="hint inline">最多 {{ LIMIT.features }} 项，图标只能从列表里选</span>
      </el-card>

      <el-card class="card" shadow="never">
        <template #header>价格</template>
        <div class="form">
          <el-form-item label="说明">
            <el-input v-model="form.plans_note" :maxlength="LIMIT.note" show-word-limit placeholder="显示在价格标题下方，可留空" />
          </el-form-item>
        </div>
        <div v-for="(p, i) in form.plans" :key="i" class="plan">
          <div class="plan-head">
            <span class="plan-no">套餐 {{ i + 1 }}</span>
            <el-checkbox v-model="p.highlight">标为推荐</el-checkbox>
            <span class="spacer"></span>
            <el-button :icon="ArrowUp" text :disabled="i === 0" :aria-label="`上移套餐 ${i + 1}`" @click="move(form.plans, i, -1)" />
            <el-button
              :icon="ArrowDown"
              text
              :disabled="i === form.plans.length - 1"
              :aria-label="`下移套餐 ${i + 1}`"
              @click="move(form.plans, i, 1)"
            />
            <el-button :icon="Delete" text type="danger" :aria-label="`删除套餐 ${i + 1}`" @click="form.plans.splice(i, 1)" />
          </div>
          <div class="plan-grid">
            <el-form-item label="名称" required>
              <el-input v-model="p.name" :maxlength="LIMIT.planName" placeholder="如 专业版" />
            </el-form-item>
            <el-form-item label="价格">
              <div class="price-row">
                <el-input v-model="p.price" :maxlength="LIMIT.price" placeholder="如 ¥899，留空显示联系咨询" />
                <span class="slash">/</span>
                <el-input v-model="p.period" class="w-period" :maxlength="LIMIT.period" placeholder="月" aria-label="计费周期" />
              </div>
            </el-form-item>
            <el-form-item label="一句话说明">
              <el-input v-model="p.desc" :maxlength="LIMIT.planDesc" placeholder="适合什么样的客户" />
            </el-form-item>
            <el-form-item label="关联套餐">
              <el-select v-model="p.plan_code" clearable placeholder="不关联" class="full">
                <el-option v-for="row in plans" :key="row.code" :label="`${row.name}（${row.code}）`" :value="row.code" />
              </el-select>
              <div class="hint">{{ p.plan_code ? `首页会显示：${planLimits(p.plan_code) || '该套餐没有设置上限'}` : '关联后自动显示该套餐的节点、域名、集群上限' }}</div>
            </el-form-item>
            <el-form-item label="包含内容" class="span2">
              <el-input
                v-model="p.items"
                type="textarea"
                :rows="3"
                resize="vertical"
                :placeholder="`每行一条，最多 ${LIMIT.planItems} 条，每条 ${LIMIT.planItem} 字以内`"
              />
            </el-form-item>
          </div>
        </div>
        <div v-if="!form.plans.length" class="empty">没有套餐，首页不显示价格</div>
        <el-button :icon="Plus" :disabled="form.plans.length >= LIMIT.plans" @click="addPlan">添加套餐</el-button>
        <span class="hint inline">最多 {{ LIMIT.plans }} 个。这里只是展示，实际开通的配额仍以「套餐」页为准。</span>
      </el-card>

      <el-card class="card" shadow="never">
        <template #header>联系方式</template>
        <div class="form">
          <el-form-item label="说明">
            <el-input v-model="form.contact_note" :maxlength="LIMIT.note" show-word-limit placeholder="显示在联系我们下方，可留空" />
          </el-form-item>
        </div>
        <div v-for="(c, i) in form.contacts" :key="i" class="row">
          <el-select v-model="c.type" class="w-type" :aria-label="`第 ${i + 1} 个联系方式类型`">
            <el-option v-for="t in contactTypes" :key="t.value" :label="t.label" :value="t.value" />
          </el-select>
          <el-input
            v-model="c.label"
            class="w-title"
            :maxlength="LIMIT.contactLabel"
            :placeholder="`名称，默认「${contactMeta[c.type]?.label}」`"
            :aria-label="`第 ${i + 1} 个联系方式名称`"
          />
          <el-input
            v-model="c.value"
            class="grow"
            :maxlength="LIMIT.contactValue"
            :placeholder="contactMeta[c.type]?.placeholder"
            :aria-label="`第 ${i + 1} 个联系方式内容`"
          />
          <div class="ops">
            <el-button :icon="ArrowUp" text :disabled="i === 0" :aria-label="`上移第 ${i + 1} 个联系方式`" @click="move(form.contacts, i, -1)" />
            <el-button
              :icon="ArrowDown"
              text
              :disabled="i === form.contacts.length - 1"
              :aria-label="`下移第 ${i + 1} 个联系方式`"
              @click="move(form.contacts, i, 1)"
            />
            <el-button :icon="Delete" text type="danger" :aria-label="`删除第 ${i + 1} 个联系方式`" @click="form.contacts.splice(i, 1)" />
          </div>
        </div>
        <div v-if="!form.contacts.length" class="empty">还没有联系方式，访客无法联系你开通</div>
        <el-button :icon="Plus" :disabled="form.contacts.length >= LIMIT.contacts" @click="addContact">添加联系方式</el-button>
        <span class="hint inline">邮箱、电话、Telegram 会显示为可点击的链接；微信和 QQ 只显示号码</span>
      </el-card>

      <el-card class="card" shadow="never">
        <template #header>页脚</template>
        <div class="form">
          <el-form-item label="备案号">
            <el-input v-model="form.icp" :maxlength="LIMIT.icp" placeholder="如 京ICP备00000000号，留空不显示" />
            <div class="hint">填写后在页脚显示，并链接到工信部备案查询网站</div>
          </el-form-item>
          <el-form-item label="附加文字">
            <el-input v-model="form.footer_note" :maxlength="LIMIT.footer" show-word-limit placeholder="可留空" />
          </el-form-item>
        </div>
      </el-card>

      <el-button type="primary" native-type="submit" :loading="saving">保存首页</el-button>
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
.form {
  max-width: 620px;
}
.hint {
  font-size: 12px;
  color: var(--text-dim, #999);
  line-height: 1.6;
  margin-top: 4px;
}
.hint.inline {
  margin-left: 10px;
}
.row {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}
.w-icon {
  width: 150px;
  flex: none;
}
.w-type {
  width: 120px;
  flex: none;
}
.w-title {
  width: 170px;
  flex: none;
}
.grow {
  flex: 1;
  min-width: 0;
}
.ops {
  display: flex;
  flex: none;
}
.ops .el-button + .el-button,
.plan-head .el-button + .el-button {
  margin-left: 0;
}
.opt {
  display: inline-flex;
  align-items: center;
  gap: 8px;
}
.empty {
  font-size: 13px;
  color: var(--text-dim, #999);
  padding: 6px 0 10px;
}
.plan {
  border: 1px solid var(--line, #2a3a57);
  border-radius: 8px;
  padding: 10px 14px 4px;
  margin-bottom: 12px;
}
.plan-head {
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 6px;
}
.plan-no {
  font-weight: 600;
}
.spacer {
  flex: 1;
}
.plan-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  column-gap: 16px;
}
.plan-grid :deep(.el-form-item) {
  margin-bottom: 14px;
}
.span2 {
  grid-column: span 2;
}
.price-row {
  display: flex;
  align-items: center;
  gap: 6px;
  width: 100%;
}
.slash {
  color: var(--text-dim, #999);
}
.w-period {
  width: 80px;
  flex: none;
}
.full {
  width: 100%;
}
@media (max-width: 860px) {
  .row {
    flex-wrap: wrap;
  }
  .grow {
    flex-basis: 100%;
  }
  .plan-grid {
    grid-template-columns: 1fr;
  }
  .span2 {
    grid-column: auto;
  }
}
</style>
