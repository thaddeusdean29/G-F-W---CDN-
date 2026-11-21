<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage } from 'element-plus'
import { ArrowDown, ArrowUp, Delete, Plus } from '@element-plus/icons-vue'
import {
  deleteFavicon,
  fetchAdminSettings,
  saveAdminSettings,
  uploadFavicon,
  type BrandingView,
  type LoginFeature,
} from '@/api/branding'
import { useBrandingStore } from '@/stores/branding'
import { ApiClientError } from '@/api/client'
import { featureIconNames, featureIcons } from '@/utils/featureIcons'

// 平台系统设置：平台名称、网站图标、登录页标语和功能卡片，所有代理后台共用。

const branding = useBrandingStore()
const form = reactive({
  platform_name: '',
  logo_text: '',
  login_subtitle: '',
  login_slogan: '',
  login_features: [] as LoginFeature[],
})
const loading = ref(true)
const saving = ref(false)
const error = ref('')
const faviconUrl = ref('')
const iconBusy = ref(false)
const fileInput = ref<HTMLInputElement>()

const ICON_TYPES = ['image/png', 'image/x-icon', 'image/vnd.microsoft.icon', 'image/jpeg', 'image/gif', 'image/webp']
const ICON_MAX = 256 * 1024

// 和后端 platform_settings.go 的限制一致
const MAX_FEATURES = 6
const MAX_SLOGAN = 40
const MAX_TITLE = 12
const MAX_DESC = 32

const DEFAULT_FEATURES: LoginFeature[] = [
  { icon: 'Connection', title: '全球边缘加速', desc: '多节点就近接入，智能回源与缓存' },
  { icon: 'Lightning', title: 'XDP 四层防护', desc: '内核态丢弃洪水与反射攻击' },
  { icon: 'Lock', title: 'CC / WAF 防御', desc: '人机验证与规则引擎双层拦截' },
  { icon: 'DataLine', title: '实时流量统计', desc: '节点主动上报，攻击态势一目了然' },
]

function applyView(v: BrandingView) {
  Object.assign(form, {
    platform_name: v.platform_name,
    logo_text: v.logo_text,
    login_subtitle: v.login_subtitle,
    login_slogan: v.login_slogan,
    login_features: (v.login_features ?? []).map((f) => ({ ...f })),
  })
  setIcon(v)
}

// 图标操作只刷新图标，不覆盖表单里还没保存的文字。
function setIcon(v: BrandingView) {
  faviconUrl.value = v.favicon_url
  branding.apply(v)
}

async function onPickIcon(ev: Event) {
  const input = ev.target as HTMLInputElement
  const file = input.files?.[0]
  input.value = ''
  if (!file) return
  if (file.type && !ICON_TYPES.includes(file.type)) {
    return ElMessage.error('只支持 ICO、PNG、JPG、GIF、WebP 格式')
  }
  if (file.size > ICON_MAX) return ElMessage.error('图标不能超过 256 KB')
  iconBusy.value = true
  try {
    setIcon(await uploadFavicon(file))
    ElMessage.success('图标已更新')
  } catch (e) {
    ElMessage.error(e instanceof ApiClientError ? e.message : '上传失败')
  } finally {
    iconBusy.value = false
  }
}

async function removeIcon() {
  iconBusy.value = true
  try {
    setIcon(await deleteFavicon())
    ElMessage.success('已恢复默认图标')
  } catch (e) {
    ElMessage.error(e instanceof ApiClientError ? e.message : '操作失败')
  } finally {
    iconBusy.value = false
  }
}

function addFeature() {
  if (form.login_features.length >= MAX_FEATURES) return
  form.login_features.push({ icon: 'Star', title: '', desc: '' })
}

function removeFeature(i: number) {
  form.login_features.splice(i, 1)
}

function moveFeature(i: number, delta: number) {
  const j = i + delta
  const list = form.login_features
  if (j < 0 || j >= list.length) return
  ;[list[i], list[j]] = [list[j], list[i]]
}

function resetFeatures() {
  form.login_features = DEFAULT_FEATURES.map((f) => ({ ...f }))
}

// 标语按行清理：去掉每行首尾空白和空行，最多两行。
function cleanSlogan(s: string) {
  return s
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)
    .join('\n')
}

async function load() {
  loading.value = true
  error.value = ''
  try {
    applyView(await fetchAdminSettings())
  } catch (e) {
    error.value = e instanceof ApiClientError ? e.message : '加载失败'
  } finally {
    loading.value = false
  }
}

async function save() {
  if (!form.platform_name.trim()) return ElMessage.error('请填写平台名称')
  const slogan = cleanSlogan(form.login_slogan)
  if (slogan.split('\n').length > 2) return ElMessage.error('标语最多两行')
  const features = form.login_features.map((f) => ({ icon: f.icon, title: f.title.trim(), desc: f.desc.trim() }))
  const empty = features.findIndex((f) => !f.title)
  if (empty >= 0) return ElMessage.error(`第 ${empty + 1} 张卡片标题必填`)
  saving.value = true
  try {
    const saved = await saveAdminSettings({
      platform_name: form.platform_name.trim(),
      logo_text: form.logo_text.trim(),
      login_subtitle: form.login_subtitle.trim(),
      login_slogan: slogan,
      login_features: features,
    })
    applyView(saved)
    ElMessage.success('已保存')
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
      <h1>系统设置</h1>
    </div>
    <el-alert v-if="error" :title="error" type="error" show-icon :closable="false" class="alert" />
    <el-form v-loading="loading" label-width="110px" @submit.prevent="save">
      <el-card class="card" shadow="never">
        <template #header>平台品牌</template>
        <div class="form">
          <el-form-item label="平台名称" required>
            <el-input v-model="form.platform_name" maxlength="32" show-word-limit placeholder="例如 某某云 CDN" />
            <div class="hint">显示在登录页、侧边栏和浏览器标题，所有代理后台共用</div>
          </el-form-item>
          <el-form-item label="Logo 文字">
            <el-input v-model="form.logo_text" maxlength="6" show-word-limit placeholder="留空则为 CDN" />
            <div class="hint">登录页图标里的短文字</div>
          </el-form-item>
          <el-form-item label="网站图标">
            <div class="icon-row">
              <div class="icon-preview" aria-hidden="true">
                <img v-if="faviconUrl" :src="faviconUrl" alt="" />
                <span v-else>无</span>
              </div>
              <input
                ref="fileInput"
                type="file"
                accept=".ico,.png,.jpg,.jpeg,.gif,.webp,image/png,image/x-icon,image/jpeg,image/gif,image/webp"
                class="file-input"
                aria-label="选择网站图标文件"
                @change="onPickIcon"
              />
              <el-button :loading="iconBusy" @click="fileInput?.click()">{{ faviconUrl ? '更换图标' : '上传图标' }}</el-button>
              <el-button v-if="faviconUrl" :disabled="iconBusy" @click="removeIcon">恢复默认</el-button>
            </div>
            <div class="hint">浏览器标签页上的小图标。支持 ICO / PNG / JPG / GIF / WebP，不超过 256 KB，建议 64×64 的正方形 PNG。上传后立即生效。</div>
          </el-form-item>
        </div>
      </el-card>

      <el-card class="card" shadow="never">
        <template #header>登录页内容</template>
        <div class="form">
          <el-form-item label="标语">
            <el-input
              v-model="form.login_slogan"
              type="textarea"
              :rows="2"
              :maxlength="MAX_SLOGAN"
              show-word-limit
              resize="none"
              placeholder="留空则用默认标语"
            />
            <div class="hint">登录页左侧的大字标题，回车换行，最多两行</div>
          </el-form-item>
          <el-form-item label="副标题">
            <el-input v-model="form.login_subtitle" maxlength="64" show-word-limit placeholder="留空则用默认文案" />
            <div class="hint">显示在标语下方</div>
          </el-form-item>
        </div>

        <el-form-item label="功能卡片">
          <div class="features">
            <div v-for="(f, i) in form.login_features" :key="i" class="feature">
              <el-select v-model="f.icon" class="f-icon" :aria-label="`第 ${i + 1} 张卡片图标`">
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
                class="f-title"
                :maxlength="MAX_TITLE"
                placeholder="标题（必填）"
                :aria-label="`第 ${i + 1} 张卡片标题`"
              />
              <el-input
                v-model="f.desc"
                class="f-desc"
                :maxlength="MAX_DESC"
                placeholder="一句话说明"
                :aria-label="`第 ${i + 1} 张卡片说明`"
              />
              <div class="f-ops">
                <el-button :icon="ArrowUp" text :disabled="i === 0" :aria-label="`上移第 ${i + 1} 张卡片`" @click="moveFeature(i, -1)" />
                <el-button
                  :icon="ArrowDown"
                  text
                  :disabled="i === form.login_features.length - 1"
                  :aria-label="`下移第 ${i + 1} 张卡片`"
                  @click="moveFeature(i, 1)"
                />
                <el-button :icon="Delete" text type="danger" :aria-label="`删除第 ${i + 1} 张卡片`" @click="removeFeature(i)" />
              </div>
            </div>
            <div v-if="!form.login_features.length" class="empty">没有卡片，登录页不显示这一块</div>
            <div class="f-actions">
              <el-button :icon="Plus" :disabled="form.login_features.length >= MAX_FEATURES" @click="addFeature">添加卡片</el-button>
              <el-button text @click="resetFeatures">恢复默认卡片</el-button>
            </div>
            <div class="hint">最多 {{ MAX_FEATURES }} 张，标题 {{ MAX_TITLE }} 字以内，说明 {{ MAX_DESC }} 字以内。图标只能从列表里选。</div>
          </div>
        </el-form-item>
      </el-card>

      <el-button type="primary" native-type="submit" :loading="saving">保存设置</el-button>
    </el-form>
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
.card {
  max-width: 860px;
  margin-bottom: 16px;
}
.form {
  max-width: 560px;
}
.icon-row {
  display: flex;
  align-items: center;
  gap: 10px;
}
.icon-preview {
  width: 40px;
  height: 40px;
  border: 1px solid var(--line, #444);
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 12px;
  color: var(--text-dim, #999);
  overflow: hidden;
}
.icon-preview img {
  max-width: 32px;
  max-height: 32px;
}
.file-input {
  display: none;
}
.hint {
  font-size: 12px;
  color: var(--text-dim, #999);
  line-height: 1.6;
  margin-top: 4px;
}
.features {
  width: 100%;
}
.feature {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}
.f-icon {
  width: 150px;
  flex: none;
}
.f-title {
  width: 160px;
  flex: none;
}
.f-desc {
  flex: 1;
  min-width: 0;
}
.f-ops {
  display: flex;
  flex: none;
}
.f-ops .el-button + .el-button {
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
  padding: 6px 0;
}
.f-actions {
  display: flex;
  gap: 8px;
  margin-top: 4px;
}
@media (max-width: 760px) {
  .feature {
    flex-wrap: wrap;
  }
  .f-desc {
    flex-basis: 100%;
  }
}
</style>
