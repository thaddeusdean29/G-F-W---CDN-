<script setup lang="ts">
import { computed, reactive, ref } from 'vue'
import { useRoute } from 'vue-router'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'
import { useAuthStore } from '@/stores/auth'
import { useAdminStore } from '@/stores/admin'
import { useBrandingStore } from '@/stores/branding'
import { errMessage } from '@/utils/format'

const route = useRoute()
const auth = useAuthStore()
const admin = useAdminStore()
const branding = useBrandingStore()
const showShell = computed(() => !route.meta.public)
const isAdmin = computed(() => !!route.meta.admin)

interface NavItem {
  to: string
  label: string
}
interface NavGroup {
  title: string
  items: NavItem[]
}

const tenantNav: NavGroup[] = [
  {
    title: '概览',
    items: [
      { to: '/', label: '看板' },
      { to: '/traffic', label: '流量统计' },
    ],
  },
  {
    title: '域名与集群',
    items: [
      { to: '/domains', label: '域名' },
      { to: '/clusters', label: '集群' },
      { to: '/nodes', label: '节点' },
      { to: '/tags', label: '标签分类' },
      { to: '/cache', label: '缓存' },
    ],
  },
  {
    title: '安全防御',
    items: [
      { to: '/attacks', label: '攻击列表' },
      { to: '/cc', label: 'CC 防御' },
      { to: '/xdp', label: 'XDP 防御' },
      { to: '/waf', label: 'WAF' },
    ],
  },
  {
    title: '设置',
    items: [{ to: '/settings', label: 'Cloudflare 设置' }],
  },
]

const adminNav: NavGroup[] = [
  {
    title: '平台管理',
    items: [
      { to: '/admin', label: '代理管理' },
      { to: '/admin/plans', label: '套餐' },
      { to: '/admin/waf', label: 'WAF 规则包' },
      { to: '/admin/geo', label: '区域封禁' },
      { to: '/admin/homepage', label: '首页设置' },
      { to: '/admin/faq', label: '常见问题' },
      { to: '/admin/settings', label: '系统设置' },
    ],
  },
]

const nav = computed(() => (isAdmin.value ? adminNav : tenantNav))

// 看板 / 与 /admin 用精确匹配，否则所有子页面都会高亮它们。
function isActive(to: string): boolean {
  if (to === '/' || to === '/admin') return route.path === to
  return route.path === to || route.path.startsWith(to + '/')
}

async function handleLogout() {
  await auth.logout()
  // 生产环境 SPA 挂在 /console/ 下，写死 '/login' 会跳出控制台（根路径只做跳转）。
  // 整页跳转（而非 router.push）顺带清掉内存里的状态。
  window.location.href = import.meta.env.BASE_URL + 'login'
}

async function handleAdminLogout() {
  await admin.logout()
  window.location.href = import.meta.env.BASE_URL + 'admin/login'
}

// 平台管理员改密码：端点是 PATCH /api/v2/admin/auth/me。除了改 admin_users，后端还会
// 把安装向导用同一登录名建出来的代理端账号一起改掉，并让其他设备的登录态失效——
// 这两件事都必须在这句成功提示里说清楚，否则用户会以为只影响当前这台机器。
const pwdVisible = ref(false)
const pwdFormRef = ref<FormInstance>()
const pwdSaving = ref(false)
const pwdForm = reactive({ old: '', next: '', confirm: '' })

const pwdRules: FormRules = {
  old: [{ required: true, message: '请输入原密码', trigger: 'blur' }],
  next: [
    { required: true, message: '请输入新密码', trigger: 'blur' },
    { min: 8, max: 72, message: '密码需 8–72 位', trigger: 'blur' },
    {
      // 后端 hashPassword 也是这个区间：bcrypt 只取前 72 字节，超出的部分会被静默丢掉。
      validator: (_rule, value, callback) =>
        callback(value === pwdForm.confirm ? undefined : new Error('两次输入的新密码不一致')),
      trigger: 'blur',
    },
  ],
  confirm: [{ required: true, message: '请再次输入新密码', trigger: 'blur' }],
}

function openPasswordDialog() {
  pwdForm.old = ''
  pwdForm.next = ''
  pwdForm.confirm = ''
  pwdVisible.value = true
}

async function submitPassword() {
  if (!(await pwdFormRef.value?.validate().catch(() => false))) return
  pwdSaving.value = true
  try {
    await admin.changePassword(pwdForm.old, pwdForm.next)
    ElMessage.success('密码已修改，其他设备的登录状态已失效，需要重新登录')
    pwdVisible.value = false
  } catch (e) {
    ElMessage.error(errMessage(e, '修改密码失败'))
  } finally {
    pwdSaving.value = false
  }
}
</script>

<template>
  <div v-if="showShell" class="shell">
    <aside class="sidebar">
      <div class="brand">
        <span class="logo" aria-hidden="true"></span>
        <div>
          <div class="brand-name">{{ isAdmin ? branding.platform_name + ' · 管理' : branding.platform_name }}</div>
          <div class="brand-sub mono">EDGE · DEFENSE</div>
        </div>
      </div>
      <nav aria-label="主导航">
        <div v-for="g in nav" :key="g.title" class="nav-group">
          <div class="nav-title">{{ g.title }}</div>
          <RouterLink
            v-for="it in g.items"
            :key="it.to"
            :to="it.to"
            :class="{ active: isActive(it.to) }"
            :aria-current="isActive(it.to) ? 'page' : undefined"
          >
            {{ it.label }}
          </RouterLink>
        </div>
      </nav>
      <div v-if="isAdmin && admin.me" class="tenant-info">
        <div class="who">{{ admin.me.admin.username }}</div>
        <div class="plan">平台管理员</div>
        <button type="button" class="quiet" @click="openPasswordDialog">修改密码</button>
        <button type="button" @click="handleAdminLogout">退出登录</button>
      </div>
      <div v-else-if="!isAdmin && auth.me" class="tenant-info">
        <div class="who">{{ auth.me.tenant.name }}</div>
        <div class="plan">{{ auth.me.plan.name }}</div>
        <button type="button" @click="handleLogout">退出登录</button>
      </div>
    </aside>
    <main class="content">
      <RouterView />
    </main>
    <el-dialog v-if="isAdmin" v-model="pwdVisible" title="修改密码" width="420px">
      <el-form
        ref="pwdFormRef"
        :model="pwdForm"
        :rules="pwdRules"
        label-position="top"
        @submit.prevent="submitPassword"
      >
        <el-form-item label="原密码" prop="old">
          <el-input v-model="pwdForm.old" type="password" show-password autocomplete="current-password" />
        </el-form-item>
        <el-form-item label="新密码" prop="next">
          <el-input
            v-model="pwdForm.next"
            type="password"
            show-password
            maxlength="72"
            placeholder="8–72 位"
            autocomplete="new-password"
          />
        </el-form-item>
        <el-form-item label="确认新密码" prop="confirm">
          <el-input
            v-model="pwdForm.confirm"
            type="password"
            show-password
            maxlength="72"
            autocomplete="new-password"
          />
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="pwdVisible = false">取消</el-button>
        <el-button type="primary" :loading="pwdSaving" @click="submitPassword">修改密码</el-button>
      </template>
    </el-dialog>
  </div>
  <RouterView v-else />
</template>

<style>
.shell {
  display: flex;
  min-height: 100vh;
}
.sidebar {
  width: 216px;
  flex-shrink: 0;
  position: sticky;
  top: 0;
  height: 100vh;
  padding: 18px 14px;
  display: flex;
  flex-direction: column;
  background: var(--panel);
  border-right: 1px solid var(--line);
}
.brand {
  display: flex;
  align-items: center;
  gap: 10px;
  margin: 0 4px 22px;
}
.logo {
  width: 30px;
  height: 30px;
  border-radius: 6px;
  background: var(--accent-strong);
  position: relative;
}
.logo::after {
  content: '';
  position: absolute;
  inset: 7px;
  border-radius: 3px;
  background: var(--panel);
}
.brand-name {
  font-weight: 600;
  color: var(--text);
}
.brand-sub {
  font-size: 10px;
  color: var(--text-dim);
}
.sidebar nav {
  flex: 1;
  overflow-y: auto;
}
.nav-group {
  margin-bottom: 14px;
}
.nav-title {
  font-size: 11px;
  color: var(--text-dim);
  margin: 0 10px 6px;
}
.sidebar nav a {
  display: block;
  position: relative;
  color: var(--text-dim);
  text-decoration: none;
  padding: 8px 12px;
  border-radius: 6px;
  font-size: 14px;
  transition: background 0.15s, color 0.15s;
}
.sidebar nav a:hover {
  background: rgba(255, 255, 255, 0.05);
  color: var(--text);
}
.sidebar nav a:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 1px;
}
.sidebar nav a.active {
  color: var(--text);
  background: color-mix(in srgb, var(--accent) 14%, transparent);
}
.sidebar nav a.active::before {
  content: '';
  position: absolute;
  left: 0;
  top: 6px;
  bottom: 6px;
  width: 3px;
  border-radius: 2px;
  background: var(--accent);
}
.tenant-info {
  font-size: 13px;
  color: var(--text-dim);
  border-top: 1px solid var(--line);
  padding: 12px 4px 0;
}
.tenant-info .who {
  color: var(--text);
  word-break: break-all;
}
.tenant-info .plan {
  margin: 4px 0 10px;
  color: var(--text-dim);
  font-size: 12px;
}
.tenant-info button {
  width: 100%;
  padding: 7px;
  background: transparent;
  border: 1px solid var(--line-strong);
  color: var(--text);
  border-radius: 6px;
  cursor: pointer;
}
.tenant-info button:hover {
  background: color-mix(in srgb, var(--danger) 14%, transparent);
  border-color: var(--danger);
}
/* 侧边栏现在有两枚按钮，红底只留给退出登录，否则看起来像两个危险操作。 */
.tenant-info button + button {
  margin-top: 8px;
}
.tenant-info button.quiet:hover {
  background: rgba(255, 255, 255, 0.06);
  border-color: var(--accent);
}
.content {
  flex: 1;
  min-width: 0;
  padding: 24px 28px;
}
</style>
