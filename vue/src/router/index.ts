import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'
import { useAdminStore } from '@/stores/admin'

const router = createRouter({
  // 与 vite.config.ts 的生产 base 保持一致：编译进 cdnpanel 后整个 SPA 挂在 /console/ 下，
  // 根路径 / 由 cdnpanel 302 到 /console/。import.meta.env.BASE_URL 在 dev 模式下是 '/'。
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/login',
      name: 'login',
      component: () => import('@/views/LoginView.vue'),
      meta: { public: true },
    },
    {
      path: '/',
      name: 'dashboard',
      component: () => import('@/views/DashboardView.vue'),
    },
    {
      path: '/domains',
      name: 'domains',
      component: () => import('@/views/DomainsView.vue'),
    },
    {
      path: '/clusters',
      name: 'clusters',
      component: () => import('@/views/ClustersView.vue'),
    },
    {
      path: '/nodes',
      name: 'nodes',
      component: () => import('@/views/NodesView.vue'),
    },
    {
      path: '/traffic',
      name: 'traffic',
      component: () => import('@/views/TrafficView.vue'),
    },
    {
      path: '/attacks',
      name: 'attacks',
      component: () => import('@/views/AttacksView.vue'),
    },
    {
      path: '/cc',
      name: 'cc',
      component: () => import('@/views/CCView.vue'),
    },
    {
      path: '/xdp',
      name: 'xdp',
      component: () => import('@/views/XDPView.vue'),
    },
    {
      path: '/waf',
      name: 'waf',
      component: () => import('@/views/WAFView.vue'),
    },
    {
      path: '/cache',
      name: 'cache',
      component: () => import('@/views/CacheView.vue'),
    },
    {
      path: '/tags',
      name: 'tags',
      component: () => import('@/views/TagsView.vue'),
    },
    {
      path: '/settings',
      name: 'settings',
      component: () => import('@/views/SettingsView.vue'),
    },
    // 平台管理员：开通代理（每个代理一套独立后台）。用 cdn_admin_session，与代理登录互不相通。
    {
      path: '/admin/login',
      name: 'admin-login',
      component: () => import('@/views/AdminLoginView.vue'),
      meta: { public: true, admin: true },
    },
    {
      path: '/admin',
      name: 'admin-tenants',
      component: () => import('@/views/AdminTenantsView.vue'),
      meta: { admin: true },
    },
    {
      path: '/admin/plans',
      name: 'admin-plans',
      component: () => import('@/views/AdminPlansView.vue'),
      meta: { admin: true },
    },
    {
      path: '/admin/settings',
      name: 'admin-settings',
      component: () => import('@/views/AdminSettingsView.vue'),
      meta: { admin: true },
    },
    {
      path: '/admin/waf',
      name: 'admin-waf',
      component: () => import('@/views/AdminWafView.vue'),
      meta: { admin: true },
    },
    {
      path: '/admin/geo',
      name: 'admin-geo',
      component: () => import('@/views/AdminGeoView.vue'),
      meta: { admin: true },
    },
    {
      path: '/admin/homepage',
      name: 'admin-homepage',
      component: () => import('@/views/AdminHomepageView.vue'),
      meta: { admin: true },
    },
    {
      path: '/admin/faq',
      name: 'admin-faq',
      component: () => import('@/views/AdminFAQView.vue'),
      meta: { admin: true },
    },
  ],
})

// 会话检查：第一次进入任何页面时先查一次 /auth/me，之后直接看内存状态。
// 401 拦截器会调用 clearSession()，下一次路由跳转会被这里拦回登录页。
// /admin 下只查管理员会话，其余只查代理会话，两边互不影响。
router.beforeEach(async (to) => {
  if (to.meta.admin) {
    const admin = useAdminStore()
    if (admin.loading) {
      await admin.fetchMe()
    }
    if (!admin.isAuthenticated && !to.meta.public) {
      return { name: 'admin-login', query: { redirect: to.fullPath } }
    }
    if (admin.isAuthenticated && to.name === 'admin-login') {
      return { name: 'admin-tenants' }
    }
    return true
  }

  const auth = useAuthStore()
  if (auth.loading) {
    await auth.fetchMe()
  }
  if (!auth.isAuthenticated && !to.meta.public) {
    return { name: 'login', query: { redirect: to.fullPath } }
  }
  if (auth.isAuthenticated && to.name === 'login') {
    return { name: 'dashboard' }
  }
  return true
})

export default router
