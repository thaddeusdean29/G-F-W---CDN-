import { createApp } from 'vue'
import { createPinia } from 'pinia'
import ElementPlus from 'element-plus'
import 'element-plus/dist/index.css'
import 'element-plus/theme-chalk/dark/css-vars.css'
import './styles/theme.css'
import App from './App.vue'
import router from './router'
import { setUnauthenticatedHandler } from './api/client'
import { useAuthStore } from './stores/auth'
import { useAdminStore } from './stores/admin'
import { useBrandingStore } from './stores/branding'

document.documentElement.classList.add('dark')

const app = createApp(App)
const pinia = createPinia()
app.use(pinia)
app.use(router)
app.use(ElementPlus)

// 401 时清空本地会话状态，路由守卫会在下一次导航把用户送回登录页。
setUnauthenticatedHandler(() => {
  useAuthStore().clearSession()
})
setUnauthenticatedHandler(() => {
  useAdminStore().clearSession()
}, 'admin')

// 平台名称不阻塞首屏，拿到后各处响应式更新。
void useBrandingStore().load()

app.mount('#app')
