import { defineStore } from 'pinia'
import { fetchBranding, type BrandingView } from '@/api/branding'

// 平台名称等品牌信息。加载失败时保留默认值，不影响登录和使用。
export const useBrandingStore = defineStore('branding', {
  state: (): BrandingView & { loaded: boolean } => ({
    platform_name: 'CDN 控制台',
    logo_text: 'CDN',
    login_subtitle: '欢迎回来，请登录你的账号',
    login_slogan: '让每一次访问\n都更快、更安全',
    login_features: [
      { icon: 'Connection', title: '全球边缘加速', desc: '多节点就近接入，智能回源与缓存' },
      { icon: 'Lightning', title: 'XDP 四层防护', desc: '内核态丢弃洪水与反射攻击' },
      { icon: 'Lock', title: 'CC / WAF 防御', desc: '人机验证与规则引擎双层拦截' },
      { icon: 'DataLine', title: '实时流量统计', desc: '节点主动上报，攻击态势一目了然' },
    ],
    favicon_url: '',
    loaded: false,
  }),
  actions: {
    async load() {
      try {
        this.apply(await fetchBranding())
      } catch {
        // 保留默认值
      } finally {
        this.loaded = true
      }
    },
    apply(b: BrandingView) {
      this.platform_name = b.platform_name
      this.logo_text = b.logo_text
      this.login_subtitle = b.login_subtitle
      this.login_slogan = b.login_slogan
      this.login_features = b.login_features ?? []
      this.favicon_url = b.favicon_url
      document.title = b.platform_name
      setFavicon(b.favicon_url)
    },
  },
})

// 替换页面的 <link rel="icon">；没有上传图标时移除，浏览器回落到默认图标。
function setFavicon(url: string) {
  let link = document.querySelector<HTMLLinkElement>('link[rel="icon"]')
  if (!url) {
    link?.remove()
    return
  }
  if (!link) {
    link = document.createElement('link')
    link.rel = 'icon'
    document.head.appendChild(link)
  }
  link.href = url
}
