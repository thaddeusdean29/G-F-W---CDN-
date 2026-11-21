<script setup lang="ts">
import { computed } from 'vue'
import { useBrandingStore } from '@/stores/branding'
import { featureIcons } from '@/utils/featureIcons'

// 代理登录页和管理员登录页共用的外框：左侧品牌展示，右侧登录卡片。
// 两种登录页只靠 badge / title / subtitle 文案区分，不再各占一种色相。
// 窄屏（<900px）只显示卡片，品牌信息挪到卡片顶部。

defineProps<{
  badge: string
  title: string
  subtitle: string
}>()

const branding = useBrandingStore()

// 标语和功能卡片来自系统设置；文字一律走插值渲染，不用 v-html。
const sloganLines = computed(() => branding.login_slogan.split('\n').filter(Boolean))
const features = computed(() =>
  branding.login_features.map((f) => ({ ...f, component: featureIcons[f.icon] ?? featureIcons.Star })),
)
</script>

<template>
  <div class="login-page">
    <section class="showcase" aria-hidden="true">
      <div class="brand-row">
        <div class="logo">
          <img v-if="branding.favicon_url" :src="branding.favicon_url" alt="" />
          <span v-else>{{ branding.logo_text }}</span>
        </div>
        <span class="brand-name">{{ branding.platform_name }}</span>
      </div>

      <div class="hero">
        <p class="eyebrow mono">EDGE · ACCELERATION · DEFENSE</p>
        <h2><template v-for="(line, i) in sloganLines" :key="i"><br v-if="i" />{{ line }}</template></h2>
        <p class="lead">{{ branding.login_subtitle }}</p>
      </div>

      <ul v-if="features.length" class="features">
        <li v-for="(f, i) in features" :key="i">
          <span class="f-icon"><el-icon><component :is="f.component" /></el-icon></span>
          <div>
            <div class="f-title">{{ f.title }}</div>
            <div v-if="f.desc" class="f-desc">{{ f.desc }}</div>
          </div>
        </li>
      </ul>
    </section>

    <main class="auth">
      <div class="card">
        <div class="card-head">
          <div class="mobile-brand">
            <div class="logo sm">
              <img v-if="branding.favicon_url" :src="branding.favicon_url" alt="" />
              <span v-else>{{ branding.logo_text }}</span>
            </div>
            <span class="brand-name">{{ branding.platform_name }}</span>
          </div>
          <span class="badge mono">{{ badge }}</span>
          <h1>{{ title }}</h1>
          <p class="subtitle">{{ subtitle }}</p>
        </div>

        <slot />

        <div class="card-foot">
          <slot name="footer" />
        </div>
      </div>
      <p class="copyright">© {{ new Date().getFullYear() }} {{ branding.platform_name }}</p>
    </main>
  </div>
</template>

<style scoped>
.login-page {
  display: grid;
  grid-template-columns: minmax(0, 1.15fr) minmax(0, 1fr);
  min-height: 100vh;
  overflow: hidden;
}

/* 左侧品牌展示 */
.showcase {
  display: flex;
  flex-direction: column;
  padding: 48px 56px;
  border-right: 1px solid var(--line);
  background: var(--panel);
}
.brand-row {
  display: flex;
  align-items: center;
  gap: 12px;
}
.logo {
  min-width: 44px;
  height: 44px;
  padding: 0 8px;
  border-radius: 8px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  font-size: 14px;
  color: #fff;
  background: var(--accent-strong);
}
.logo img {
  width: 28px;
  height: 28px;
  object-fit: contain;
}
.logo.sm {
  min-width: 36px;
  height: 36px;
  font-size: 12px;
  border-radius: 6px;
}
.logo.sm img {
  width: 22px;
  height: 22px;
}
.brand-name {
  font-size: 18px;
  font-weight: 600;
  color: var(--text);
}

.hero {
  margin-top: auto;
}
.eyebrow {
  margin: 0 0 16px;
  font-size: 12px;
  letter-spacing: 1px;
  color: var(--text-dim);
}
.hero h2 {
  margin: 0;
  font-size: 30px;
  line-height: 1.35;
  font-weight: 600;
  color: var(--text);
}
.lead {
  margin: 18px 0 0;
  max-width: 440px;
  font-size: 14px;
  line-height: 1.7;
  color: var(--text-dim);
}

.features {
  list-style: none;
  margin: 40px 0 auto;
  padding: 0;
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 14px;
  max-width: 560px;
}
.features li {
  display: flex;
  gap: 12px;
  padding: 14px;
  border: 1px solid var(--line);
  border-radius: 8px;
  background: var(--panel-2);
}
.f-icon {
  flex: none;
  width: 34px;
  height: 34px;
  border-radius: 6px;
  display: flex;
  align-items: center;
  justify-content: center;
  font-size: 17px;
  color: var(--accent);
  background: color-mix(in srgb, var(--accent) 12%, transparent);
}
.f-title {
  font-size: 14px;
  font-weight: 600;
  color: var(--text);
}
.f-desc {
  margin-top: 4px;
  font-size: 12px;
  line-height: 1.5;
  color: var(--text-dim);
}

/* 右侧登录卡片 */
.auth {
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  padding: 32px 20px;
}
.card {
  width: 100%;
  max-width: 400px;
  padding: 36px 32px 26px;
  border-radius: 10px;
  border: 1px solid var(--line);
  background: var(--panel);
  box-shadow: 0 8px 24px rgba(0, 0, 0, 0.4);
}
.card-head {
  margin-bottom: 28px;
}
.mobile-brand {
  display: none;
  align-items: center;
  gap: 10px;
  margin-bottom: 24px;
}
.mobile-brand .brand-name {
  font-size: 16px;
}
.badge {
  display: inline-block;
  padding: 3px 10px;
  border-radius: 4px;
  font-size: 11px;
  letter-spacing: 0.5px;
  color: var(--text-dim);
  border: 1px solid var(--line-strong);
}
.card-head h1 {
  margin: 14px 0 6px;
  font-size: 22px;
  font-weight: 600;
  color: var(--text);
}
.subtitle {
  margin: 0;
  font-size: 13px;
  color: var(--text-dim);
}

.card :deep(.el-form-item) {
  margin-bottom: 22px;
}
.card :deep(.el-input__wrapper) {
  background: var(--bg);
  border-radius: 6px;
  transition: box-shadow 0.2s;
}
.card :deep(.el-input__wrapper.is-focus) {
  box-shadow: 0 0 0 1px var(--accent);
}
.card :deep(.el-button.el-button--primary.submit-btn) {
  width: 100%;
  height: 42px;
  margin-top: 4px;
  border: none;
  border-radius: 6px;
  font-size: 15px;
  font-weight: 600;
  color: #fff;
  background: var(--accent-strong);
}
.card :deep(.el-button.el-button--primary.submit-btn:hover),
.card :deep(.el-button.el-button--primary.submit-btn:focus-visible) {
  background: #265a8c;
}

.card-foot {
  margin-top: 22px;
  padding-top: 18px;
  border-top: 1px solid var(--line);
  text-align: center;
  font-size: 13px;
}
.card-foot :deep(a) {
  color: var(--text-dim);
  text-decoration: none;
  transition: color 0.15s;
}
.card-foot :deep(a:hover),
.card-foot :deep(a:focus-visible) {
  color: var(--accent);
}
.copyright {
  margin: 20px 0 0;
  font-size: 12px;
  color: var(--text-dim);
}

@media (max-width: 900px) {
  .login-page {
    grid-template-columns: 1fr;
  }
  .showcase {
    display: none;
  }
  .mobile-brand {
    display: flex;
  }
}
@media (max-width: 420px) {
  .card {
    padding: 32px 22px 22px;
  }
}
</style>
