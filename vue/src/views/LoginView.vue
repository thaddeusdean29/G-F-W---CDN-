<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'
import { User, Lock } from '@element-plus/icons-vue'
import { useAuthStore } from '@/stores/auth'
import LoginShell from '@/components/LoginShell.vue'
import { ApiClientError } from '@/api/client'

const formRef = ref<FormInstance>()
const form = reactive({
  email: '',
  password: '',
})
const rules: FormRules = {
  email: [{ required: true, message: '请输入邮箱', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }],
}

const loading = ref(false)
const auth = useAuthStore()
const router = useRouter()
const route = useRoute()

async function handleSubmit() {
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return

  loading.value = true
  try {
    await auth.login(form.email, form.password)
    const redirect = (route.query.redirect as string) || '/'
    router.push(redirect)
  } catch (e) {
    if (e instanceof ApiClientError) {
      ElMessage.error(e.code === 'invalid_credentials' ? '账号或密码错误' : e.message)
    } else {
      ElMessage.error('登录失败，请稍后重试')
    }
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <LoginShell badge="AGENT CONSOLE" title="登录控制台" subtitle="使用代理账号的邮箱和密码登录">
    <el-form
      ref="formRef"
      :model="form"
      :rules="rules"
      size="large"
      @submit.prevent="handleSubmit"
    >
      <el-form-item prop="email">
        <el-input
          v-model="form.email"
          placeholder="邮箱"
          :prefix-icon="User"
          autocomplete="username"
          @keyup.enter="handleSubmit"
        />
      </el-form-item>
      <el-form-item prop="password">
        <el-input
          v-model="form.password"
          type="password"
          placeholder="密码"
          :prefix-icon="Lock"
          show-password
          autocomplete="current-password"
          @keyup.enter="handleSubmit"
        />
      </el-form-item>
      <el-button type="primary" class="submit-btn" :loading="loading" @click="handleSubmit">
        {{ loading ? '登录中' : '登录' }}
      </el-button>
    </el-form>
    <template #footer>
      <RouterLink to="/admin/login">平台管理员登录 →</RouterLink>
    </template>
  </LoginShell>
</template>
