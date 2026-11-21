<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { ElMessage, type FormInstance, type FormRules } from 'element-plus'
import { User, Lock } from '@element-plus/icons-vue'
import { useAdminStore } from '@/stores/admin'
import LoginShell from '@/components/LoginShell.vue'
import { ApiClientError } from '@/api/client'

const formRef = ref<FormInstance>()
const form = reactive({
  username: '',
  password: '',
})
const rules: FormRules = {
  username: [{ required: true, message: '请输入管理员账号', trigger: 'blur' }],
  password: [{ required: true, message: '请输入密码', trigger: 'blur' }],
}

const loading = ref(false)
const admin = useAdminStore()
const router = useRouter()
const route = useRoute()

async function handleSubmit() {
  const valid = await formRef.value?.validate().catch(() => false)
  if (!valid) return

  loading.value = true
  try {
    await admin.login(form.username, form.password)
    const redirect = (route.query.redirect as string) || '/admin'
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
  <LoginShell badge="PLATFORM ADMIN" title="平台管理后台" subtitle="使用安装向导里设置的管理员账号登录">
    <el-form
      ref="formRef"
      :model="form"
      :rules="rules"
      size="large"
      @submit.prevent="handleSubmit"
    >
      <el-form-item prop="username">
        <el-input
          v-model="form.username"
          placeholder="管理员账号"
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
      <RouterLink to="/login">← 返回代理登录</RouterLink>
    </template>
  </LoginShell>
</template>
