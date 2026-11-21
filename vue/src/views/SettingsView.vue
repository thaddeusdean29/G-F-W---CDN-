<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { deleteCfCredentials, getCfCredentials, saveCfCredentials, testCfCredentials } from '@/api/cf'
import { pushDefense } from '@/api/security'
import type { CfCredentials, CfCredentialsInput } from '@/api/types'
import { errMessage, formatTime, pushFailures } from '@/utils/format'

const cf = ref<CfCredentials | null>(null)
const loading = ref(false)
const saving = ref(false)
const testing = ref(false)
const removing = ref(false)
const pushing = ref(false)
const form = reactive({ api_token: '', zone_id: '', base_domain: '', enabled: true })

function fill(c: CfCredentials) {
  cf.value = c
  form.api_token = ''
  form.zone_id = c.zone_id
  form.base_domain = c.base_domain
  form.enabled = c.configured ? c.enabled : true
}

async function load() {
  loading.value = true
  try {
    fill(await getCfCredentials())
  } catch (e) {
    ElMessage.error(errMessage(e, '加载 Cloudflare 配置失败'))
  } finally {
    loading.value = false
  }
}

async function save() {
  const input: CfCredentialsInput = {
    zone_id: form.zone_id.trim(),
    base_domain: form.base_domain.trim(),
    enabled: form.enabled,
  }
  // 留空 = 保留已保存的 token，不传该字段
  const token = form.api_token.trim()
  if (token) input.api_token = token
  saving.value = true
  try {
    fill(await saveCfCredentials(input))
    ElMessage.success('Cloudflare 配置已保存并验证通过')
  } catch (e) {
    ElMessage.error(errMessage(e, '保存失败'))
  } finally {
    saving.value = false
  }
}

async function test() {
  testing.value = true
  try {
    const r = await testCfCredentials()
    if (r.ok) ElMessage.success('连接正常，token 可以管理该 Zone')
    else ElMessage.error(`测试失败：${r.error || '未知错误'}`)
    await load()
  } catch (e) {
    ElMessage.error(errMessage(e, '测试失败'))
  } finally {
    testing.value = false
  }
}

async function remove() {
  try {
    await ElMessageBox.confirm(
      '删除后本代理的域名将无法自动创建 / 切换 DNS 记录（已有记录不会被删除）。确定删除？',
      '删除 Cloudflare 配置',
      { type: 'warning', confirmButtonText: '删除', cancelButtonText: '取消' },
    )
  } catch {
    return
  }
  removing.value = true
  try {
    await deleteCfCredentials()
    ElMessage.success('已删除')
    await load()
  } catch (e) {
    ElMessage.error(errMessage(e, '删除失败'))
  } finally {
    removing.value = false
  }
}

async function repush() {
  pushing.value = true
  try {
    const r = await pushDefense()
    const fails: string[] = []
    for (const [kind, res] of Object.entries(r.push)) {
      for (const f of pushFailures(res)) fails.push(`${kind} ${f}`)
    }
    if (!r.nodes) ElMessage.info('本代理还没有节点')
    else if (fails.length) ElMessage.warning(`已下发到 ${r.nodes} 个节点，部分失败：${fails.join('；')}`)
    else ElMessage.success(`防御配置已重新下发到 ${r.nodes} 个节点`)
  } catch (e) {
    ElMessage.error(errMessage(e, '下发失败'))
  } finally {
    pushing.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="page">
    <div class="page-header">
      <div>
        <h1>设置</h1>
        <p class="sub">本代理专属配置，其他代理与平台管理员均不可见</p>
      </div>
    </div>

    <div class="panel" v-loading="loading">
      <div class="panel-title">
        <span>Cloudflare 设置</span>
        <span>
          <el-tag v-if="!cf?.configured" type="info" size="small">未配置</el-tag>
          <el-tag v-else-if="cf.last_error" type="danger" size="small">异常</el-tag>
          <el-tag v-else-if="!cf.enabled" type="warning" size="small">已停用</el-tag>
          <el-tag v-else type="success" size="small">正常</el-tag>
        </span>
      </div>
      <el-alert
        type="info"
        :closable="false"
        show-icon
        title="每个代理单独保存一份 Cloudflare 账号密钥，用于给本代理的域名自动创建 CNAME 和故障切换。token 加密存储，保存后不会再显示明文。"
      />
      <el-form label-width="130px" class="cf-form" @submit.prevent="save">
        <el-form-item label="API Token" required>
          <el-input
            v-model="form.api_token"
            type="password"
            show-password
            autocomplete="new-password"
            class="mono"
            :placeholder="cf?.api_token_set ? `已保存（${cf.api_token_hint || '****'}），留空则不修改` : 'Cloudflare API Token'"
          />
          <div class="hint">需要该 Zone 的 DNS:Edit 权限（Zone → DNS → Edit）。域名的「申请 Let's Encrypt 证书」也复用这份凭证：用它写校验用的 TXT 记录。</div>
        </el-form-item>
        <el-form-item label="Zone ID" required>
          <el-input v-model="form.zone_id" class="mono" placeholder="32 位 Zone ID" />
        </el-form-item>
        <el-form-item label="基础域名" required>
          <el-input v-model="form.base_domain" class="mono" placeholder="cdn.example.com" />
          <div class="hint">CNAME 目标会建在这个域名下</div>
        </el-form-item>
        <el-form-item label="启用">
          <el-switch v-model="form.enabled" />
        </el-form-item>
        <el-form-item v-if="cf?.configured" label="状态">
          <div class="status">
            <div>最近验证：{{ formatTime(cf.verified_at) }}</div>
            <div v-if="cf.updated_at" class="dim">更新于：{{ formatTime(cf.updated_at) }}</div>
            <div v-if="cf.last_error" class="err">{{ cf.last_error }}</div>
          </div>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" native-type="submit" :loading="saving">保存并验证</el-button>
          <el-button :disabled="!cf?.configured" :loading="testing" @click="test">测试连接</el-button>
          <el-button type="danger" plain :disabled="!cf?.configured" :loading="removing" @click="remove">删除</el-button>
        </el-form-item>
      </el-form>
    </div>

    <div class="panel">
      <div class="panel-title"><span>防御配置下发</span></div>
      <p class="dim desc">
        把本代理保存的 CC / XDP / 封禁阶梯配置重新推送到自己的全部节点。节点重装或离线恢复后会自动补齐，一般无需手动操作。
      </p>
      <el-button :loading="pushing" @click="repush">重新下发防御配置</el-button>
    </div>
  </div>
</template>

<style scoped>
.cf-form {
  max-width: 640px;
  margin-top: 12px;
}
.hint {
  width: 100%;
  font-size: 12px;
  color: var(--text-dim);
}
.status {
  line-height: 1.7;
  font-size: 13px;
}
.err {
  color: var(--danger);
}
.desc {
  font-size: 13px;
  margin: 0 0 12px;
}
</style>
