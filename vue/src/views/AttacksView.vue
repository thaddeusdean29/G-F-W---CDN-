<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import { blockIP, getAttacks, unblockIP } from '@/api/security'
import type { AttackIP, Attacks } from '@/api/types'
import { errMessage, formatNumber, formatTime, nodeErrorsText, pushFailures } from '@/utils/format'

const data = ref<Attacks | null>(null)
const loading = ref(false)
const q = ref('')
const busy = ref<Record<string, boolean>>({})

async function load() {
  loading.value = true
  try {
    data.value = await getAttacks()
  } catch (e) {
    ElMessage.error(errMessage(e, '加载攻击列表失败'))
  } finally {
    loading.value = false
  }
}
onMounted(load)

// 按域名被攻击次数降序（服务端已排序，这里再兜底一次，同次数按域名字母序保持稳定）。
const domains = computed(() => {
  const kw = q.value.trim().toLowerCase()
  return [...(data.value?.domains ?? [])]
    .filter((d) => !kw || d.domain.toLowerCase().includes(kw) || d.ips.some((i) => i.ip.includes(kw)))
    .sort((a, b) => b.attacks - a.attacks || a.domain.localeCompare(b.domain))
})
const errors = computed(() => nodeErrorsText(data.value?.errors))

function reportPush(push: Record<string, string>, okMsg: string) {
  const fails = pushFailures(push)
  if (fails.length) ElMessage.warning(`${okMsg}，但部分节点失败：${fails.join('；')}`)
  else ElMessage.success(okMsg)
}

async function unblock(ip: AttackIP) {
  busy.value[ip.ip] = true
  try {
    const res = await unblockIP(ip.ip, 'all')
    reportPush(res.push, `已解封 ${ip.ip}`)
    await load()
  } catch (e) {
    ElMessage.error(errMessage(e, '解封失败'))
  } finally {
    busy.value[ip.ip] = false
  }
}

async function block(ip: AttackIP) {
  try {
    await ElMessageBox.confirm(`在本代理全部节点封禁 ${ip.ip} 60 分钟（WAF + XDP）？`, '封禁 IP', {
      type: 'warning',
      confirmButtonText: '封禁',
      cancelButtonText: '取消',
    })
  } catch {
    return
  }
  busy.value[ip.ip] = true
  try {
    const res = await blockIP(ip.ip, 'all', 60)
    reportPush(res.push, `已封禁 ${ip.ip}`)
    await load()
  } catch (e) {
    ElMessage.error(errMessage(e, '封禁失败'))
  } finally {
    busy.value[ip.ip] = false
  }
}
</script>

<template>
  <div class="page">
    <div class="page-header">
      <div>
        <h1>攻击列表</h1>
        <p class="sub">按域名被攻击次数排序 · 仅含本代理自己的域名与节点</p>
      </div>
      <div class="actions">
        <el-input v-model="q" placeholder="搜索域名 / IP" clearable style="width: 220px" />
        <el-button :loading="loading" @click="load">刷新</el-button>
      </div>
    </div>

    <el-alert v-if="errors" type="warning" :closable="false" show-icon :title="`部分节点未返回数据：${errors}`" />

    <div class="stat-grid">
      <div class="stat warn">
        <div class="label">被攻击域名</div>
        <div class="value">{{ formatNumber(data?.summary.attacked_domains) }}</div>
      </div>
      <div class="stat danger">
        <div class="label">CC 封禁 IP</div>
        <div class="value">{{ formatNumber(data?.summary.cc_blocked) }}</div>
      </div>
      <div class="stat danger">
        <div class="label">WAF 封禁 IP</div>
        <div class="value">{{ formatNumber(data?.summary.waf_banned) }}</div>
      </div>
      <div class="stat danger">
        <div class="label">XDP 封禁 IP</div>
        <div class="value">{{ formatNumber(data?.summary.xdp_blocked) }}</div>
      </div>
    </div>

    <div class="panel">
      <el-table v-loading="loading" :data="domains" row-key="domain" empty-text="暂无攻击记录">
        <el-table-column type="expand">
          <template #default="{ row }">
            <div class="ips">
              <el-table :data="row.ips" size="small" empty-text="无 IP 明细">
                <el-table-column label="IP" min-width="150">
                  <template #default="{ row: ip }"><span class="mono">{{ ip.ip }}</span></template>
                </el-table-column>
                <el-table-column label="规则" prop="rule" min-width="120" show-overflow-tooltip />
                <el-table-column label="路径" prop="path" min-width="160" show-overflow-tooltip />
                <el-table-column label="违规次数" width="90" align="right">
                  <template #default="{ row: ip }">{{ formatNumber(ip.violations) }}</template>
                </el-table-column>
                <el-table-column label="RPM" width="80" align="right">
                  <template #default="{ row: ip }">{{ formatNumber(ip.requests_per_minute) }}</template>
                </el-table-column>
                <el-table-column label="状态" width="170">
                  <template #default="{ row: ip }">
                    <el-tag v-if="ip.blocked" type="danger" size="small" effect="dark">已封禁</el-tag>
                    <el-tag v-else type="info" size="small">观察中</el-tag>
                    <div v-if="ip.blocked && ip.blocked_until" class="dim small">
                      至 {{ formatTime(ip.blocked_until) }}
                    </div>
                  </template>
                </el-table-column>
                <el-table-column label="节点" min-width="120" show-overflow-tooltip>
                  <template #default="{ row: ip }">{{ ip.nodes.join(', ') }}</template>
                </el-table-column>
                <el-table-column label="操作" width="90" fixed="right">
                  <template #default="{ row: ip }">
                    <el-button
                      v-if="ip.blocked"
                      link
                      type="primary"
                      :loading="busy[ip.ip]"
                      @click="unblock(ip)"
                    >
                      解封
                    </el-button>
                    <el-button v-else link type="danger" :loading="busy[ip.ip]" @click="block(ip)">
                      封禁
                    </el-button>
                  </template>
                </el-table-column>
              </el-table>
            </div>
          </template>
        </el-table-column>
        <el-table-column type="index" width="50" />
        <el-table-column label="域名" prop="domain" min-width="200" />
        <el-table-column label="被攻击次数" width="130" align="right">
          <template #default="{ row }">
            <span class="hot mono">{{ formatNumber(row.attacks) }}</span>
          </template>
        </el-table-column>
        <el-table-column label="封禁 IP" width="100" align="right">
          <template #default="{ row }">{{ formatNumber(row.blocked_ips) }}</template>
        </el-table-column>
        <el-table-column label="攻击 IP 数" width="110" align="right">
          <template #default="{ row }">{{ formatNumber(row.ips.length) }}</template>
        </el-table-column>
        <el-table-column label="最近攻击" width="180">
          <template #default="{ row }">{{ formatTime(row.last_attack) }}</template>
        </el-table-column>
      </el-table>
    </div>
  </div>
</template>

<style scoped>
.ips {
  padding: 4px 12px 8px 48px;
}
.hot {
  color: var(--danger);
  font-weight: 600;
}
.small {
  font-size: 11px;
}
</style>
