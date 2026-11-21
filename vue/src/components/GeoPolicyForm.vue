<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { InfoFilled } from '@element-plus/icons-vue'
import { countryLabel, sortByCountry, toCodes } from '@/utils/countries'
import { geoActions, geoModes, geoPolicyIssues, splitNets } from '@/utils/geo'
import type { GeoPolicy } from '@/api/types'

// 一条区域规则的编辑区，域名级（七层）和整节点级（四层丢包）共用这一份。
//
// 两个作用范围的差别只有"四层只能 deny、必须有例外"，所以用 denyOnly 一个开关区分，
// 不复制第二个组件：复制出来的第二份会和第一份在不同步的那天给出不同的判决文案。
//
// 直接改父组件传进来的 reactive 对象（和 AdminSettingsView 一样的写法）：
// 这里不保存、不提交，保存归页面管，控件也不该知道自己存到哪儿。

const props = defineProps<{
  policy: GeoPolicy
  // 可选国家码。父组件负责把它收窄成"这个用户真能选的那些"：
  // 租户传平台范围∩库覆盖，管理员传库覆盖（管理员自己不受范围限制）。
  codes: string[]
  // 整节点（四层）为 true：allow 语义在四层做不到，页面直接把选项标成不可选，
  // 而不是让人提交后被后端拒。
  denyOnly?: boolean
  // 管理员划了范围、但库里没有网段的那些码。选了也拦不到任何地址，要当场说清楚。
  unavailable?: string[]
  // 别处已经在用的国家，只用于提示，不限制选择。
  used?: string[]
  busy?: boolean
  // 作用范围说明，显示在标题下。
  hint?: string
  // 例外清单的说明文案：整节点策略那条要求更硬，得有对应的说法。
  exceptionsHint?: string
}>()

const issues = computed(() => geoPolicyIssues(props.policy, { denyOnly: !!props.denyOnly }))
const options = computed(() => sortByCountry(props.codes))
const usedSet = computed(() => new Set(props.used ?? []))

// 国家多选直接绑数组会丢归一（小写、重复、顺序），后端也会再做一遍，
// 但页面先归一次才能让"改了一个国家"和"什么都没改"区分开。
const picked = computed({
  get: () => props.policy.countries,
  set: (v) => {
    props.policy.countries = toCodes(v as string[])
  },
})

// 例外按行编辑：库里存的是归一后的 CIDR，回填时原样显示，
// 提交前才拆开——输入到一半的 "10." 不该当场报错。
const netsText = ref(props.policy.exceptions.join('\n'))
// 只在值真的变了时回写文本框：commitNets 之后后端/父组件可能把 "1.2.3.4" 归一成
// "1.2.3.4/32"，那种情况下应该让页面显示将要存下去的那一串。
watch(
  () => props.policy.exceptions.join('\n'),
  (v) => {
    if (v !== netsText.value) netsText.value = v
  },
)
function commitNets() {
  props.policy.exceptions = splitNets(netsText.value)
}

const modeHint = computed(() => geoModes.find((m) => m.value === props.policy.mode)?.hint ?? '')
const actionHint = computed(() => geoActions.find((a) => a.value === props.policy.action)?.hint ?? '')
</script>

<template>
  <div class="geo-form">
    <div class="head">
      <el-switch v-model="policy.enabled" :disabled="busy" />
      <div class="head-text">
        <div class="title">启用区域规则</div>
        <div v-if="hint" class="hint">{{ hint }}</div>
      </div>
    </div>

    <div v-if="policy.enabled" class="body">
      <div class="field">
        <div class="label">动作</div>
        <el-radio-group v-model="policy.action" :disabled="busy" size="small">
          <el-radio-button v-for="a in geoActions" :key="a.value" :value="a.value" :disabled="denyOnly && a.value === 'allow'">
            {{ a.label }}
          </el-radio-button>
        </el-radio-group>
        <div class="hint">{{ actionHint }}</div>
        <div v-if="denyOnly" class="hint">
          整节点策略只能封禁所列国家：四层看不到 HTTP host，也分不清「归属未知」和「不在允许清单」，
          配成只放行会把未知归属的流量一起丢掉。要按国家只放行，请用域名的七层规则。
        </div>
      </div>

      <div class="field">
        <div class="label">执行模式</div>
        <el-radio-group v-model="policy.mode" :disabled="busy" size="small">
          <el-radio-button v-for="m in geoModes" :key="m.value" :value="m.value">{{ m.label }}</el-radio-button>
        </el-radio-group>
        <div class="hint">{{ modeHint }}</div>
        <div v-if="policy.mode === 'observe' && denyOnly" class="hint">
          观察模式不会装四层丢包表：只记账、照常放行。开拦之前先看这一档的读数。
        </div>
      </div>

      <div class="field">
        <div class="label">
          国家
          <span class="count">{{ policy.countries.length }} / {{ options.length }}</span>
        </div>
        <el-select
          v-model="picked"
          multiple
          filterable
          :disabled="busy"
          collapse-tags
          collapse-tags-tooltip
          :max-collapse-tags="8"
          placeholder="按中文名或两位码搜索，可多选"
          class="codes"
        >
          <el-option v-for="c in options" :key="c" :label="countryLabel(c)" :value="c">
            <span class="opt">
              {{ countryLabel(c) }}
              <span v-if="usedSet.has(c)" class="tag-used">本代理已在用</span>
            </span>
          </el-option>
        </el-select>
        <div v-if="policy.countries.length" class="chips">
          <el-tag v-for="c in policy.countries" :key="c" size="small" type="info">{{ countryLabel(c) }}</el-tag>
        </div>
        <div v-if="used?.length" class="hint">
          标了「本代理已在用」的国家，本代理已经有启用中的域名在封它（可能就是这个域名自己）：
          前缀表是一台节点上共用的一份，不会因为这条规则单独缩小范围——摘掉这里的某个国家，只会让这条规则不再用它。
        </div>
        <div v-if="unavailable?.length" class="hint warn">
          这些国家在平台范围里，但国家级地理库没有它们的网段，选了也拦不到任何地址：
          {{ unavailable.map(countryLabel).join('、') }}
        </div>
      </div>

      <div class="field">
        <div class="label">
          例外 IP / CIDR
          <span class="count">{{ policy.exceptions.length }}</span>
        </div>
        <el-input
          v-model="netsText"
          type="textarea"
          :rows="3"
          :disabled="busy"
          resize="none"
          placeholder="每行一条，例如&#10;203.0.113.9&#10;198.51.100.0/24"
          @change="commitNets"
          @blur="commitNets"
        />
        <div class="hint">
          {{
            exceptionsHint ??
            '命中例外的地址永远放行，不看国家。裸 IP 会自动补成 /32（IPv6 补 /128）。建议至少放上自己的办公出口 IP，调试时不会被自己的规则挡在外面。'
          }}
        </div>
      </div>

      <el-alert v-if="issues.length" type="warning" :closable="false" class="issues">
        <template #title>
          <span class="issue-title"><el-icon><InfoFilled /></el-icon> 还差这些才能保存</span>
        </template>
        <ul class="issue-list">
          <li v-for="m in issues" :key="m">{{ m }}</li>
        </ul>
      </el-alert>
    </div>
    <div v-else class="hint off">
      规则关着：域名照常放行所有来源。这个状态下保存不会改动节点上已有的表，也不会新增要编译的国家。
    </div>
  </div>
</template>

<style scoped>
.geo-form {
  width: 100%;
}
.head {
  display: flex;
  align-items: flex-start;
  gap: 10px;
  margin-bottom: 12px;
}
.head-text {
  padding-top: 1px;
}
.title {
  font-size: 13px;
  font-weight: 600;
}
.body {
  display: flex;
  flex-direction: column;
  gap: 14px;
}
.field {
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.label {
  display: flex;
  align-items: center;
  gap: 8px;
  font-size: 12px;
  font-weight: 600;
  color: var(--text-dim, #909399);
}
.count {
  font-weight: 400;
  color: var(--text-dim, #909399);
}
.hint {
  font-size: 12px;
  line-height: 1.6;
  color: var(--text-dim, #909399);
}
.hint.warn {
  color: var(--el-color-warning, #e6a23c);
}
.hint.off {
  margin-top: 2px;
}
.codes {
  width: 100%;
}
.chips {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
}
.opt {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
}
.tag-used {
  font-size: 11px;
  color: var(--text-dim, #909399);
}
.issues {
  margin-top: 2px;
}
.issue-title {
  display: inline-flex;
  align-items: center;
  gap: 6px;
}
.issue-list {
  margin: 6px 0 0;
  padding-left: 20px;
  font-size: 12px;
  line-height: 1.7;
}
</style>
