import { adminApi } from './client'
import type {
  GeoAdminNodesResponse,
  GeoAdminPushResponse,
  GeoAdminResponse,
  GeoAdminSaveResponse,
  GeoScope,
} from './types'

// 区域封禁的平台侧接口：能力总闸、租可选国家、整节点的四层丢包策略。
//
// 只有平台管理员能改这三样，代理侧只能读（见 api/security.ts 的 getGeoOptions）。
// 保存会顺带把编译好的前缀表下发全网，返回值里的 push 是逐节点结果——
// 接口 200 只说明主控存下了，不说明节点装上了。

// GET /admin/geo：当前范围 + 这张表长什么样（plan）+ 面板有没有库（geo_db）+ 全网读数汇总。
export async function getGeoScope(): Promise<GeoAdminResponse> {
  return (await adminApi.get<GeoAdminResponse>('/geo')).data
}

// PUT /admin/geo：保存并下发。后端只认 enabled/selectable/node 三个字段，
// 多传会被当成未知字段拒掉，所以这里按整个 Scope 提交。
export async function putGeoScope(scope: GeoScope): Promise<GeoAdminSaveResponse> {
  return (await adminApi.put<GeoAdminSaveResponse>('/geo', scope)).data
}

// 不改任何配置，只把当前应该生效的那张表重推一遍（节点当时不在线、后来装好了用它）。
export async function pushGeoScope(): Promise<GeoAdminPushResponse> {
  return (await adminApi.post<GeoAdminPushResponse>('/geo/push', {})).data
}

// GET /admin/geo/nodes：逐节点报"实跑的表"与"面板要它跑的表"是否同一张。
export async function listGeoNodes(): Promise<GeoAdminNodesResponse> {
  return (await adminApi.get<GeoAdminNodesResponse>('/geo/nodes')).data
}
