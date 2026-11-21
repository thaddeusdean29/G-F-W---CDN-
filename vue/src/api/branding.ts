import { adminApi, tenantApi } from './client'

// 登录页左侧的功能卡片；icon 是 utils/featureIcons.ts 里的名字。
export interface LoginFeature {
  icon: string
  title: string
  desc: string
}

// 平台品牌信息（平台名称等）。公开读取，管理员可修改。
export interface Branding {
  platform_name: string
  logo_text: string
  login_subtitle: string
  // 登录页大标语，用换行分成最多两行
  login_slogan: string
  login_features: LoginFeature[]
}

// 接口返回的品牌信息多一个只读的网站图标地址（未上传时为空串）。
export interface BrandingView extends Branding {
  favicon_url: string
}

export async function fetchBranding(): Promise<BrandingView> {
  const { data } = await tenantApi.get<BrandingView>('/branding')
  return data
}

export async function fetchAdminSettings(): Promise<BrandingView> {
  const { data } = await adminApi.get<BrandingView>('/settings')
  return data
}

export async function saveAdminSettings(input: Branding): Promise<BrandingView> {
  const { data } = await adminApi.put<BrandingView>('/settings', input)
  return data
}

// 请求体直接是图片字节；格式由服务端按内容判断。
export async function uploadFavicon(file: File): Promise<BrandingView> {
  const { data } = await adminApi.put<BrandingView>('/settings/favicon', file, {
    headers: { 'Content-Type': file.type || 'application/octet-stream' },
  })
  return data
}

export async function deleteFavicon(): Promise<BrandingView> {
  const { data } = await adminApi.delete<BrandingView>('/settings/favicon')
  return data
}
