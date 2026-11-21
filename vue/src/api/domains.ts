import { tenantApi, pollJob } from './client'
import type {
  Certificate,
  Domain,
  DomainCreateInput,
  DomainPatchInput,
  Job,
  Paginated,
} from './types'

export interface DomainListParams {
  cluster_id?: string
  tag?: string
  enabled?: boolean
  q?: string
  page?: number
  page_size?: number
}

export async function listDomains(params: DomainListParams = {}): Promise<Paginated<Domain>> {
  const { data } = await tenantApi.get<Paginated<Domain>>('/domains', { params })
  return data
}

export async function getDomain(id: string): Promise<Domain> {
  const { data } = await tenantApi.get<Domain>(`/domains/${id}`)
  return data
}

export async function createDomain(input: DomainCreateInput): Promise<Domain> {
  const { data } = await tenantApi.post<Domain>('/domains', input)
  return data
}

// version 用于 If-Match 乐观锁；不传时不做冲突检查（API-v2.md 0.4）。
export async function patchDomain(
  id: string,
  patch: DomainPatchInput,
  version?: number,
): Promise<Domain> {
  const { data } = await tenantApi.patch<Domain>(`/domains/${id}`, patch, {
    headers: version != null ? { 'If-Match': String(version) } : undefined,
  })
  return data
}

export async function deleteDomain(id: string): Promise<void> {
  await tenantApi.delete(`/domains/${id}`)
}

export async function switchToDefense(id: string): Promise<Domain> {
  const { data } = await tenantApi.post<Domain>(`/domains/${id}/switch-to-defense`)
  return data
}

export async function switchToCluster(id: string): Promise<Domain> {
  const { data } = await tenantApi.post<Domain>(`/domains/${id}/switch-to-cluster`)
  return data
}

export async function resyncDomain(id: string): Promise<Job> {
  const { data } = await tenantApi.post<{ job: Job }>(`/domains/${id}/resync`)
  return data.job
}

export async function resyncDomainAndWait(id: string): Promise<Job> {
  const job = await resyncDomain(id)
  return pollJob(tenantApi, job.id)
}

export async function purgeDomain(id: string, paths: string[] = ['/']): Promise<Job> {
  const { data } = await tenantApi.post<{ job: Job }>(`/domains/${id}/purge`, { paths })
  return data.job
}

// 自助申请 Let's Encrypt 证书：dns-01 校验，用本代理在「设置」里保存的 Cloudflare 凭证
// 写一条 TXT 记录。异步 Job（要等 CA 查 DNS），前端拿 job 后轮询 /jobs/:id。
export async function requestAcmeCertificate(id: string): Promise<Job> {
  const { data } = await tenantApi.post<{ job: Job }>(`/domains/${id}/certificate/acme`)
  return data.job
}

// 证书：私钥只上传不回显，GET 只有元数据
export async function getCertificate(id: string): Promise<Certificate | null> {
  const { data } = await tenantApi.get<{ certificate: Certificate | null }>(`/domains/${id}/certificate`)
  return data.certificate
}

export async function uploadCertificate(
  id: string,
  input: { cert_pem: string; key_pem: string; force_https?: boolean },
): Promise<{ domain: Domain; certificate: Certificate }> {
  const { data } = await tenantApi.post<{ domain: Domain; certificate: Certificate }>(
    `/domains/${id}/certificate`,
    input,
  )
  return data
}
