import { tenantApi, pollJob } from './client'
import type { Job, Node, NodeCreateInput, NodeDeployInput, NodePatchInput, Paginated } from './types'

export interface NodeListParams {
  cluster_id?: string
  online?: boolean
}

export async function listNodes(params: NodeListParams = {}): Promise<Paginated<Node>> {
  const { data } = await tenantApi.get<Paginated<Node>>('/nodes', { params })
  return data
}

export async function getNode(id: string): Promise<Node> {
  const { data } = await tenantApi.get<Node>(`/nodes/${id}`)
  return data
}

// 手动添加已经装好的边缘节点。批量上线用 deployNode。
export async function createNode(input: NodeCreateInput): Promise<Node> {
  const { data } = await tenantApi.post<Node>('/nodes', input)
  return data
}

export async function deployNode(input: NodeDeployInput): Promise<Job> {
  const { data } = await tenantApi.post<{ job: Job }>('/nodes/deploy', input)
  return data.job
}

export async function deployNodeAndWait(input: NodeDeployInput): Promise<Job> {
  const job = await deployNode(input)
  return pollJob(tenantApi, job.id, { timeoutMs: 15 * 60 * 1000 })
}

export async function patchNode(
  id: string,
  patch: NodePatchInput,
  version?: number,
): Promise<Node> {
  const { data } = await tenantApi.patch<Node>(`/nodes/${id}`, patch, {
    headers: version != null ? { 'If-Match': String(version) } : undefined,
  })
  return data
}

export async function deleteNode(id: string): Promise<void> {
  await tenantApi.delete(`/nodes/${id}`)
}

export async function installXdp(id: string): Promise<Job> {
  const { data } = await tenantApi.post<{ job: Job }>(`/nodes/${id}/install-xdp`)
  return data.job
}

export async function onboardNode(id: string): Promise<Job> {
  const { data } = await tenantApi.post<{ job: Job }>(`/nodes/${id}/onboard`)
  return data.job
}

export async function getEdgeRegisterInfo() {
  const { data } = await tenantApi.get<{
    secret_set: boolean
    secret_hint: string
    install_command: string
  }>('/edge-register')
  return data
}

export async function rotateEdgeRegisterSecret() {
  const { data } = await tenantApi.post<{ secret: string; install_command: string }>(
    '/edge-register/rotate',
  )
  return data
}
