import { tenantApi } from './client'
import type { Cluster, ClusterCreateInput, ClusterPatchInput, Node, Paginated } from './types'

export async function listClusters(): Promise<Paginated<Cluster>> {
  const { data } = await tenantApi.get<Paginated<Cluster>>('/clusters')
  return data
}

export async function getCluster(id: string): Promise<Cluster> {
  const { data } = await tenantApi.get<Cluster>(`/clusters/${id}`)
  return data
}

export async function createCluster(input: ClusterCreateInput): Promise<Cluster> {
  const { data } = await tenantApi.post<Cluster>('/clusters', input)
  return data
}

export async function patchCluster(
  id: string,
  patch: ClusterPatchInput,
  version?: number,
): Promise<Cluster> {
  const { data } = await tenantApi.patch<Cluster>(`/clusters/${id}`, patch, {
    headers: version != null ? { 'If-Match': String(version) } : undefined,
  })
  return data
}

export async function deleteCluster(id: string): Promise<void> {
  await tenantApi.delete(`/clusters/${id}`)
}

export async function listClusterNodes(id: string): Promise<Paginated<Node>> {
  const { data } = await tenantApi.get<Paginated<Node>>(`/clusters/${id}/nodes`)
  return data
}

export async function triggerFailover(
  id: string,
  action: 'trigger' | 'cancel',
): Promise<Cluster> {
  const { data } = await tenantApi.post<Cluster>(`/clusters/${id}/failover`, { action })
  return data
}
