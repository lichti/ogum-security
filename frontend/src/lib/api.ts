import axios from 'axios'
import type { ApiResponse, ResourceSummary, ResourceDetail, InventoryStats, InventoryFilters } from './types'

const apiClient = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000',
  headers: {
    'Content-Type': 'application/json',
  },
})

// DEV MODE: tenant injected from env var — Sprint 7 replaces with JWT extraction
apiClient.interceptors.request.use((config) => {
  const tenantId = process.env.NEXT_PUBLIC_TENANT_ID ?? 'dev-tenant'
  config.headers['X-Tenant-ID'] = tenantId
  return config
})

export const inventoryApi = {
  list: (filters: InventoryFilters) =>
    apiClient.get<ApiResponse<ResourceSummary[]>>('/api/v1/inventory', {
      params: {
        provider: filters.provider || undefined,
        resource_type: filters.resource_type || undefined,
        region: filters.region || undefined,
        search: filters.search || undefined,
        status: filters.status,
        limit: filters.limit,
        offset: filters.offset,
      },
    }),

  stats: () =>
    apiClient.get<ApiResponse<InventoryStats>>('/api/v1/inventory/stats'),

  detail: (key: string) =>
    apiClient.get<ApiResponse<ResourceDetail>>(`/api/v1/inventory/${key}`),

  triggerDiscovery: (provider: string, regions: string[]) =>
    apiClient.post('/api/v1/inventory/discover', null, {
      params: { provider, regions },
    }),
}
