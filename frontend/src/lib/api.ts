import axios from 'axios'
import type {
  ApiResponse,
  ResourceSummary,
  ResourceDetail,
  InventoryStats,
  InventoryFilters,
  ProviderConfig,
  ProviderRegisterRequest,
  ProviderRegisterResponse,
} from './types'

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

  exportCsv: (params?: { provider?: string; status?: string }) =>
    apiClient.get('/api/v1/inventory/export', {
      params: { format: 'csv', ...params },
      responseType: 'blob',
    }),

  exportJson: (params?: { provider?: string; status?: string }) =>
    apiClient.get('/api/v1/inventory/export', {
      params: { format: 'json', ...params },
      responseType: 'blob',
    }),
}

export const providersApi = {
  list: () =>
    apiClient.get<ApiResponse<ProviderConfig[]>>('/api/v1/providers'),

  register: (data: ProviderRegisterRequest) =>
    apiClient.post<ApiResponse<ProviderRegisterResponse>>('/api/v1/providers', data),

  delete: (providerId: string) =>
    apiClient.delete<ApiResponse<{ deleted: boolean }>>(`/api/v1/providers/${providerId}`),
}
