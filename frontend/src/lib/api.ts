import axios from 'axios'
import type {
  ApiResponse,
  AttackPathDetail,
  AttackPathFilters,
  AttackPathStats,
  ComplianceSummary,
  FindingDetail,
  FindingsFilter,
  FindingsStats,
  PagedAttackPaths,
  PagedFindings,
  ResourceSummary,
  ResourceDetail,
  InventoryStats,
  InventoryFilters,
  ProviderConfig,
  ProviderRegisterRequest,
  ProviderRegisterResponse,
  ProviderUpdateRequest,
  DiscoverRequest,
  DiscoverResponse,
  ScanJob,
  ScanTriggerRequest,
  ScanTriggerResponse,
} from './types'

export const apiClient = axios.create({
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

  get: (providerId: string) =>
    apiClient.get<ApiResponse<ProviderConfig>>(`/api/v1/providers/${providerId}`),

  register: (data: ProviderRegisterRequest) =>
    apiClient.post<ApiResponse<ProviderRegisterResponse>>('/api/v1/providers', data),

  update: (providerId: string, data: ProviderUpdateRequest) =>
    apiClient.patch<ApiResponse<ProviderConfig>>(`/api/v1/providers/${providerId}`, data),

  triggerDiscovery: (providerId: string, body?: DiscoverRequest) =>
    apiClient.post<ApiResponse<DiscoverResponse>>(
      `/api/v1/providers/${providerId}/discover`,
      body ?? null,
    ),

  delete: (providerId: string) =>
    apiClient.delete<ApiResponse<{ deleted: boolean }>>(`/api/v1/providers/${providerId}`),
}

export const findingsApi = {
  stats: () =>
    apiClient.get<ApiResponse<FindingsStats>>('/api/v1/findings/stats'),

  list: (filters: FindingsFilter) =>
    apiClient.get<ApiResponse<PagedFindings>>('/api/v1/findings', {
      params: {
        provider: filters.provider || undefined,
        severity: filters.severity || undefined,
        status: filters.status || undefined,
        framework: filters.framework || undefined,
        region: filters.region || undefined,
        account_id: filters.account_id || undefined,
        resource_type: filters.resource_type || undefined,
        source: filters.source || undefined,
        q: filters.q || undefined,
        limit: filters.limit,
        cursor: filters.cursor || undefined,
      },
    }),

  get: (findingKey: string) =>
    apiClient.get<ApiResponse<FindingDetail>>(`/api/v1/findings/${findingKey}`),

  mute: (findingKey: string, reason: string) =>
    apiClient.patch<ApiResponse<FindingDetail>>(`/api/v1/findings/${findingKey}`, {
      status: 'MUTED',
      reason,
    }),

  accept: (findingKey: string, reason?: string) =>
    apiClient.patch<ApiResponse<FindingDetail>>(`/api/v1/findings/${findingKey}`, {
      status: 'ACCEPTED',
      reason,
    }),
}

export const scansApi = {
  trigger: (body: ScanTriggerRequest) =>
    apiClient.post<ApiResponse<ScanTriggerResponse>>('/api/v1/scans', body),

  get: (jobId: string) =>
    apiClient.get<ApiResponse<ScanJob>>(`/api/v1/scans/${jobId}`),

  list: () =>
    apiClient.get<ApiResponse<ScanJob[]>>('/api/v1/scans'),
}

export const complianceApi = {
  summary: (tenantId?: string) =>
    apiClient.get<ApiResponse<ComplianceSummary>>('/api/v1/compliance/summary', {
      params: tenantId ? { tenant_id: tenantId } : undefined,
    }),
}

export const attackPathsApi = {
  stats: () =>
    apiClient.get<ApiResponse<AttackPathStats>>('/api/v1/attack-paths/stats'),

  list: (filters: AttackPathFilters) =>
    apiClient.get<ApiResponse<PagedAttackPaths>>('/api/v1/attack-paths', {
      params: {
        severity: filters.severity || undefined,
        is_toxic_combination: filters.is_toxic_combination ?? undefined,
        provider: filters.provider || undefined,
        limit: filters.limit,
        cursor: filters.cursor || undefined,
      },
    }),

  get: (pathKey: string) =>
    apiClient.get<ApiResponse<AttackPathDetail>>(`/api/v1/attack-paths/${pathKey}`),
}
