import axios from 'axios'
import type {
  ApiResponse,
  AttackPathDetail,
  AttackPathFilters,
  AttackPathStats,
  AqlResult,
  CompliancePeriod,
  ComplianceControlAsset,
  ComplianceFamilySettingsUpdateRequest,
  ComplianceFamilySettingsView,
  ComplianceFrameworkDetail,
  ComplianceScoreTrendPoint,
  ComplianceSummary,
  ExposureSummary,
  FindingDetail,
  FindingsFilter,
  FindingsStats,
  IdentityPermissions,
  IdentitySummary,
  ImageSecurityStatus,
  PagedAttackPaths,
  PagedFindings,
  PagedSideScanJobs,
  ResourceSummary,
  ResourceDetail,
  ResourceNarrativeSummary,
  BlastRadiusResponse,
  ResourceComplianceResponse,
  SoftwareInventoryResponse,
  InventoryStats,
  InventoryFilters,
  ProviderConfig,
  ProviderRegisterRequest,
  ProviderRegisterResponse,
  ProviderUpdateRequest,
  DiscoverRequest,
  DiscoverResponse,
  SavedQuery,
  SavedView,
  SavedViewCreateRequest,
  SavedViewUpdateRequest,
  ShortestPathResult,
  PagedScanJobs,
  ScanJob,
  ScanJobFilter,
  ScanJobLogs,
  ScanTriggerRequest,
  ScanTriggerResponse,
  SideScanJob,
  SLASettings,
  SLASummary,
  ViewScope,
} from './types'

// FastAPI's Query(list[str]) expects repeated bare keys (?k=a&k=b), not axios's
// default bracket notation (?k[]=a&k[]=b) — a custom serializer keeps array
// filters (providers, regions, etc.) working across the whole client.
export function serializeParams(params: Record<string, unknown>): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null) continue
    if (Array.isArray(value)) {
      for (const item of value) search.append(key, String(item))
    } else {
      search.append(key, String(value))
    }
  }
  return search.toString()
}

export const apiClient = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000',
  headers: {
    'Content-Type': 'application/json',
  },
  paramsSerializer: serializeParams,
})

// DEV MODE: tenant/user injected from env vars — Epic 06 replaces with JWT extraction
apiClient.interceptors.request.use((config) => {
  const tenantId = process.env.NEXT_PUBLIC_TENANT_ID ?? 'dev-tenant'
  const userId = process.env.NEXT_PUBLIC_USER_ID ?? 'dev-user'
  config.headers['X-Tenant-ID'] = tenantId
  config.headers['X-User-Id'] = userId
  return config
})

export const inventoryApi = {
  list: (filters: InventoryFilters) =>
    apiClient.get<ApiResponse<ResourceSummary[]>>('/api/v1/inventory', {
      params: {
        provider: filters.providers.length ? filters.providers : undefined,
        resource_type: filters.resourceTypes.length ? filters.resourceTypes : undefined,
        region: filters.regions.length ? filters.regions : undefined,
        account_id: filters.accountIds.length ? filters.accountIds : undefined,
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

  summary: (key: string) =>
    apiClient.get<ApiResponse<ResourceNarrativeSummary>>(`/api/v1/inventory/${key}/summary`),

  blastRadius: (key: string) =>
    apiClient.get<ApiResponse<BlastRadiusResponse>>(`/api/v1/inventory/${key}/blast-radius`),

  software: (key: string) =>
    apiClient.get<ApiResponse<SoftwareInventoryResponse>>(`/api/v1/inventory/${key}/software`),

  compliance: (key: string, framework?: string) =>
    apiClient.get<ApiResponse<ResourceComplianceResponse>>(`/api/v1/inventory/${key}/compliance`, {
      params: framework ? { framework } : undefined,
    }),

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
        resource_id: filters.resource_id || undefined,
        check_id: filters.check_id || undefined,
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

  slaSummary: () =>
    apiClient.get<ApiResponse<SLASummary>>('/api/v1/findings/sla-summary'),

  exposurePath: (findingKey: string) =>
    apiClient.get<ApiResponse<BlastRadiusResponse>>(`/api/v1/findings/${findingKey}/exposure-path`),
}

export const settingsApi = {
  getSla: () =>
    apiClient.get<ApiResponse<SLASettings>>('/api/v1/settings/sla'),

  updateSla: (data: Partial<SLASettings>) =>
    apiClient.put<ApiResponse<SLASettings>>('/api/v1/settings/sla', data),

  listCompliance: () =>
    apiClient.get<ApiResponse<ComplianceFamilySettingsView[]>>('/api/v1/settings/compliance'),

  updateCompliance: (familyKey: string, data: ComplianceFamilySettingsUpdateRequest) =>
    apiClient.put<ApiResponse<ComplianceFamilySettingsView>>(
      `/api/v1/settings/compliance/${encodeURIComponent(familyKey)}`,
      data,
    ),
}

export const scansApi = {
  trigger: (body: ScanTriggerRequest) =>
    apiClient.post<ApiResponse<ScanTriggerResponse>>('/api/v1/scans', body),

  get: (jobId: string) =>
    apiClient.get<ApiResponse<ScanJob>>(`/api/v1/scans/${jobId}`),

  list: (filters: ScanJobFilter = {}) =>
    apiClient.get<ApiResponse<PagedScanJobs>>('/api/v1/scans', {
      params: {
        status: filters.status || undefined,
        provider_id: filters.provider_id || undefined,
        limit: filters.limit,
        cursor: filters.cursor || undefined,
      },
    }),

  logs: (jobId: string) =>
    apiClient.get<ApiResponse<ScanJobLogs>>(`/api/v1/scans/${jobId}/logs`),
}

export const complianceApi = {
  summary: (framework?: string, severity?: string[]) =>
    apiClient.get<ApiResponse<ComplianceSummary>>('/api/v1/compliance/summary', {
      params: { framework: framework || undefined, severity },
    }),

  frameworkDetail: (frameworkId: string) =>
    apiClient.get<ApiResponse<ComplianceFrameworkDetail>>(
      `/api/v1/compliance/frameworks/${encodeURIComponent(frameworkId)}`,
    ),

  trend: (frameworkId: string, period: CompliancePeriod) =>
    apiClient.get<ApiResponse<ComplianceScoreTrendPoint[]>>(
      `/api/v1/compliance/frameworks/${encodeURIComponent(frameworkId)}/trend`,
      { params: { period } },
    ),

  controlAssets: (frameworkId: string, controlId: string) =>
    apiClient.get<ApiResponse<ComplianceControlAsset[]>>(
      `/api/v1/compliance/frameworks/${encodeURIComponent(frameworkId)}/control-assets`,
      { params: { control_id: controlId } },
    ),
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
        target_asset_category: filters.target_asset_category || undefined,
        target_crown_jewel_reason: filters.target_crown_jewel_reason || undefined,
        limit: filters.limit,
        cursor: filters.cursor || undefined,
      },
    }),

  get: (pathKey: string) =>
    apiClient.get<ApiResponse<AttackPathDetail>>(`/api/v1/attack-paths/${pathKey}`),

  getMitre: (pathKey: string) =>
    apiClient.get<ApiResponse<import('./types').MitreIntelligence>>(`/api/v1/attack-paths/${pathKey}/mitre`),

  getNarrative: (pathKey: string) =>
    apiClient.get<ApiResponse<import('./types').PathNarrativeSummary>>(`/api/v1/attack-paths/${pathKey}/narrative`),
}

export const identitiesApi = {
  list: (params?: { provider?: string; only_dangerous?: boolean; limit?: number; offset?: number }) =>
    apiClient.get<ApiResponse<IdentitySummary[]>>('/api/v1/identities', { params }),

  permissions: (identityKey: string) =>
    apiClient.get<ApiResponse<IdentityPermissions>>(`/api/v1/identities/${identityKey}/permissions`),
}

export const graphApi = {
  setCrownJewel: (resourceId: string, isCrownJewel: boolean) =>
    apiClient.patch<ApiResponse<{ resource_id: string; is_crown_jewel: boolean }>>(
      `/api/v1/graph/resources/${resourceId}/crown-jewel`,
      { is_crown_jewel: isCrownJewel },
    ),

  listCrownJewels: () =>
    apiClient.get<ApiResponse<Record<string, unknown>[]>>('/api/v1/graph/crown-jewels'),

  executeAql: (query: string, bindVars?: Record<string, unknown>) =>
    apiClient.post<ApiResponse<AqlResult>>('/api/v1/graph/aql', {
      query,
      bind_vars: bindVars ?? {},
    }),

  listSavedQueries: () =>
    apiClient.get<ApiResponse<SavedQuery[]>>('/api/v1/graph/queries'),

  saveQuery: (name: string, query: string, description?: string) =>
    apiClient.post<ApiResponse<SavedQuery>>('/api/v1/graph/queries', {
      name,
      query,
      description: description ?? '',
    }),

  deleteQuery: (queryId: string) =>
    apiClient.delete<ApiResponse<{ deleted: string }>>(`/api/v1/graph/queries/${queryId}`),

  shortestPath: (fromId: string, toId: string, maxDepth?: number) =>
    apiClient.get<ApiResponse<ShortestPathResult>>(
      `/api/v1/graph/paths/${encodeURIComponent(fromId)}/${encodeURIComponent(toId)}`,
      { params: { max_depth: maxDepth } },
    ),

  exposureSummary: () =>
    apiClient.get<ApiResponse<ExposureSummary>>('/api/v1/graph/exposure'),
}

export const sideScanApi = {
  listJobs: (params?: { status?: string; job_type?: string; limit?: number; offset?: number }) =>
    apiClient.get<PagedSideScanJobs>('/api/v1/side-scans/jobs', { params }),

  getJob: (jobId: string) =>
    apiClient.get<SideScanJob>(`/api/v1/side-scans/jobs/${jobId}`),

  retryJob: (jobId: string) =>
    apiClient.post<{ job_id: string; status: string; original_job_id: string }>(
      `/api/v1/side-scans/jobs/${jobId}/retry`,
    ),

  imageSecurityStatus: (imageDigest: string) =>
    apiClient.get<ImageSecurityStatus>(`/api/v1/side-scans/images/${encodeURIComponent(imageDigest)}/security`),

  triggerScan: (resourceKey: string) =>
    apiClient.post<{ job_id: string; status: string; resource_key: string }>('/api/v1/side-scans/trigger', {
      resource_key: resourceKey,
    }),
}

export const viewsApi = {
  list: (scope?: ViewScope) =>
    apiClient.get<ApiResponse<SavedView[]>>('/api/v1/views', { params: scope ? { scope } : undefined }),

  create: (data: SavedViewCreateRequest) =>
    apiClient.post<ApiResponse<SavedView>>('/api/v1/views', data),

  update: (viewKey: string, data: SavedViewUpdateRequest) =>
    apiClient.patch<ApiResponse<SavedView>>(`/api/v1/views/${viewKey}`, data),

  delete: (viewKey: string) =>
    apiClient.delete<ApiResponse<{ deleted: boolean }>>(`/api/v1/views/${viewKey}`),
}
