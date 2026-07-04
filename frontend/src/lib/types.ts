export interface ResourceSummary {
  key: string
  tenant_id: string
  provider: 'aws' | 'azure' | 'gcp' | 'k8s'
  resource_type: string
  resource_id: string
  name: string
  region: string | null
  account_id: string | null
  status: 'active' | 'deleted'
  is_public: boolean
  tags: Record<string, string>
  last_scanned_at: string | null
  updated_at: string | null
}

export interface EdgeSummary {
  edge_type: string
  direction: 'outbound' | 'inbound'
  peer_key: string
  peer_collection: string
  peer_type: string | null
}

export interface ResourceDetail extends ResourceSummary {
  arn: string | null
  raw_metadata: Record<string, unknown>
  edges: EdgeSummary[]
}

export interface InventoryStats {
  by_provider: Record<string, number>
  by_resource_type: Record<string, number>
  by_status: Record<string, number>
  identity_count: number
  data_asset_count: number
  last_discovery_at: string | null
}

export interface ApiResponse<T> {
  data: T
  meta: {
    request_id: string
    timestamp: string
    total?: number
    limit?: number
    offset?: number
  }
  error: string | null
}

export interface InventoryFilters {
  provider?: string
  resource_type?: string
  region?: string
  search?: string
  status?: 'active' | 'deleted'
  limit: number
  offset: number
}

// ─── Findings ─────────────────────────────────────────────────────────────────

export type SeverityLevel = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL'
export type FindingStatus = 'FAIL' | 'PASS' | 'MUTED' | 'ACCEPTED'
export type FindingSource = 'cspm' | 'iac'

export interface Finding {
  _key: string
  finding_id: string
  tenant_id: string
  check_id: string
  title: string
  description: string
  resource_id: string
  resource_arn: string | null
  resource_type: string
  severity: SeverityLevel
  status: FindingStatus
  provider: string
  region: string | null
  account_id: string
  framework_mapping: string[]
  remediation: string | null
  remediation_code: string | null
  source: FindingSource
  detected_at: string
  updated_at: string
  mute_reason: string | null
  scan_job_id: string | null
}

export interface FindingDetail extends Finding {
  resource: {
    name: string | null
    arn: string | null
    resource_type: string
    region: string | null
    account_id: string | null
  } | null
  attack_paths: unknown[]
  cli_command: string | null
}

export interface PagedFindings {
  items: Finding[]
  next_cursor: string | null
  count: number
}

export interface FindingsFilter {
  provider?: string
  severity?: SeverityLevel
  status?: FindingStatus
  framework?: string
  region?: string
  account_id?: string
  resource_type?: string
  source?: FindingSource
  q?: string
  limit: number
  cursor?: string
}

// ─── Compliance ────────────────────────────────────────────────────────────────

export interface FrameworkScore {
  id: string
  pass: number
  fail: number
  total: number
  score: number
}

export interface ComplianceSummary {
  frameworks: FrameworkScore[]
  threat_score: number
  top_failing: { check_id: string; title: string; severity: SeverityLevel; count: number }[]
}

// ─── Providers ────────────────────────────────────────────────────────────────

export type ProviderType = 'aws' | 'azure' | 'gcp' | 'k8s'
export type ProviderStatus = 'pending' | 'active' | 'error' | 'disabled'

export interface ProviderConfig {
  key: string
  provider: ProviderType
  display_name: string
  account_id?: string | null
  subscription_id?: string | null
  project_id?: string | null
  cluster_name?: string | null
  regions: string[]
  enabled: boolean
  status: ProviderStatus
  credential_type: string
  role_arn?: string | null
  azure_tenant_id?: string | null
  azure_client_id?: string | null
  last_discovery_at?: string | null
  last_discovery_job_id?: string | null
  created_at: string
}

export interface ProviderRegisterRequest {
  provider: ProviderType
  display_name: string
  account_id?: string
  regions?: string[]
  validate_connection?: boolean
  // AWS
  role_arn?: string
  aws_access_key_id?: string
  aws_secret_access_key?: string
  // Azure
  subscription_id?: string
  azure_tenant_id?: string
  azure_client_id?: string
  azure_client_secret?: string
  // GCP
  project_id?: string
  gcp_service_account_json?: Record<string, unknown>
  // Kubernetes
  cluster_name?: string
  kubeconfig?: Record<string, unknown>
}

export interface ProviderUpdateRequest {
  display_name?: string
  regions?: string[]
  enabled?: boolean
  role_arn?: string | null
  azure_tenant_id?: string | null
  azure_client_id?: string | null
  // Secrets stored for scheduled jobs — never returned in API responses
  aws_access_key_id?: string | null
  aws_secret_access_key?: string | null
  azure_client_secret?: string | null
  gcp_service_account_json?: Record<string, unknown> | null
  kubeconfig?: Record<string, unknown> | null
}

export interface DiscoverRequest {
  aws_access_key_id?: string
  aws_secret_access_key?: string
  azure_client_secret?: string
  gcp_service_account_json?: Record<string, unknown>
  kubeconfig?: Record<string, unknown>
}

export interface ProviderRegisterResponse {
  provider_id: string
  discovery_job_id: string | null
  message: string
}

export interface DiscoverResponse {
  provider_id: string
  discovery_job_id: string
  message: string
}
