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

export interface ProviderConfig {
  key: string
  provider: string
  display_name: string
  account_id?: string | null
  subscription_id?: string | null
  project_id?: string | null
  cluster_name?: string | null
  regions: string[]
  enabled: boolean
  last_discovery_at?: string | null
  last_discovery_job_id?: string | null
  created_at: string
}

export interface ProviderRegisterRequest {
  provider: string
  display_name: string
  account_id?: string
  subscription_id?: string
  project_id?: string
  cluster_name?: string
  regions?: string[]
  validate_connection?: boolean
}

export interface ProviderRegisterResponse {
  provider_id: string
  discovery_job_id: string | null
  message: string
}
