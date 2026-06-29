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
