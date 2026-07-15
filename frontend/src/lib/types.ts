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
  risk_score?: number | null
  in_attack_path?: boolean
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

export interface NarrativeDeepLink {
  label: string
  tab: string
  subtab: string | null
  count: number
}

export interface ResourceNarrativeSummary {
  resource_key: string
  narrative: string
  generated_by: string
  finding_counts: Record<string, number>
  attack_path_count: number
  deep_links: NarrativeDeepLink[]
}

export interface BlastRadiusNode {
  id: string
  resource_type: string
  name: string
  hop: number
}

export interface BlastRadiusEdge {
  source: string
  target: string
  edge_type: string
}

export interface BlastRadiusResponse {
  resource_key: string
  nodes: BlastRadiusNode[]
  edges: BlastRadiusEdge[]
  grouped_counts: Record<string, number>
}

export interface SoftwarePackage {
  name: string
  version: string
  cve_ids: string[]
  filesystem_path: string | null
}

export type LicenseCategory = 'permissive' | 'copyleft' | 'weak_copyleft' | 'unknown'

export interface SoftwareLicense {
  license_id: string
  category: LicenseCategory
  deprecated: boolean
  package_count: number
}

export interface SoftwareInventoryResponse {
  resource_key: string
  sbom_generated_at: string | null
  installed_packages: SoftwarePackage[]
  licenses: SoftwareLicense[]
  applications_available: boolean
  running_services_available: boolean
}

export interface ResourceComplianceFrameworkOption {
  id: string
  label: string
}

export interface ResourceComplianceControl {
  control_id: string | null
  status: string
  title: string
  category: string
  severity: string
  finding_key: string
}

export interface ResourceComplianceResponse {
  resource_key: string
  available_frameworks: ResourceComplianceFrameworkOption[]
  selected_framework: string | null
  controls: ResourceComplianceControl[]
}

export interface InventoryStats {
  by_provider: Record<string, number>
  by_resource_type: Record<string, number>
  by_region: Record<string, number>
  by_account_id: Record<string, number>
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
  providers: string[]
  resourceTypes: string[]
  regions: string[]
  accountIds: string[]
  search?: string
  status?: 'active' | 'deleted'
  limit: number
  offset: number
}

// ─── Findings ─────────────────────────────────────────────────────────────────

export interface FindingsStats {
  by_severity: Record<string, number>
  by_status: Record<string, number>
  by_provider: Record<string, number>
  total: number
}

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
  first_seen_scan_id: string | null
  last_seen_scan_id: string | null
  scan_count: number
}

export interface SLASettings {
  critical_days: number
  high_days: number
  medium_days: number
  low_days: number
}

export interface SLASummary {
  within_sla: number
  at_risk: number
  overdue: number
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
  provider?: string[]
  severity?: SeverityLevel[]
  status?: FindingStatus[]
  framework?: string[]
  region?: string
  account_id?: string
  resource_type?: string
  source?: FindingSource[]
  q?: string
  limit: number
  cursor?: string
}

// ─── Compliance ────────────────────────────────────────────────────────────────

export interface ComplianceSection {
  key: string
  label: string
  pass: number
  fail: number
  total: number
  score: number
}

export interface ComplianceVersion {
  id: string
  version_label: string
  pass: number
  fail: number
  total: number
  score: number
  sections: ComplianceSection[]
}

export interface ComplianceFamily {
  family: string
  label: string
  versions: ComplianceVersion[]
}

export interface ComplianceSummary {
  families: ComplianceFamily[]
  threat_score: number
  top_failing: { check_id: string; title: string; severity: SeverityLevel; count: number }[]
}

export type ComplianceControlStatus = 'PASS' | 'FAIL' | 'UNSCORED'

// Control counts controls (ACCEPTED folds into Pass, MUTED folds into Unscored).
// Findings counts raw findings by real status — MUTED/ACCEPTED shown, but excluded
// from the score_by_asset ratio, same as Unscored is excluded from score_by_control.
export type ComplianceView = 'control' | 'findings'

export interface ComplianceRequirementNode {
  control_id: string
  name: string
  description: string | null
  status: ComplianceControlStatus
  finding_key: string | null
  pass_count: number
  fail_count: number
  accepted_count: number
  muted_count: number
}

export interface ComplianceSectionNode {
  key: string
  label: string
  control_pass_count: number
  control_fail_count: number
  control_unscored_count: number
  control_total: number
  score_by_control: number
  finding_pass_count: number
  finding_fail_count: number
  finding_accepted_count: number
  finding_muted_count: number
  score_by_asset: number
  subsections: ComplianceSectionNode[]
  requirements: ComplianceRequirementNode[]
}

export interface ComplianceFrameworkDetail {
  id: string
  family: string
  family_label: string
  version_label: string
  score_by_control: number
  score_by_asset: number
  control_pass_count: number
  control_fail_count: number
  control_unscored_count: number
  control_total: number
  finding_pass_count: number
  finding_fail_count: number
  finding_accepted_count: number
  finding_muted_count: number
  catalog_available: boolean
  sections: ComplianceSectionNode[]
}

export type CompliancePeriod = '7d' | '14d' | '1m'

export interface ComplianceScoreTrendPoint {
  date: string
  score_by_control: number
  score_by_asset: number
  pass_count: number
  fail_count: number
  unscored_count: number
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

// ─── Scans ────────────────────────────────────────────────────────────────────

export type ScanJobStatus = 'queued' | 'running' | 'completed' | 'failed'

export interface ScanJob {
  job_id: string
  tenant_id: string
  provider_id: string
  provider: string
  task_name: string
  frameworks: string[]
  regions: string[] | null
  status: ScanJobStatus
  checks_total: number
  checks_completed: number
  findings_found: number
  findings_fail: number
  started_at: string | null
  completed_at: string | null
  created_at: string
  error_message: string | null
}

export interface ScanTriggerRequest {
  provider_id: string
  frameworks?: string[]
}

export interface ScanTriggerResponse {
  job_id: string
  status: string
}

// ─── Attack Paths ─────────────────────────────────────────────────────────────

export type AttackPathSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'

export type AttackPathTargetAssetCategory =
  | 'compute'
  | 'containers'
  | 'storage'
  | 'database'
  | 'networking'
  | 'security_identity'
  | 'other'

export type AttackPathCrownJewelReason =
  | 'internet_facing'
  | 'stores_sensitive_data'
  | 'high_privilege_identity'
  | 'manually_flagged'

export interface AttackPath {
  _key: string
  path_id: string
  tenant_id: string
  rule: string
  entry_point_id: string
  entry_point_type: string
  entry_point_name: string
  target_id: string
  target_type: string
  target_name: string
  hops: number
  path_vertex_ids: string[]
  risk_score: number
  severity: AttackPathSeverity
  is_toxic_combination: boolean
  mitre_ttps?: string[]
  mitre_chain?: string[]
  actively_exploited?: boolean
  last_runtime_event_at?: string | null
  detected_at: string
  status: string
  // US-14.11 — computed at read time, always present in list/detail responses
  target_asset_category?: AttackPathTargetAssetCategory
  target_crown_jewel_reason?: AttackPathCrownJewelReason | null
  // US-14.13 — only present on paths detected after this sprint's merge;
  // undefined (not fabricated) on paths detected before it
  exposure?: 'internet_facing' | 'public_facing' | 'trusted_access' | 'none'
  is_cross_account?: boolean
  is_cross_cloud_provider?: boolean
  account_ids?: string[]
}

export interface NarrativeStep {
  index: number
  total: number
  title: string
  text: string
}

export interface PathNarrativeSummary {
  path_id: string
  steps: NarrativeStep[]
  generated_by: string
}

export interface MitreTechnique {
  technique_id: string
  name: string
  tactic_ids: string[]
  platforms?: string[]
  is_subtechnique?: boolean
}

export interface MitreTactic {
  tactic_id: string
  name: string
  shortname: string
}

export interface MitreGroup {
  group_id: string
  name: string
  aliases?: string[]
  country?: string
}

export interface MitreIntelligence {
  techniques: MitreTechnique[]
  tactics: MitreTactic[]
  apt_groups: MitreGroup[]
  mitre_chain: string[]
}

export interface AttackPathStats {
  total: number
  by_severity: Record<AttackPathSeverity, number>
  new_24h: number
  by_target_asset_category: Partial<Record<AttackPathTargetAssetCategory, number>>
  by_target_crown_jewel_reason: Partial<Record<AttackPathCrownJewelReason, number>>
}

export interface AttackPathDetail {
  path: AttackPath
  nodes: Record<string, unknown>[]
  findings: Record<string, unknown>[]
}

export interface PagedAttackPaths {
  items: AttackPath[]
  next_cursor: string | null
  count: number
}

export interface AttackPathFilters {
  severity?: AttackPathSeverity
  is_toxic_combination?: boolean
  provider?: string
  target_asset_category?: AttackPathTargetAssetCategory
  target_crown_jewel_reason?: AttackPathCrownJewelReason
  limit: number
  cursor?: string
}

// ─── Graph (Sprint 6) ─────────────────────────────────────────────────────────

export interface SavedQuery {
  key: string
  name: string
  query: string
  description: string
  created_at: string
  updated_at: string
}

export type ViewScope = 'inventory' | 'findings' | 'compliance'

export interface SavedView {
  key: string
  scope: ViewScope
  name: string
  filters: Record<string, unknown>
  columns: string[] | null
  owner: string
  is_system: boolean
  pinned: boolean
  created_at: string
  updated_at: string
}

export interface SavedViewCreateRequest {
  scope: ViewScope
  name: string
  filters?: Record<string, unknown>
  columns?: string[] | null
}

export interface SavedViewUpdateRequest {
  name?: string
  filters?: Record<string, unknown>
  columns?: string[] | null
  pinned?: boolean
}

export interface AqlResult {
  rows: unknown[]
  count: number
  truncated: boolean
  execution_ms: number | null
}

export interface ShortestPathResult {
  found: boolean
  hops: number
  vertices: Record<string, unknown>[]
  edges: Record<string, unknown>[]
}

export interface ExposureSummary {
  exposed_resources: number
  exposed_data_assets: number
  exposed_endpoints: number
  total: number
}

export interface IdentitySummary {
  key: string
  name: string
  identity_type: string
  provider: string
  account_id: string | null
  arn: string
  status: string
  risk_score: number | null
  has_admin_policy: boolean
  dangerous_permissions_count: number
  escalation_paths_count: number
  privilege_gap_score: number
  policies: string[]
  last_scanned_at: string | null
}

export interface DangerousPermission {
  action: string
  risk: string
}

export interface EscalationChain {
  start_id: string
  start_name: string
  target_id: string
  target_name: string
  hops: number
  chain: string[]
}

// ─── Side Scanning ────────────────────────────────────────────────────────────

export type SideScanJobStatus = 'queued' | 'running' | 'completed' | 'failed'
export type SideScanJobType = 'ec2' | 'lambda' | 'k8s_container' | 'ecr' | 'sbom_rescan'

export interface SideScanJob {
  _key: string
  tenant_id: string
  type: SideScanJobType
  status: SideScanJobStatus
  resource_id?: string
  image_uri?: string
  image_digest?: string
  pod_name?: string
  pod_namespace?: string
  container_name?: string
  node_name?: string
  provider_id?: string
  findings_count?: number
  error_message?: string | null
  created_at: string
  started_at?: string | null
  completed_at?: string | null
}

export interface PagedSideScanJobs {
  items: SideScanJob[]
  total: number
  limit: number
  offset: number
}

export interface ImageSecurityStatus {
  overall_status: 'pass' | 'fail'
  critical: number
  high: number
  medium: number
  low: number
  image_digest: string
}

export interface IdentityPermissions {
  identity_id: string
  identity_key: string
  name: string
  identity_type: string
  provider: string
  account_id: string | null
  policies: string[]
  granted_actions: string[]
  dangerous_permissions: DangerousPermission[]
  dangerous_permissions_count: number
  escalation_chains: EscalationChain[]
  escalation_paths_count: number
  has_admin_policy: boolean
  privilege_gap_score: number
  risk_score: number | null
  status: string
}
