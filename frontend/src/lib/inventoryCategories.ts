export type ResourceCategory =
  | 'compute'
  | 'containers'
  | 'storage'
  | 'database'
  | 'networking'
  | 'security_identity'
  | 'other'

export const CATEGORY_ORDER: ResourceCategory[] = [
  'compute',
  'containers',
  'database',
  'storage',
  'networking',
  'security_identity',
  'other',
]

export const CATEGORY_LABELS: Record<ResourceCategory, string> = {
  compute: 'Compute',
  containers: 'Containers',
  storage: 'Storage',
  database: 'Database',
  networking: 'Networking',
  security_identity: 'Security & Identity',
  other: 'Other',
}

// Known resource_type values discovered by AWS/Azure/GCP/K8s workers, grouped
// by category. Any type not listed here falls back to 'other' so new
// discovery types never disappear from the UI — they just land uncategorized
// until this map is updated.
const RESOURCE_TYPE_CATEGORY: Record<string, ResourceCategory> = {
  // Compute
  ec2_instance: 'compute',
  virtual_machine: 'compute',
  compute_instance: 'compute',
  lambda_function: 'compute',

  // Containers / Kubernetes
  eks_cluster: 'containers',
  aks_cluster: 'containers',
  gke_cluster: 'containers',
  k8s_container: 'containers',
  container_image: 'containers',
  ecr_repository: 'containers',
  pod: 'containers',
  deployment: 'containers',
  daemon_set: 'containers',
  stateful_set: 'containers',
  namespace: 'containers',
  node: 'containers',
  service: 'containers',
  ingress: 'containers',
  network_policy: 'containers',
  persistent_volume: 'containers',

  // Storage
  blob_container: 'storage',
  gcs_bucket: 'storage',
  managed_disk: 'storage',
  storage_account: 'storage',

  // Database
  rds_instance: 'database',

  // Networking
  vpc: 'networking',
  vpc_network: 'networking',
  virtual_network: 'networking',
  subnet: 'networking',
  security_group: 'networking',
  network_security_group: 'networking',
  firewall_rule: 'networking',
  internet_gateway: 'networking',
  load_balancer: 'networking',
  public_ip_address: 'networking',
  elastic_ip: 'networking',

  // Security & Identity
  kms_key: 'security_identity',
  key_vault: 'security_identity',
  secrets_manager_secret: 'security_identity',
  cloudtrail_trail: 'security_identity',
  cluster_role: 'security_identity',
  cluster_role_binding: 'security_identity',
  service_account_k8s: 'security_identity',
}

export function categoryOf(resourceType: string): ResourceCategory {
  return RESOURCE_TYPE_CATEGORY[resourceType] ?? 'other'
}

/** Sums by_resource_type counts into their categories. Unmapped types count as 'other'. */
export function aggregateByCategory(byResourceType: Record<string, number>): Record<ResourceCategory, number> {
  const totals = CATEGORY_ORDER.reduce(
    (acc, cat) => ({ ...acc, [cat]: 0 }),
    {} as Record<ResourceCategory, number>,
  )
  for (const [type, count] of Object.entries(byResourceType)) {
    totals[categoryOf(type)] += count
  }
  return totals
}

/** Resolves selected categories to the concrete resource_type values present in current data. */
export function resourceTypesForCategories(
  categories: string[],
  byResourceType: Record<string, number>,
): string[] {
  if (categories.length === 0) return []
  const selected = new Set(categories)
  return Object.keys(byResourceType).filter((type) => selected.has(categoryOf(type)))
}
