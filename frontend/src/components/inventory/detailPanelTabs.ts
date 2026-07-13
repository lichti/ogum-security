export interface SubTab {
  key: string
  label: string
}

export interface MainTab {
  key: string
  label: string
  subtabs: SubTab[]
}

// Structure per specs/ui-design.md §4.2.2 — content beyond Info/Overview and
// Risk/Blast Radius is delivered incrementally in later Epic 14 sprints.
export const DETAIL_PANEL_TABS: MainTab[] = [
  {
    key: 'info',
    label: 'Info',
    subtabs: [
      { key: 'overview', label: 'Overview' },
      { key: 'instance_details', label: 'Instance Details' },
      { key: 'additional_information', label: 'Additional Information' },
      { key: 'volumes', label: 'Volumes' },
    ],
  },
  {
    key: 'risk',
    label: 'Risk',
    subtabs: [
      { key: 'alerts', label: 'Alerts' },
      { key: 'vulnerabilities', label: 'Vulnerabilities' },
      { key: 'attack_paths', label: 'Attack Paths' },
      { key: 'blast_radius', label: 'Blast Radius' },
      { key: 'sensitive_data', label: 'Sensitive Data' },
      { key: 'suspicious_activity', label: 'Suspicious Activity' },
    ],
  },
  {
    key: 'network',
    label: 'Network',
    subtabs: [
      { key: 'connectivity_exposure', label: 'Connectivity & Exposure' },
      { key: 'security_groups_rules', label: 'Security Groups & Rules' },
    ],
  },
  {
    key: 'iam',
    label: 'IAM',
    subtabs: [
      { key: 'roles', label: 'Roles' },
      { key: 'policies', label: 'Policies' },
      { key: 'access_history', label: 'Access History' },
    ],
  },
  {
    key: 'configurations',
    label: 'Configurations',
    subtabs: [
      { key: 'overview', label: 'Overview' },
      { key: 'security_encryption', label: 'Security & Encryption' },
    ],
  },
  {
    key: 'software',
    label: 'Software Inventory',
    subtabs: [
      { key: 'applications', label: 'Applications' },
      { key: 'installed_packages', label: 'Installed Packages' },
      { key: 'licenses', label: 'Licenses' },
      { key: 'running_services', label: 'Running Services' },
    ],
  },
  {
    key: 'compliance',
    label: 'Compliance',
    subtabs: [],
  },
]

export function findTab(key: string): MainTab {
  return DETAIL_PANEL_TABS.find((t) => t.key === key) ?? DETAIL_PANEL_TABS[0]
}

export function defaultSubtab(tab: MainTab): string | undefined {
  return tab.subtabs[0]?.key
}
