'use client'

import { usePathname } from 'next/navigation'

const ROUTE_LABELS: Record<string, string> = {
  '/': 'Security Overview',
  '/inventory': 'Inventory',
  '/findings': 'Findings',
  '/compliance': 'Compliance',
  '/attack-paths': 'Attack Paths',
  '/side-scanning': 'Side Scanning',
  '/providers': 'Connected Accounts',
  '/providers/new': 'Cloud Providers / Connect',
  '/scans': 'Scans',
  '/settings/sla': 'SLA Settings',
  '/settings/compliance': 'Compliance Settings',
  '/admin/jobs': 'Admin — Jobs',
  '/admin/queue-depth': 'Admin — Queue Depth',
  '/admin/workers': 'Admin — Workers',
}

// Short, breadcrumb-style descriptions only — longer instructional copy stays inline
// in the page body (see the "Page header" convention in CLAUDE.md).
const ROUTE_SUBTITLES: Record<string, string> = {
  '/': 'Real-time posture across all connected accounts',
  '/findings': 'CSPM and IaC security findings across all providers',
  '/compliance': 'Framework scores and control status',
  '/attack-paths': 'Contextual risk graph — paths from internet exposure to sensitive data',
  '/side-scanning': 'Agentless deep scanning of EC2, Lambda, containers and registry images',
  '/providers': 'Manage cloud provider connections and trigger discovery jobs',
  '/scans': 'CSPM scan history — trigger, track, and review execution logs',
  '/settings/sla': 'Remediation deadline per finding severity, used across Findings for SLA tracking',
}

export function Header() {
  const pathname = usePathname()
  const label = ROUTE_LABELS[pathname] ?? pathname.replace(/^\//, '').replace(/-/g, ' ')
  const subtitle = ROUTE_SUBTITLES[pathname]

  return (
    <header id="app-header" className="h-14 bg-slate-900 border-b border-slate-800 flex items-center justify-between px-6 shrink-0">
      <div className="flex items-baseline gap-2.5">
        <h1 className="text-sm font-medium text-slate-200 capitalize">{label}</h1>
        {subtitle && <span className="text-xs text-slate-500">{subtitle}</span>}
      </div>
      <div className="w-8 h-8 bg-slate-700 rounded-full" aria-label="User avatar" />
    </header>
  )
}
