'use client'

import Link from 'next/link'
import { useQuery } from '@tanstack/react-query'
import {
  ShieldCheck,
  AlertTriangle,
  Package,
  Activity,
  ChevronRight,
  Clock,
  CheckCircle2,
  XCircle,
  Loader2,
  GitBranch,
  Skull,
} from 'lucide-react'
import { attackPathsApi, complianceApi, findingsApi, scansApi } from '@/lib/api'
import type { ScanJob } from '@/lib/types'

// ─── Helpers ──────────────────────────────────────────────────────────────────

function threatScoreColor(score: number) {
  if (score >= 70) return 'text-green-400'
  if (score >= 40) return 'text-yellow-400'
  return 'text-red-400'
}

function threatScoreBg(score: number) {
  if (score >= 70) return 'border-green-500/40 bg-green-500/5'
  if (score >= 40) return 'border-yellow-500/40 bg-yellow-500/5'
  return 'border-red-500/40 bg-red-500/5'
}

function scanStatusIcon(status: ScanJob['status']) {
  if (status === 'completed') return <CheckCircle2 className="w-3.5 h-3.5 text-green-400" />
  if (status === 'failed') return <XCircle className="w-3.5 h-3.5 text-red-400" />
  return <Loader2 className="w-3.5 h-3.5 text-slate-400 animate-spin" />
}

function relativeTime(iso: string) {
  const diff = Date.now() - new Date(iso).getTime()
  const m = Math.floor(diff / 60000)
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

const SEVERITY_CONFIG = [
  { key: 'CRITICAL', label: 'Critical', color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20' },
  { key: 'HIGH', label: 'High', color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/20' },
  { key: 'MEDIUM', label: 'Medium', color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/20' },
  { key: 'LOW', label: 'Low', color: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/20' },
]

// ─── Sub-components ────────────────────────────────────────────────────────────

function QuickLink({
  href,
  icon: Icon,
  label,
  description,
}: {
  href: string
  icon: React.ElementType
  label: string
  description: string
}) {
  return (
    <Link
      href={href}
      data-testid={`quick-link-${label.toLowerCase().replace(/\s+/g, '-')}`}
      className="flex items-center gap-3 p-3 rounded-lg border border-slate-800 bg-slate-900 hover:border-orange-500/40 hover:bg-orange-500/5 transition-colors group"
    >
      <Icon className="w-4 h-4 text-orange-400 shrink-0" />
      <div className="min-w-0">
        <p className="text-sm font-medium text-slate-200 group-hover:text-white">{label}</p>
        <p className="text-xs text-slate-500 truncate">{description}</p>
      </div>
      <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-slate-400 ml-auto shrink-0" />
    </Link>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function DashboardPage() {
  const { data: complianceData } = useQuery({
    queryKey: ['compliance-summary'],
    queryFn: () => complianceApi.summary(),
    refetchInterval: 60_000,
  })

  const { data: statsData } = useQuery({
    queryKey: ['findings-stats'],
    queryFn: () => findingsApi.stats(),
    refetchInterval: 60_000,
  })

  const { data: scansData } = useQuery({
    queryKey: ['scans-list'],
    queryFn: () => scansApi.list({ limit: 5 }),
    refetchInterval: 30_000,
  })

  const { data: attackPathStats } = useQuery({
    queryKey: ['attack-paths-stats'],
    queryFn: () => attackPathsApi.stats().then((r) => r.data.data),
    staleTime: 60_000,
  })

  const threatScore = complianceData?.data.data.threat_score ?? null
  const stats = statsData?.data.data
  const recentScans = scansData?.data.data.items ?? []

  return (
    <div id="dashboard-page" className="max-w-5xl mx-auto px-4 py-8 space-y-8">

      {/* Top stats row */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">

        {/* ThreatScore */}
        <div
          id="dashboard-threatscore-card"
          className={`col-span-2 md:col-span-1 bg-slate-900 border rounded-lg p-4 flex flex-col gap-1 ${
            threatScore !== null ? threatScoreBg(threatScore) : 'border-slate-800'
          }`}
        >
          <span className="text-xs text-slate-500 uppercase tracking-wide">ThreatScore</span>
          <span
            className={`text-3xl font-bold tabular-nums ${
              threatScore !== null ? threatScoreColor(threatScore) : 'text-slate-600'
            }`}
          >
            {threatScore !== null ? threatScore : '—'}
          </span>
          <span className="text-xs text-slate-500">0 = perfect · 100 = critical</span>
        </div>

        {/* Severity counts — each links to /findings?severity=X */}
        {SEVERITY_CONFIG.map(({ key, label, color, bg }) => (
          <Link
            key={key}
            href={`/findings?severity=${key}`}
            data-testid={`dashboard-severity-card-${key}`}
            className={`bg-slate-900 border rounded-lg p-4 flex flex-col gap-1 hover:opacity-80 transition-opacity ${
              (stats?.by_severity[key] ?? 0) > 0 ? bg : 'border-slate-800'
            }`}
          >
            <span className="text-xs text-slate-500 uppercase tracking-wide">{label}</span>
            <span className={`text-3xl font-bold tabular-nums ${color}`}>
              {stats ? (stats.by_severity[key] ?? 0) : '—'}
            </span>
            <span className="text-xs text-slate-500">findings</span>
          </Link>
        ))}
      </div>

      {/* Attack Paths card */}
      <Link
        href="/attack-paths"
        id="dashboard-attack-paths-card"
        className="block bg-slate-900 border border-slate-800 rounded-lg p-4 hover:border-orange-500/40 hover:bg-orange-500/5 transition-colors group"
      >
        <div className="flex items-center justify-between mb-3">
          <span className="text-sm font-medium text-slate-300 flex items-center gap-2">
            <GitBranch className="w-4 h-4 text-orange-400" />
            Attack Paths
          </span>
          <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-slate-400" />
        </div>
        <div className="flex items-center gap-6">
          <div>
            <p className="text-2xl font-bold text-slate-100 tabular-nums">
              {attackPathStats ? attackPathStats.total : '—'}
            </p>
            <p className="text-xs text-slate-500 mt-0.5">active paths</p>
          </div>
          <div className="flex items-center gap-1.5">
            <Skull className="w-4 h-4 text-red-400" />
            <p className="text-xl font-bold text-red-400 tabular-nums">
              {attackPathStats
                ? (attackPathStats.by_severity['CRITICAL'] ?? 0) +
                  (attackPathStats.by_severity['HIGH'] ?? 0)
                : '—'}
            </p>
            <p className="text-xs text-slate-500">critical/high</p>
          </div>
          {attackPathStats && attackPathStats.new_24h > 0 && (
            <div className="ml-auto">
              <span className="text-xs bg-red-500/10 border border-red-500/20 text-red-400 px-2 py-0.5 rounded">
                +{attackPathStats.new_24h} new 24h
              </span>
            </div>
          )}
        </div>
      </Link>

      {/* Bottom row: recent scans + quick links */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">

        {/* Recent scans */}
        <div id="dashboard-recent-scans" className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
            <span className="text-sm font-medium text-slate-300 flex items-center gap-2">
              <Activity className="w-4 h-4 text-orange-400" />
              Recent Scans
            </span>
            <Link href="/scans" className="text-xs text-orange-400 hover:text-orange-300">
              View scans →
            </Link>
          </div>

          {recentScans.length === 0 ? (
            <div className="px-4 py-6 text-center text-sm text-slate-600">
              No scans yet — connect a provider and click &quot;Scan Now&quot;
            </div>
          ) : (
            <ul className="divide-y divide-slate-800">
              {recentScans.map((job) => (
                <li key={job.job_id} data-testid={`recent-scan-row-${job.job_id}`} className="px-4 py-2.5 flex items-center gap-3">
                  {scanStatusIcon(job.status)}
                  <div className="min-w-0 flex-1">
                    <p className="text-xs text-slate-300 truncate">
                      {job.provider.toUpperCase()} · {job.frameworks.join(', ')}
                    </p>
                    <p className="text-xs text-slate-500">
                      {job.findings_fail} fail · {job.findings_found} total
                    </p>
                  </div>
                  <span className="text-xs text-slate-600 shrink-0 flex items-center gap-1">
                    <Clock className="w-3 h-3" />
                    {relativeTime(job.created_at)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>

        {/* Quick links */}
        <div id="dashboard-quick-links" className="space-y-2">
          <p className="text-xs text-slate-500 uppercase tracking-wide px-1">Navigate</p>
          <QuickLink
            href="/findings"
            icon={AlertTriangle}
            label="Findings"
            description="Browse and filter all security findings"
          />
          <QuickLink
            href="/compliance"
            icon={ShieldCheck}
            label="Compliance"
            description="CIS, PCI DSS, SOC 2, ISO 27001 scores"
          />
          <QuickLink
            href="/inventory"
            icon={Package}
            label="Inventory"
            description="All discovered cloud resources"
          />
          <QuickLink
            href="/providers"
            icon={Activity}
            label="Providers"
            description="Connected accounts and scan controls"
          />
          <QuickLink
            href="/attack-paths"
            icon={GitBranch}
            label="Attack Paths"
            description="Risk graph — internet exposure to sensitive data"
          />
        </div>
      </div>
    </div>
  )
}
