'use client'
import { clsx } from 'clsx'
import type { SeverityLevel } from '@/lib/types'

const SEVERITIES: SeverityLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']
const PROVIDERS = ['aws', 'azure', 'gcp', 'k8s'] as const

const SEVERITY_COLORS: Record<SeverityLevel, string> = {
  CRITICAL: 'bg-red-950/40 text-red-400 border-red-800 hover:bg-red-950/60',
  HIGH: 'bg-orange-950/40 text-orange-400 border-orange-800 hover:bg-orange-950/60',
  MEDIUM: 'bg-yellow-950/40 text-yellow-400 border-yellow-800 hover:bg-yellow-950/60',
  LOW: 'bg-blue-950/40 text-blue-400 border-blue-800 hover:bg-blue-950/60',
  INFORMATIONAL: 'bg-slate-800/60 text-slate-400 border-slate-700 hover:bg-slate-800',
}

const PROVIDER_COLORS: Record<string, string> = {
  aws: 'bg-amber-950/40 text-amber-400 border-amber-800 hover:bg-amber-950/60',
  azure: 'bg-blue-950/40 text-blue-400 border-blue-800 hover:bg-blue-950/60',
  gcp: 'bg-sky-950/40 text-sky-400 border-sky-800 hover:bg-sky-950/60',
  k8s: 'bg-indigo-950/40 text-indigo-400 border-indigo-800 hover:bg-indigo-950/60',
}

interface FindingsSummaryProps {
  bySeverity: Record<string, number>
  byProvider: Record<string, number>
  selectedSeverities: string[]
  selectedProviders: string[]
  onSeverityClick: (severity: string) => void
  onProviderClick: (provider: string) => void
}

export function FindingsSummary({
  bySeverity,
  byProvider,
  selectedSeverities,
  selectedProviders,
  onSeverityClick,
  onProviderClick,
}: FindingsSummaryProps) {
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs font-medium text-slate-500 w-24 flex-shrink-0">By severity</span>
        {SEVERITIES.map((sev) => {
          const count = bySeverity[sev] ?? 0
          const active = selectedSeverities.includes(sev)
          return (
            <button
              key={sev}
              type="button"
              onClick={() => onSeverityClick(sev)}
              aria-label={`Filter by ${sev}`}
              aria-pressed={active}
              className={clsx(
                'rounded-lg px-3 py-1.5 flex items-center gap-2 border transition-colors cursor-pointer text-xs',
                SEVERITY_COLORS[sev],
                active && 'ring-1 ring-inset ring-current',
              )}
            >
              <span className="font-medium">{sev}</span>
              <span className="font-bold">{count.toLocaleString()}</span>
            </button>
          )
        })}
      </div>

      <div className="flex items-center gap-2 flex-wrap">
        <span className="text-xs font-medium text-slate-500 w-24 flex-shrink-0">By provider</span>
        {PROVIDERS.map((p) => {
          const count = byProvider[p] ?? 0
          const active = selectedProviders.includes(p)
          return (
            <button
              key={p}
              type="button"
              onClick={() => onProviderClick(p)}
              aria-label={`Filter by ${p.toUpperCase()}`}
              aria-pressed={active}
              className={clsx(
                'rounded-lg px-3 py-1.5 flex items-center gap-2 border transition-colors cursor-pointer text-xs',
                PROVIDER_COLORS[p],
                active && 'ring-1 ring-inset ring-current',
              )}
            >
              <span className="font-medium">{p.toUpperCase()}</span>
              <span className="font-bold">{count.toLocaleString()}</span>
            </button>
          )
        })}
      </div>
    </div>
  )
}
