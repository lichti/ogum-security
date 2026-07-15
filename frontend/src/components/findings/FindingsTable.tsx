'use client'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { Badge, type BadgeVariant } from '@/components/ui/Badge'
import { RiskBadge } from '@/components/ui/RiskBadge'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { SLABadge } from '@/components/ui/SLABadge'
import { Skeleton } from '@/components/ui/Skeleton'
import { useSlaSettings } from '@/hooks/useSlaSettings'
import type { Finding } from '@/lib/types'

interface FindingsTableProps {
  findings: Finding[]
  loading?: boolean
  nextCursor: string | null
  prevCursors: string[]
  onNext: () => void
  onPrev: () => void
  onRowClick: (finding: Finding) => void
}

function providerVariant(p: string): BadgeVariant {
  const map: Record<string, BadgeVariant> = {
    aws: 'provider-aws',
    azure: 'provider-azure',
    gcp: 'provider-gcp',
    k8s: 'provider-k8s',
  }
  return map[p] ?? 'default'
}

function statusVariant(s: string): BadgeVariant {
  if (s === 'MUTED') return 'status-deleted'
  if (s === 'ACCEPTED') return 'default'
  return 'default'
}

export function FindingsTable({
  findings,
  loading,
  nextCursor,
  prevCursors,
  onNext,
  onPrev,
  onRowClick,
}: FindingsTableProps) {
  const { classify } = useSlaSettings()

  if (loading) {
    return (
      <div className="space-y-2" data-testid="findings-skeleton">
        {Array.from({ length: 8 }).map((_, i) => (
          <Skeleton key={i} className="h-12 w-full" />
        ))}
      </div>
    )
  }

  if (findings.length === 0) {
    return (
      <div className="text-center py-16 text-slate-500" data-testid="findings-empty">
        <p className="text-lg">No findings found</p>
        <p className="text-sm mt-1">Try adjusting your filters or run a CSPM scan.</p>
      </div>
    )
  }

  return (
    <div>
      <table className="w-full text-sm" data-testid="findings-table">
        <thead>
          <tr className="text-left text-slate-500 border-b border-slate-800">
            <th className="pb-3 pr-4 font-medium">Severity</th>
            <th className="pb-3 pr-4 font-medium">Check / Title</th>
            <th className="pb-3 pr-4 font-medium">Resource</th>
            <th className="pb-3 pr-4 font-medium">Provider</th>
            <th className="pb-3 pr-4 font-medium">Region</th>
            <th className="pb-3 pr-4 font-medium">Status</th>
            <th className="pb-3 pr-4 font-medium">Risk</th>
            <th className="pb-3 pr-4 font-medium">SLA</th>
            <th className="pb-3 font-medium">Detected</th>
          </tr>
        </thead>
        <tbody>
          {findings.map((f) => (
            <tr
              key={f._key}
              onClick={() => onRowClick(f)}
              className="border-b border-slate-800/50 hover:bg-slate-800/50 cursor-pointer transition-colors"
            >
              <td className="py-3 pr-4">
                <SeverityBadge severity={f.severity} />
              </td>
              <td className="py-3 pr-4 max-w-xs">
                <div className="text-slate-200 font-medium truncate">{f.title}</div>
                <div className="text-slate-500 text-xs font-mono">{f.check_id}</div>
              </td>
              <td className="py-3 pr-4 max-w-[200px]">
                <div className="text-slate-400 text-xs font-mono truncate">
                  {f.resource_arn ?? f.resource_id}
                </div>
                <div className="text-slate-600 text-xs">{f.resource_type.replace(/_/g, ' ')}</div>
              </td>
              <td className="py-3 pr-4">
                <Badge variant={providerVariant(f.provider)}>{f.provider.toUpperCase()}</Badge>
              </td>
              <td className="py-3 pr-4 text-slate-400">{f.region ?? '—'}</td>
              <td className="py-3 pr-4">
                {f.status === 'FAIL' ? (
                  <span className="text-red-400 text-xs font-medium">FAIL</span>
                ) : f.status === 'MUTED' || f.status === 'ACCEPTED' ? (
                  <Badge variant={statusVariant(f.status)}>{f.status}</Badge>
                ) : (
                  <span className="text-green-400 text-xs font-medium">{f.status}</span>
                )}
              </td>
              <td className="py-3 pr-4">
                <RiskBadge score={(f as Finding & { risk_score?: number | null }).risk_score} />
              </td>
              <td className="py-3 pr-4">
                {f.status === 'FAIL' &&
                  (() => {
                    const status = classify(f.detected_at, f.severity)
                    return status ? <SLABadge status={status} /> : <span className="text-slate-600">—</span>
                  })()}
              </td>
              <td className="py-3 text-slate-500 text-xs">
                {new Date(f.detected_at).toLocaleDateString()}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <div className="flex items-center justify-end mt-4 gap-2">
        <button
          onClick={onPrev}
          disabled={prevCursors.length === 0}
          className="p-1.5 rounded hover:bg-slate-800 disabled:opacity-30 disabled:cursor-not-allowed text-slate-400"
          aria-label="Previous page"
        >
          <ChevronLeft className="w-4 h-4" />
        </button>
        <button
          onClick={onNext}
          disabled={!nextCursor}
          className="p-1.5 rounded hover:bg-slate-800 disabled:opacity-30 disabled:cursor-not-allowed text-slate-400"
          aria-label="Next page"
        >
          <ChevronRight className="w-4 h-4" />
        </button>
      </div>
    </div>
  )
}
