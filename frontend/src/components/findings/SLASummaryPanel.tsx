'use client'
import { useQuery } from '@tanstack/react-query'
import { clsx } from 'clsx'
import { findingsApi } from '@/lib/api'
import type { SLASummary } from '@/lib/types'

const TILES: { key: keyof SLASummary; label: string; classes: string }[] = [
  { key: 'within_sla', label: 'Within SLA', classes: 'border-green-800 bg-green-950/40 text-green-400' },
  { key: 'at_risk', label: 'At Risk', classes: 'border-yellow-800 bg-yellow-950/40 text-yellow-400' },
  { key: 'overdue', label: 'Overdue', classes: 'border-red-800 bg-red-950/40 text-red-400' },
]

export function SLASummaryPanel() {
  const { data } = useQuery({
    queryKey: ['findings-sla-summary'],
    queryFn: () => findingsApi.slaSummary().then((r) => r.data.data),
    staleTime: 30_000,
  })

  const summary = data ?? { within_sla: 0, at_risk: 0, overdue: 0 }
  const total = summary.within_sla + summary.at_risk + summary.overdue

  return (
    <div className="grid grid-cols-3 gap-3" data-testid="sla-summary-panel">
      {TILES.map((tile) => {
        const count = summary[tile.key]
        const pct = total > 0 ? Math.round((count / total) * 100) : 0
        return (
          <div
            key={tile.key}
            data-testid={`sla-summary-tile-${tile.key}`}
            className={clsx('rounded-lg border px-4 py-3', tile.classes)}
          >
            <p className="text-xs font-medium uppercase tracking-wider opacity-80">{tile.label}</p>
            <p className="text-2xl font-bold mt-1">
              {count} <span className="text-sm font-normal opacity-70">({pct}%)</span>
            </p>
          </div>
        )
      })}
    </div>
  )
}
