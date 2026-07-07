import type { AttackPathStats } from '@/lib/types'

interface Props {
  stats: AttackPathStats
  onSeverityClick: (severity: string) => void
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-900/40 text-red-400 border border-red-800 hover:bg-red-900/60',
  HIGH: 'bg-orange-900/40 text-orange-400 border border-orange-800 hover:bg-orange-900/60',
  MEDIUM: 'bg-yellow-900/40 text-yellow-400 border border-yellow-800 hover:bg-yellow-900/60',
  LOW: 'bg-blue-900/40 text-blue-400 border border-blue-800 hover:bg-blue-900/60',
}

export function AttackPathStatsBar({ stats, onSeverityClick }: Props) {
  const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const

  return (
    <div className="flex items-center gap-3 flex-wrap">
      <div className="bg-slate-800 rounded-lg px-4 py-2.5 flex items-center gap-2">
        <span className="text-slate-400 text-xs">Total</span>
        <span className="text-slate-100 font-bold text-lg">{stats.total}</span>
      </div>

      {severities.map((sev) => (
        <button
          key={sev}
          onClick={() => onSeverityClick(sev)}
          className={`rounded-lg px-3 py-2.5 flex items-center gap-2 transition-colors cursor-pointer ${SEVERITY_COLORS[sev]}`}
          aria-label={`Filter by ${sev}`}
        >
          <span className="text-xs font-medium">{sev}</span>
          <span className="font-bold text-sm">{stats.by_severity[sev] ?? 0}</span>
        </button>
      ))}

      {stats.new_24h > 0 && (
        <div className="bg-slate-800 rounded-lg px-3 py-2.5 flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-orange-500 animate-pulse" />
          <span className="text-slate-400 text-xs">New (24h)</span>
          <span className="text-orange-400 font-bold text-sm">{stats.new_24h}</span>
        </div>
      )}
    </div>
  )
}
