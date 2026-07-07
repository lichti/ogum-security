import { formatDistanceToNow } from 'date-fns'
import { ArrowRight, Flame, ChevronLeft, ChevronRight } from 'lucide-react'
import type { AttackPath, AttackPathSeverity } from '@/lib/types'

interface Props {
  paths: AttackPath[]
  loading: boolean
  nextCursor: string | null
  prevCursors: string[]
  onNext: () => void
  onPrev: () => void
  onRowClick: (path: AttackPath) => void
}

const SEV_CLASSES: Record<AttackPathSeverity, string> = {
  CRITICAL: 'bg-red-900/30 text-red-400 border border-red-800',
  HIGH: 'bg-orange-900/30 text-orange-400 border border-orange-800',
  MEDIUM: 'bg-yellow-900/30 text-yellow-400 border border-yellow-800',
  LOW: 'bg-blue-900/30 text-blue-400 border border-blue-800',
}

const RISK_BAR_COLOR: Record<AttackPathSeverity, string> = {
  CRITICAL: 'bg-red-500',
  HIGH: 'bg-orange-500',
  MEDIUM: 'bg-yellow-500',
  LOW: 'bg-blue-500',
}

function RiskScoreBar({ score, severity }: { score: number; severity: AttackPathSeverity }) {
  const pct = Math.min(100, Math.round(score))
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-1.5 bg-slate-700 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${RISK_BAR_COLOR[severity]}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-slate-300 text-xs font-mono">{score.toFixed(0)}</span>
    </div>
  )
}

function EmptyState() {
  return (
    <tr>
      <td colSpan={6} className="py-16 text-center text-slate-500">
        <div className="text-sm">No attack paths detected</div>
        <div className="text-xs mt-1 text-slate-600">Run a CSPM scan with graph analysis to discover attack paths</div>
      </td>
    </tr>
  )
}

function SkeletonRow() {
  return (
    <tr>
      {[...Array(6)].map((_, i) => (
        <td key={i} className="px-4 py-3">
          <div className="h-4 bg-slate-800 rounded animate-pulse" />
        </td>
      ))}
    </tr>
  )
}

export function AttackPathsTable({ paths, loading, nextCursor, prevCursors, onNext, onPrev, onRowClick }: Props) {
  const hasPrev = prevCursors.length > 0

  return (
    <div className="rounded-lg border border-slate-800 overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-slate-800/60">
          <tr>
            <th className="px-4 py-3 text-left text-slate-400 font-medium text-xs uppercase tracking-wider">Attack Path</th>
            <th className="px-4 py-3 text-left text-slate-400 font-medium text-xs uppercase tracking-wider">Severity</th>
            <th className="px-4 py-3 text-left text-slate-400 font-medium text-xs uppercase tracking-wider">Risk Score</th>
            <th className="px-4 py-3 text-left text-slate-400 font-medium text-xs uppercase tracking-wider">Hops</th>
            <th className="px-4 py-3 text-left text-slate-400 font-medium text-xs uppercase tracking-wider">Type</th>
            <th className="px-4 py-3 text-left text-slate-400 font-medium text-xs uppercase tracking-wider">Detected</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800">
          {loading
            ? Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} />)
            : paths.length === 0
              ? <EmptyState />
              : paths.map((path) => (
                  <tr
                    key={path._key}
                    onClick={() => onRowClick(path)}
                    className="hover:bg-slate-800/40 cursor-pointer transition-colors"
                  >
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2 max-w-sm">
                        <span className="text-slate-200 font-medium truncate" title={path.entry_point_name}>
                          {path.entry_point_name || path.entry_point_type}
                        </span>
                        <ArrowRight size={13} className="text-slate-500 shrink-0" />
                        <span className="text-slate-400 truncate" title={path.target_name}>
                          {path.target_name || path.target_type}
                        </span>
                      </div>
                      <div className="text-slate-600 text-xs mt-0.5">{path.rule}</div>
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${SEV_CLASSES[path.severity]}`}>
                        {path.severity}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <RiskScoreBar score={path.risk_score} severity={path.severity} />
                    </td>
                    <td className="px-4 py-3 text-slate-400 font-mono text-xs">{path.hops}</td>
                    <td className="px-4 py-3">
                      {path.is_toxic_combination && (
                        <span className="inline-flex items-center gap-1 bg-red-900/30 text-red-400 border border-red-800 px-2 py-0.5 rounded text-xs font-medium">
                          <Flame size={10} />
                          Toxic
                        </span>
                      )}
                    </td>
                    <td className="px-4 py-3 text-slate-500 text-xs">
                      {formatDistanceToNow(new Date(path.detected_at), { addSuffix: true })}
                    </td>
                  </tr>
                ))}
        </tbody>
      </table>

      {/* Pagination */}
      <div className="flex items-center justify-between px-4 py-3 border-t border-slate-800 bg-slate-900/50">
        <span className="text-slate-500 text-xs">{paths.length} paths</span>
        <div className="flex items-center gap-2">
          <button
            onClick={onPrev}
            disabled={!hasPrev}
            className="p-1.5 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            aria-label="Previous page"
          >
            <ChevronLeft size={16} />
          </button>
          <button
            onClick={onNext}
            disabled={!nextCursor}
            className="p-1.5 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
            aria-label="Next page"
          >
            <ChevronRight size={16} />
          </button>
        </div>
      </div>
    </div>
  )
}
