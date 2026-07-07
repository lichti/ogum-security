'use client'

import { Flame } from 'lucide-react'
import type { AttackPath, AttackPathSeverity } from '@/lib/types'

const SEVERITY_ORDER: AttackPathSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']

const SEVERITY_STYLES: Record<
  AttackPathSeverity,
  { label: string; dot: string; header: string }
> = {
  CRITICAL: { label: 'Critical', dot: 'bg-red-500', header: 'text-red-400' },
  HIGH: { label: 'High', dot: 'bg-orange-500', header: 'text-orange-400' },
  MEDIUM: { label: 'Medium', dot: 'bg-yellow-500', header: 'text-yellow-400' },
  LOW: { label: 'Low', dot: 'bg-blue-500', header: 'text-blue-400' },
}

interface AttackPathListProps {
  paths: AttackPath[]
  selectedKey: string | null
  loading?: boolean
  onSelect: (path: AttackPath) => void
}

export function AttackPathList({ paths, selectedKey, loading, onSelect }: AttackPathListProps) {
  if (loading) {
    return (
      <div className="w-64 shrink-0 flex flex-col gap-2 p-1">
        {[...Array(6)].map((_, i) => (
          <div key={i} className="h-16 bg-slate-800/70 rounded-lg animate-pulse" />
        ))}
      </div>
    )
  }

  if (paths.length === 0) {
    return (
      <div className="w-64 shrink-0 flex flex-col items-center justify-center text-center gap-2 p-6">
        <p className="text-slate-400 text-sm font-medium">No attack paths</p>
        <p className="text-slate-600 text-xs">Run a CSPM scan to detect paths</p>
      </div>
    )
  }

  const grouped = SEVERITY_ORDER.reduce<Record<AttackPathSeverity, AttackPath[]>>(
    (acc, sev) => {
      acc[sev] = paths.filter((p) => p.severity === sev)
      return acc
    },
    { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] },
  )

  return (
    <div className="w-64 shrink-0 overflow-y-auto flex flex-col gap-5 pr-1">
      {SEVERITY_ORDER.map((sev) => {
        const group = grouped[sev]
        if (group.length === 0) return null
        const styles = SEVERITY_STYLES[sev]
        return (
          <div key={sev}>
            <div className="flex items-center gap-1.5 px-1 mb-2">
              <span className={`w-2 h-2 rounded-full ${styles.dot} shrink-0`} />
              <span
                className={`text-[11px] font-semibold uppercase tracking-wide ${styles.header}`}
              >
                {styles.label}
              </span>
              <span className="text-slate-600 text-[11px] ml-auto tabular-nums">{group.length}</span>
            </div>
            <div className="flex flex-col gap-1">
              {group.map((path) => (
                <button
                  key={path._key}
                  onClick={() => onSelect(path)}
                  className={`w-full text-left rounded-lg px-3 py-2.5 border transition-all ${
                    selectedKey === path._key
                      ? 'bg-orange-500/10 border-orange-500/50 shadow-sm shadow-orange-900/20'
                      : 'bg-slate-900 border-slate-800 hover:border-slate-600 hover:bg-slate-800/80'
                  }`}
                >
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-slate-300 text-xs font-semibold tabular-nums">
                      {path.risk_score.toFixed(0)}
                      <span className="text-slate-600 font-normal">/100</span>
                    </span>
                    {path.is_toxic_combination && (
                      <span className="flex items-center gap-0.5 text-orange-400 text-[10px]">
                        <Flame size={10} />
                        Toxic
                      </span>
                    )}
                  </div>
                  <p className="text-slate-400 text-[11px] truncate leading-tight">
                    {path.entry_point_name} → {path.target_name}
                  </p>
                  <p className="text-slate-600 text-[10px] mt-0.5">
                    {path.hops} hop{path.hops !== 1 ? 's' : ''} · {path.rule}
                  </p>
                </button>
              ))}
            </div>
          </div>
        )
      })}
    </div>
  )
}
