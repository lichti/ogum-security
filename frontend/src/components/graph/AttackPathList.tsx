'use client'

import { useMemo, useState } from 'react'
import { ChevronDown, ChevronRight, Flame } from 'lucide-react'
import { CATEGORY_LABELS, type ResourceCategory } from '@/lib/inventoryCategories'
import type { AttackPath, AttackPathSeverity } from '@/lib/types'

export type AttackPathViewMode = 'paths' | 'alerts' | 'assets'

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

function humanizeRule(rule: string): string {
  if (/^TC-\d+$/i.test(rule)) return rule.toUpperCase()
  return rule
    .split('_')
    .map((word) => word.charAt(0).toUpperCase() + word.slice(1))
    .join(' ')
}

/** Second-level grouping key/label — same underlying path list, different lens per US-14.12. */
function secondLevelOf(path: AttackPath, viewMode: AttackPathViewMode): { key: string; label: string } {
  if (viewMode === 'alerts') {
    const key = path.rule || 'unknown'
    return { key, label: humanizeRule(key) }
  }
  // target_asset_category is computed server-side (US-14.11); undefined only for
  // paths detected before this sprint's merge — bucketed honestly, not guessed.
  const category = (path.target_asset_category ?? 'other') as ResourceCategory
  return { key: category, label: CATEGORY_LABELS[category] ?? CATEGORY_LABELS.other }
}

interface AttackPathListProps {
  paths: AttackPath[]
  selectedKey: string | null
  loading?: boolean
  viewMode?: AttackPathViewMode
  onSelect: (path: AttackPath) => void
}

export function AttackPathList({ paths, selectedKey, loading, viewMode = 'paths', onSelect }: AttackPathListProps) {
  const [collapsed, setCollapsed] = useState<Set<string>>(new Set())

  const toggle = (key: string) => {
    setCollapsed((prev) => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  const tree = useMemo(() => {
    const bySeverity = SEVERITY_ORDER.reduce<Record<AttackPathSeverity, AttackPath[]>>(
      (acc, sev) => {
        acc[sev] = paths.filter((p) => p.severity === sev)
        return acc
      },
      { CRITICAL: [], HIGH: [], MEDIUM: [], LOW: [] },
    )

    return SEVERITY_ORDER.map((sev) => {
      const group = bySeverity[sev]
      const subgroups = new Map<string, { label: string; items: AttackPath[] }>()
      for (const path of group) {
        const { key, label } = secondLevelOf(path, viewMode)
        if (!subgroups.has(key)) subgroups.set(key, { label, items: [] })
        subgroups.get(key)!.items.push(path)
      }
      return { severity: sev, total: group.length, subgroups: Array.from(subgroups.entries()) }
    })
  }, [paths, viewMode])

  if (loading) {
    return (
      <div id="attack-path-list-loading" className="w-64 shrink-0 flex flex-col gap-2 p-1">
        {[...Array(6)].map((_, i) => (
          <div key={i} className="h-16 bg-slate-800/70 rounded-lg animate-pulse" />
        ))}
      </div>
    )
  }

  if (paths.length === 0) {
    return (
      <div id="attack-path-list-empty" className="w-64 shrink-0 flex flex-col items-center justify-center text-center gap-2 p-6">
        <p className="text-slate-400 text-sm font-medium">No attack paths</p>
        <p className="text-slate-600 text-xs">Run a CSPM scan to detect paths</p>
      </div>
    )
  }

  return (
    <div id="attack-path-list" className="w-64 shrink-0 overflow-y-auto flex flex-col gap-5 pr-1">
      {tree.map(({ severity, total, subgroups }) => {
        if (total === 0) return null
        const styles = SEVERITY_STYLES[severity]
        const sevCollapsed = collapsed.has(severity)
        return (
          <div key={severity} data-testid={`attack-path-list-severity-group-${severity}`}>
            <button
              type="button"
              onClick={() => toggle(severity)}
              className="w-full flex items-center gap-1.5 px-1 mb-2"
            >
              {sevCollapsed ? (
                <ChevronRight size={12} className="text-slate-600 shrink-0" />
              ) : (
                <ChevronDown size={12} className="text-slate-600 shrink-0" />
              )}
              <span className={`w-2 h-2 rounded-full ${styles.dot} shrink-0`} />
              <span
                className={`text-[11px] font-semibold uppercase tracking-wide ${styles.header}`}
              >
                {styles.label}
              </span>
              <span className="text-slate-600 text-[11px] ml-auto tabular-nums">{total}</span>
            </button>

            {!sevCollapsed &&
              subgroups.map(([subKey, { label, items }]) => {
                const subgroupKey = `${severity}::${subKey}`
                const subCollapsed = collapsed.has(subgroupKey)
                return (
                  <div key={subgroupKey} data-testid={`attack-path-list-subgroup-${subgroupKey}`} className="mb-2 pl-3.5">
                    <button
                      type="button"
                      onClick={() => toggle(subgroupKey)}
                      className="w-full flex items-center gap-1.5 px-1 mb-1"
                    >
                      {subCollapsed ? (
                        <ChevronRight size={10} className="text-slate-700 shrink-0" />
                      ) : (
                        <ChevronDown size={10} className="text-slate-700 shrink-0" />
                      )}
                      <span className="text-[10px] font-medium text-slate-500 uppercase tracking-wide truncate">
                        {label}
                      </span>
                      <span className="text-slate-700 text-[10px] ml-auto tabular-nums">{items.length}</span>
                    </button>

                    {!subCollapsed && (
                      <div className="flex flex-col gap-1">
                        {items.map((path) => (
                          <button
                            key={path._key}
                            onClick={() => onSelect(path)}
                            data-testid={`attack-path-row-${path._key}`}
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
                    )}
                  </div>
                )
              })}
          </div>
        )
      })}
    </div>
  )
}
