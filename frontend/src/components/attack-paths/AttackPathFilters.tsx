'use client'

import type { AttackPathFilters, AttackPathSeverity } from '@/lib/types'

interface Props {
  filters: AttackPathFilters
  onChange: (next: AttackPathFilters) => void
}

const SEVERITIES: AttackPathSeverity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
const PROVIDERS = ['aws', 'azure', 'gcp', 'k8s']

export function AttackPathFilterBar({ filters, onChange }: Props) {
  const selectClass =
    'bg-slate-800 border border-slate-700 text-slate-200 text-sm rounded-md px-3 py-1.5 focus:outline-none focus:ring-1 focus:ring-orange-500'

  return (
    <div className="flex items-center gap-3 flex-wrap">
      <select
        value={filters.severity ?? ''}
        onChange={(e) => onChange({ ...filters, severity: (e.target.value as AttackPathSeverity) || undefined, cursor: undefined })}
        className={selectClass}
        aria-label="Filter by severity"
      >
        <option value="">All severities</option>
        {SEVERITIES.map((s) => (
          <option key={s} value={s}>{s}</option>
        ))}
      </select>

      <select
        value={filters.provider ?? ''}
        onChange={(e) => onChange({ ...filters, provider: e.target.value || undefined, cursor: undefined })}
        className={selectClass}
        aria-label="Filter by provider"
      >
        <option value="">All providers</option>
        {PROVIDERS.map((p) => (
          <option key={p} value={p}>{p.toUpperCase()}</option>
        ))}
      </select>

      <label className="flex items-center gap-2 cursor-pointer select-none">
        <input
          type="checkbox"
          checked={filters.is_toxic_combination === true}
          onChange={(e) =>
            onChange({ ...filters, is_toxic_combination: e.target.checked ? true : undefined, cursor: undefined })
          }
          className="w-4 h-4 rounded accent-orange-500"
        />
        <span className="text-slate-300 text-sm">Toxic combinations only</span>
      </label>

      {(filters.severity || filters.provider || filters.is_toxic_combination) && (
        <button
          onClick={() => onChange({ limit: filters.limit })}
          className="text-slate-500 hover:text-slate-300 text-sm transition-colors"
        >
          Clear filters
        </button>
      )}
    </div>
  )
}
