'use client'
import { Search, X } from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import type { FindingsFilter, FindingStatus, FindingSource, SeverityLevel } from '@/lib/types'

const SEVERITIES: SeverityLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']
const STATUSES: FindingStatus[] = ['FAIL', 'PASS', 'MUTED', 'ACCEPTED']
const PROVIDERS = ['aws', 'azure', 'gcp', 'k8s']
const FRAMEWORKS = ['CIS-AWS-2.0', 'PCI_DSS', 'SOC2', 'ISO27001', 'NIST_800_53']
const SOURCES: FindingSource[] = ['cspm', 'iac']

interface FindingFiltersProps {
  filters: FindingsFilter
  onChange: (filters: FindingsFilter) => void
}

function Select({
  label,
  value,
  options,
  onChange,
}: {
  label: string
  value: string
  options: string[]
  onChange: (v: string) => void
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="bg-slate-800 border border-slate-700 rounded px-3 py-1.5 text-sm text-slate-300 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500/30"
      aria-label={label}
    >
      <option value="">{label}</option>
      {options.map((o) => (
        <option key={o} value={o}>
          {o}
        </option>
      ))}
    </select>
  )
}

export function FindingFilters({ filters, onChange }: FindingFiltersProps) {
  const [q, setQ] = useState(filters.q ?? '')
  const debounceRef = useRef<ReturnType<typeof setTimeout>>(null)

  const update = useCallback(
    (patch: Partial<FindingsFilter>) => {
      onChange({ ...filters, cursor: undefined, ...patch })
    },
    [filters, onChange],
  )

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => {
      if (q !== (filters.q ?? '')) update({ q: q || undefined })
    }, 300)
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current)
    }
  }, [q, filters.q, update])

  const activeFilters = [
    filters.severity && { key: 'severity', label: `Severity: ${filters.severity}` },
    filters.status && { key: 'status', label: `Status: ${filters.status}` },
    filters.provider && { key: 'provider', label: `Provider: ${filters.provider}` },
    filters.framework && { key: 'framework', label: `Framework: ${filters.framework}` },
    filters.source && { key: 'source', label: `Source: ${filters.source}` },
    filters.q && { key: 'q', label: `Search: ${filters.q}` },
  ].filter(Boolean) as { key: string; label: string }[]

  const clearFilter = (key: string) => {
    update({ [key]: undefined })
    if (key === 'q') setQ('')
  }

  const clearAll = () => {
    onChange({ ...filters, severity: undefined, status: undefined, provider: undefined, framework: undefined, source: undefined, q: undefined, cursor: undefined })
    setQ('')
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap gap-2 items-center">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
          <input
            type="text"
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search findings…"
            className="bg-slate-800 border border-slate-700 rounded pl-8 pr-3 py-1.5 text-sm text-slate-300 placeholder-slate-600 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500/30 w-52"
            aria-label="Search findings"
          />
        </div>
        <Select label="Severity" value={filters.severity ?? ''} options={SEVERITIES} onChange={(v) => update({ severity: (v as SeverityLevel) || undefined })} />
        <Select label="Status" value={filters.status ?? ''} options={STATUSES} onChange={(v) => update({ status: (v as FindingStatus) || undefined })} />
        <Select label="Provider" value={filters.provider ?? ''} options={PROVIDERS} onChange={(v) => update({ provider: v || undefined })} />
        <Select label="Framework" value={filters.framework ?? ''} options={FRAMEWORKS} onChange={(v) => update({ framework: v || undefined })} />
        <Select label="Source" value={filters.source ?? ''} options={SOURCES} onChange={(v) => update({ source: (v as FindingSource) || undefined })} />
      </div>

      {activeFilters.length > 0 && (
        <div className="flex flex-wrap gap-1.5 items-center">
          {activeFilters.map(({ key, label }) => (
            <span
              key={key}
              className="inline-flex items-center gap-1 px-2 py-0.5 bg-orange-500/10 border border-orange-500/30 rounded text-xs text-orange-400"
            >
              {label}
              <button onClick={() => clearFilter(key)} aria-label={`Remove ${key} filter`}>
                <X className="w-3 h-3 hover:text-orange-200" />
              </button>
            </span>
          ))}
          <button
            onClick={clearAll}
            className="text-xs text-slate-500 hover:text-slate-300 underline"
          >
            Clear all
          </button>
        </div>
      )}
    </div>
  )
}
