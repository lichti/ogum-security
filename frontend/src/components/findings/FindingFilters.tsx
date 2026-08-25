'use client'
import { Search, X } from 'lucide-react'
import { useCallback, useEffect, useRef, useState } from 'react'
import { MultiSelectFilter } from '@/components/ui/MultiSelectFilter'
import type { FindingsFilter, FindingStatus, FindingSource, SeverityLevel } from '@/lib/types'

const SEVERITIES: SeverityLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']
const STATUSES: FindingStatus[] = ['FAIL', 'PASS', 'MUTED', 'ACCEPTED']
const PROVIDERS = ['aws', 'azure', 'gcp', 'k8s']
// Raw Prowler framework slugs (must match the "framework_mapping" prefixes actually
// stored on findings — see backend/app/services/compliance_frameworks.py). The
// previous list ("CIS-AWS-2.0", "PCI_DSS", "NIST_800_53"...) never matched any real
// data, so selecting a framework here always silently returned zero results.
const FRAMEWORKS = ['CIS-7.0', 'PCI-4.0', 'SOC2', 'ISO27001-2022', 'NIST-800-53-Revision-5', 'HIPAA', 'GDPR']
const SOURCES: FindingSource[] = ['cspm', 'iac']

function toOptions(values: string[]): { value: string; label: string }[] {
  return values.map((v) => ({ value: v, label: v }))
}

const SEVERITY_OPTIONS = toOptions(SEVERITIES)
const STATUS_OPTIONS = toOptions(STATUSES)
const PROVIDER_OPTIONS = PROVIDERS.map((v) => ({ value: v, label: v.toUpperCase() }))
const FRAMEWORK_OPTIONS = toOptions(FRAMEWORKS)
const SOURCE_OPTIONS = toOptions(SOURCES)

interface FindingFiltersProps {
  filters: FindingsFilter
  onChange: (filters: FindingsFilter) => void
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

  const hasActiveFilters =
    !!q ||
    !!filters.severity?.length ||
    !!filters.status?.length ||
    !!filters.provider?.length ||
    !!filters.framework?.length ||
    !!filters.source?.length

  const clearAll = () => {
    onChange({
      ...filters,
      severity: undefined,
      status: undefined,
      provider: undefined,
      framework: undefined,
      source: undefined,
      q: undefined,
      cursor: undefined,
    })
    setQ('')
  }

  return (
    <div id="finding-filters" className="flex flex-wrap gap-2 items-center">
      <div className="relative">
        <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
        <input
          id="finding-filters-search"
          type="text"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search findings…"
          className="bg-slate-800 border border-slate-700 rounded pl-8 pr-3 py-1.5 text-sm text-slate-300 placeholder-slate-600 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500/30 w-52"
          aria-label="Search findings"
        />
      </div>

      <MultiSelectFilter
        label="Severities"
        options={SEVERITY_OPTIONS}
        selected={filters.severity ?? []}
        onChange={(v) => update({ severity: (v as SeverityLevel[]).length ? (v as SeverityLevel[]) : undefined })}
      />
      <MultiSelectFilter
        label="Statuses"
        options={STATUS_OPTIONS}
        selected={filters.status ?? []}
        onChange={(v) => update({ status: (v as FindingStatus[]).length ? (v as FindingStatus[]) : undefined })}
      />
      <MultiSelectFilter
        label="Providers"
        options={PROVIDER_OPTIONS}
        selected={filters.provider ?? []}
        onChange={(v) => update({ provider: v.length ? v : undefined })}
      />
      <MultiSelectFilter
        label="Frameworks"
        options={FRAMEWORK_OPTIONS}
        selected={filters.framework ?? []}
        onChange={(v) => update({ framework: v.length ? v : undefined })}
      />
      <MultiSelectFilter
        label="Sources"
        options={SOURCE_OPTIONS}
        selected={filters.source ?? []}
        onChange={(v) => update({ source: (v as FindingSource[]).length ? (v as FindingSource[]) : undefined })}
      />

      {hasActiveFilters && (
        <button
          id="finding-filters-clear-button"
          onClick={clearAll}
          className="flex items-center gap-1 text-slate-500 hover:text-slate-300 text-sm transition-colors"
        >
          <X className="w-3.5 h-3.5" />
          Clear filters
        </button>
      )}
    </div>
  )
}
