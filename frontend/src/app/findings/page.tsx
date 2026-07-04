'use client'
import { useCallback, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { FindingsTable } from '@/components/findings/FindingsTable'
import { FindingFilters } from '@/components/findings/FindingFilters'
import { ExportButton } from '@/components/findings/ExportButton'
import { FindingDetailPanel } from '@/components/findings/FindingDetailPanel'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { findingsApi } from '@/lib/api'
import type { Finding, FindingsFilter, SeverityLevel } from '@/lib/types'

const SEVERITY_ORDER: SeverityLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']

const DEFAULT_FILTERS: FindingsFilter = { limit: 50 }

export default function FindingsPage() {
  const [filters, setFilters] = useState<FindingsFilter>(DEFAULT_FILTERS)
  const [prevCursors, setPrevCursors] = useState<string[]>([])
  const [selectedKey, setSelectedKey] = useState<string | null>(null)

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['findings', filters],
    queryFn: () => findingsApi.list(filters).then((r) => r.data.data),
    placeholderData: (prev) => prev,
  })

  const findings = data?.items ?? []
  const nextCursor = data?.next_cursor ?? null

  // Severity counters from current page
  const severityCounts = findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] ?? 0) + 1
    return acc
  }, {})

  const handleFiltersChange = useCallback((next: FindingsFilter) => {
    setPrevCursors([])
    setFilters(next)
  }, [])

  const handleNext = () => {
    if (!nextCursor) return
    setPrevCursors((p) => [...p, filters.cursor ?? ''])
    setFilters((f) => ({ ...f, cursor: nextCursor }))
  }

  const handlePrev = () => {
    const prev = [...prevCursors]
    const cursor = prev.pop() || undefined
    setPrevCursors(prev)
    setFilters((f) => ({ ...f, cursor }))
  }

  const handleRowClick = (f: Finding) => setSelectedKey(f._key)

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200">
      <div className="max-w-screen-xl mx-auto px-6 py-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-6">
          <div>
            <h1 className="text-2xl font-bold text-slate-100">Findings</h1>
            <p className="text-slate-500 text-sm mt-1">CSPM and IaC security findings across all providers</p>
          </div>
          {/* Actions + severity summary chips */}
          <div className="flex items-center gap-4">
            <ExportButton filters={filters} />
          </div>
          <div className="flex gap-2">
            {SEVERITY_ORDER.filter((s) => severityCounts[s]).map((s) => (
              <button
                key={s}
                onClick={() => handleFiltersChange({ ...DEFAULT_FILTERS, severity: s })}
                className="flex items-center gap-1.5"
                aria-label={`Filter by ${s}`}
              >
                <SeverityBadge severity={s} />
                <span className="text-slate-400 text-sm font-mono">{severityCounts[s]}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Filters */}
        <div className="mb-6">
          <FindingFilters filters={filters} onChange={handleFiltersChange} />
        </div>

        {/* Table */}
        <FindingsTable
          findings={findings}
          loading={isLoading}
          nextCursor={nextCursor}
          prevCursors={prevCursors}
          onNext={handleNext}
          onPrev={handlePrev}
          onRowClick={handleRowClick}
        />
      </div>

      {/* Detail panel */}
      <FindingDetailPanel
        findingKey={selectedKey}
        onClose={() => setSelectedKey(null)}
        onMuted={() => refetch()}
      />
    </div>
  )
}
