'use client'
import { Suspense, useCallback, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useSearchParams } from 'next/navigation'
import { FindingsTable } from '@/components/findings/FindingsTable'
import { FindingFilters } from '@/components/findings/FindingFilters'
import { FindingsSummary } from '@/components/findings/FindingsSummary'
import { ExportButton } from '@/components/findings/ExportButton'
import { FindingDetailPanel } from '@/components/findings/FindingDetailPanel'
import { findingsApi } from '@/lib/api'
import type { Finding, FindingsFilter } from '@/lib/types'

const DEFAULT_FILTERS: FindingsFilter = { limit: 50 }

function toggleValue<T extends string>(list: T[] | undefined, value: T): T[] {
  const current = list ?? []
  return current.includes(value) ? current.filter((v) => v !== value) : [...current, value]
}

export default function FindingsPage() {
  return (
    <Suspense fallback={null}>
      <FindingsPageContent />
    </Suspense>
  )
}

function FindingsPageContent() {
  // One-time initial filter from the URL (e.g. Compliance page links here with
  // ?framework=CIS-7.0). Deliberately not a full two-way URL sync — just enough for
  // deep links to pre-filter the page on first load. useSearchParams (not
  // window.location.search) is required here: this page is reached via a Next.js
  // client-side <Link> navigation from Compliance, and the router's parsed params are
  // the only reliably up-to-date source at that point.
  const searchParams = useSearchParams()
  const [filters, setFilters] = useState<FindingsFilter>(() => {
    const framework = searchParams.get('framework')
    return framework ? { ...DEFAULT_FILTERS, framework: [framework] } : DEFAULT_FILTERS
  })
  const [prevCursors, setPrevCursors] = useState<string[]>([])
  const [selectedKey, setSelectedKey] = useState<string | null>(null)

  const { data: statsData } = useQuery({
    queryKey: ['findings-stats'],
    queryFn: () => findingsApi.stats().then((r) => r.data),
    staleTime: 30_000,
  })

  const { data, isLoading, refetch } = useQuery({
    queryKey: ['findings', filters],
    queryFn: () => findingsApi.list(filters).then((r) => r.data.data),
    placeholderData: (prev) => prev,
  })

  const findings = data?.items ?? []
  const nextCursor = data?.next_cursor ?? null
  const stats = statsData?.data

  const handleFiltersChange = useCallback((next: FindingsFilter) => {
    setPrevCursors([])
    setFilters(next)
  }, [])

  const handleSeverityToggle = useCallback(
    (severity: string) => {
      handleFiltersChange({
        ...filters,
        severity: toggleValue(filters.severity, severity as Finding['severity']),
        cursor: undefined,
      })
    },
    [filters, handleFiltersChange],
  )

  const handleProviderToggle = useCallback(
    (provider: string) => {
      handleFiltersChange({ ...filters, provider: toggleValue(filters.provider, provider), cursor: undefined })
    },
    [filters, handleFiltersChange],
  )

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
        <div className="flex items-center justify-between mb-4">
          <div>
            <h1 className="text-2xl font-bold text-slate-100">Findings</h1>
            <p className="text-slate-500 text-sm mt-1">CSPM and IaC security findings across all providers</p>
          </div>
          <ExportButton filters={filters} />
        </div>

        {/* Summary */}
        <div className="mb-6">
          <FindingsSummary
            bySeverity={stats?.by_severity ?? {}}
            byProvider={stats?.by_provider ?? {}}
            selectedSeverities={filters.severity ?? []}
            selectedProviders={filters.provider ?? []}
            onSeverityClick={handleSeverityToggle}
            onProviderClick={handleProviderToggle}
          />
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
