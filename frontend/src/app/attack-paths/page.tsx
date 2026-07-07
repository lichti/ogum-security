'use client'

import { useCallback, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AttackPathStatsBar } from '@/components/attack-paths/AttackPathStatsBar'
import { AttackPathFilterBar } from '@/components/attack-paths/AttackPathFilters'
import { AttackPathsTable } from '@/components/attack-paths/AttackPathsTable'
import { AttackPathDetailPanel } from '@/components/attack-paths/AttackPathDetailPanel'
import { attackPathsApi } from '@/lib/api'
import type { AttackPath, AttackPathFilters, AttackPathSeverity } from '@/lib/types'

const DEFAULT_FILTERS: AttackPathFilters = { limit: 50 }

export default function AttackPathsPage() {
  const [filters, setFilters] = useState<AttackPathFilters>(DEFAULT_FILTERS)
  const [prevCursors, setPrevCursors] = useState<string[]>([])
  const [selectedKey, setSelectedKey] = useState<string | null>(null)

  const { data: statsData } = useQuery({
    queryKey: ['attack-paths-stats'],
    queryFn: () => attackPathsApi.stats().then((r) => r.data.data),
    staleTime: 30_000,
  })

  const { data: listData, isLoading } = useQuery({
    queryKey: ['attack-paths', filters],
    queryFn: () => attackPathsApi.list(filters).then((r) => r.data.data),
    placeholderData: (prev) => prev,
  })

  const paths = listData?.items ?? []
  const nextCursor = listData?.next_cursor ?? null

  const handleFiltersChange = useCallback((next: AttackPathFilters) => {
    setPrevCursors([])
    setFilters({ ...next, cursor: undefined })
  }, [])

  const handleSeverityClick = useCallback((severity: string) => {
    handleFiltersChange({ ...DEFAULT_FILTERS, severity: severity as AttackPathSeverity })
  }, [handleFiltersChange])

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

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200">
      <div className="max-w-screen-xl mx-auto px-6 py-8">
        {/* Header */}
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-slate-100">Attack Paths</h1>
          <p className="text-slate-500 text-sm mt-1">
            Contextual risk graph — paths from internet exposure to sensitive data
          </p>
        </div>

        {/* Stats bar */}
        {statsData && (
          <div className="mb-6">
            <AttackPathStatsBar stats={statsData} onSeverityClick={handleSeverityClick} />
          </div>
        )}

        {/* Filters */}
        <div className="mb-5">
          <AttackPathFilterBar filters={filters} onChange={handleFiltersChange} />
        </div>

        {/* Table */}
        <AttackPathsTable
          paths={paths}
          loading={isLoading}
          nextCursor={nextCursor}
          prevCursors={prevCursors}
          onNext={handleNext}
          onPrev={handlePrev}
          onRowClick={(p: AttackPath) => setSelectedKey(p._key)}
        />
      </div>

      {/* Detail panel */}
      <AttackPathDetailPanel
        pathKey={selectedKey}
        onClose={() => setSelectedKey(null)}
      />
    </div>
  )
}
