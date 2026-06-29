'use client'
import { useState, useCallback } from 'react'
import { useQuery } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import { RefreshCw } from 'lucide-react'
import { ProviderTabs } from '@/components/inventory/ProviderTabs'
import { Filters } from '@/components/inventory/Filters'
import { DataTable } from '@/components/inventory/DataTable'
import { DetailPanel } from '@/components/inventory/DetailPanel'
import { inventoryApi } from '@/lib/api'
import type { ResourceSummary, ResourceDetail, InventoryFilters } from '@/lib/types'

const DEFAULT_FILTERS: InventoryFilters = {
  limit: 50,
  offset: 0,
}

export default function InventoryPage() {
  const [filters, setFilters] = useState<InventoryFilters>(DEFAULT_FILTERS)
  const [activeProvider, setActiveProvider] = useState('all')
  const [selected, setSelected] = useState<ResourceDetail | null>(null)

  const { data: listData, isLoading: listLoading } = useQuery({
    queryKey: ['inventory', filters],
    queryFn: () => inventoryApi.list(filters).then((r) => r.data),
  })

  const { data: statsData } = useQuery({
    queryKey: ['inventory-stats'],
    queryFn: () => inventoryApi.stats().then((r) => r.data),
    staleTime: 30_000,
  })

  const handleProviderChange = useCallback(
    (provider: string) => {
      setActiveProvider(provider)
      setFilters((f) => ({
        ...f,
        provider: provider === 'all' ? undefined : provider,
        offset: 0,
      }))
    },
    [],
  )

  const handleSearch = useCallback((search: string) => {
    setFilters((f) => ({ ...f, search: search || undefined, offset: 0 }))
  }, [])

  const handleResourceType = useCallback((type: string) => {
    setFilters((f) => ({ ...f, resource_type: type || undefined, offset: 0 }))
  }, [])

  const handleRegion = useCallback((region: string) => {
    setFilters((f) => ({ ...f, region: region || undefined, offset: 0 }))
  }, [])

  const handleRowClick = useCallback(async (resource: ResourceSummary) => {
    try {
      const detail = await inventoryApi.detail(resource.key)
      setSelected(detail.data.data)
    } catch {
      setSelected(resource as ResourceDetail)
    }
  }, [])

  const stats = statsData?.data
  const counts = stats?.by_provider ?? {}
  const lastScanned = stats?.last_discovery_at
    ? formatDistanceToNow(new Date(stats.last_discovery_at), { addSuffix: true })
    : null

  return (
    <div className="min-h-screen bg-slate-950">
      <header className="border-b border-slate-800 bg-slate-900 px-6 py-4">
        <div className="flex items-center justify-between max-w-screen-2xl mx-auto">
          <div>
            <h1 className="text-xl font-bold text-slate-100">Inventory</h1>
            {lastScanned && (
              <p className="text-xs text-slate-500 mt-0.5 flex items-center gap-1">
                <RefreshCw className="w-3 h-3" />
                Last updated {lastScanned}
              </p>
            )}
          </div>
          <div className="flex items-center gap-3 text-sm text-slate-400">
            {stats && (
              <>
                <span>{(stats.by_status['active'] ?? 0).toLocaleString()} resources</span>
                <span className="text-slate-700">·</span>
                <span>{stats.identity_count.toLocaleString()} identities</span>
              </>
            )}
          </div>
        </div>
      </header>

      <main className="max-w-screen-2xl mx-auto px-6 py-6 space-y-4">
        <ProviderTabs
          active={activeProvider}
          counts={counts}
          onChange={handleProviderChange}
        />

        <Filters
          onSearch={handleSearch}
          onResourceType={handleResourceType}
          onRegion={handleRegion}
        />

        <DataTable
          resources={listData?.data ?? []}
          total={listData?.meta.total ?? 0}
          limit={filters.limit}
          offset={filters.offset}
          loading={listLoading}
          onPageChange={(offset) => setFilters((f) => ({ ...f, offset }))}
          onRowClick={handleRowClick}
        />
      </main>

      <DetailPanel resource={selected} onClose={() => setSelected(null)} />
    </div>
  )
}
