'use client'
import { useCallback, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import { RefreshCw } from 'lucide-react'
import { InventorySummary } from '@/components/inventory/InventorySummary'
import { Filters } from '@/components/inventory/Filters'
import { DataTable } from '@/components/inventory/DataTable'
import { DetailPanel } from '@/components/inventory/DetailPanel'
import { inventoryApi } from '@/lib/api'
import { aggregateByCategory, CATEGORY_LABELS, CATEGORY_ORDER, resourceTypesForCategories } from '@/lib/inventoryCategories'
import type { ResourceSummary, ResourceDetail, InventoryFilters } from '@/lib/types'

const EMPTY_CATEGORY_STATS = CATEGORY_ORDER.reduce(
  (acc, cat) => ({ ...acc, [cat]: 0 }),
  {} as Record<string, number>,
)

const LIMIT = 50

function toggleValue(list: string[], value: string): string[] {
  return list.includes(value) ? list.filter((v) => v !== value) : [...list, value]
}

export default function InventoryPage() {
  const [providers, setProviders] = useState<string[]>([])
  const [categories, setCategories] = useState<string[]>([])
  const [regions, setRegions] = useState<string[]>([])
  const [accountIds, setAccountIds] = useState<string[]>([])
  const [search, setSearch] = useState('')
  const [offset, setOffset] = useState(0)
  const [selected, setSelected] = useState<ResourceDetail | null>(null)

  const { data: statsData } = useQuery({
    queryKey: ['inventory-stats'],
    queryFn: () => inventoryApi.stats().then((r) => r.data),
    staleTime: 30_000,
  })

  const stats = statsData?.data
  const byCategory = useMemo(
    () => (stats ? aggregateByCategory(stats.by_resource_type) : EMPTY_CATEGORY_STATS),
    [stats],
  )
  const resourceTypes = useMemo(
    () => (stats ? resourceTypesForCategories(categories, stats.by_resource_type) : []),
    [categories, stats],
  )

  const filters: InventoryFilters = useMemo(
    () => ({
      providers,
      resourceTypes,
      regions,
      accountIds,
      search: search || undefined,
      limit: LIMIT,
      offset,
    }),
    [providers, resourceTypes, regions, accountIds, search, offset],
  )

  const { data: listData, isLoading: listLoading } = useQuery({
    queryKey: ['inventory', filters],
    queryFn: () => inventoryApi.list(filters).then((r) => r.data),
  })

  const providerOptions = useMemo(
    () =>
      Object.entries(stats?.by_provider ?? {})
        .map(([value, count]) => ({ value, label: value.toUpperCase(), count }))
        .sort((a, b) => b.count - a.count),
    [stats],
  )
  const categoryOptions = useMemo(
    () => CATEGORY_ORDER.map((cat) => ({ value: cat, label: CATEGORY_LABELS[cat], count: byCategory[cat] ?? 0 })),
    [byCategory],
  )
  const regionOptions = useMemo(
    () =>
      Object.entries(stats?.by_region ?? {})
        .map(([value, count]) => ({ value, label: value, count }))
        .sort((a, b) => b.count - a.count),
    [stats],
  )
  const accountOptions = useMemo(
    () =>
      Object.entries(stats?.by_account_id ?? {})
        .map(([value, count]) => ({ value, label: value, count }))
        .sort((a, b) => b.count - a.count),
    [stats],
  )

  const handleProviderToggle = useCallback((provider: string) => {
    setProviders((prev) => toggleValue(prev, provider))
    setOffset(0)
  }, [])

  const handleCategoryToggle = useCallback((category: string) => {
    setCategories((prev) => toggleValue(prev, category))
    setOffset(0)
  }, [])

  const handleSearch = useCallback((value: string) => {
    setSearch(value)
    setOffset(0)
  }, [])

  const handleClearFilters = useCallback(() => {
    setProviders([])
    setCategories([])
    setRegions([])
    setAccountIds([])
    setSearch('')
    setOffset(0)
  }, [])

  const handleRowClick = useCallback(async (resource: ResourceSummary) => {
    try {
      const detail = await inventoryApi.detail(resource.key)
      setSelected(detail.data.data)
    } catch {
      setSelected(resource as ResourceDetail)
    }
  }, [])

  const lastScanned = stats?.last_discovery_at
    ? formatDistanceToNow(new Date(stats.last_discovery_at), { addSuffix: true })
    : null

  const isPristineEmpty =
    !listLoading &&
    (listData?.meta.total ?? 0) === 0 &&
    !search &&
    providers.length === 0 &&
    categories.length === 0 &&
    regions.length === 0 &&
    accountIds.length === 0

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
        <InventorySummary
          byProvider={stats?.by_provider ?? {}}
          byCategory={byCategory}
          selectedProviders={providers}
          selectedCategories={categories}
          onProviderClick={handleProviderToggle}
          onCategoryClick={handleCategoryToggle}
        />

        <Filters
          search={search}
          onSearch={handleSearch}
          providerOptions={providerOptions}
          selectedProviders={providers}
          onProvidersChange={(v) => {
            setProviders(v)
            setOffset(0)
          }}
          categoryOptions={categoryOptions}
          selectedCategories={categories}
          onCategoriesChange={(v) => {
            setCategories(v)
            setOffset(0)
          }}
          regionOptions={regionOptions}
          selectedRegions={regions}
          onRegionsChange={(v) => {
            setRegions(v)
            setOffset(0)
          }}
          accountOptions={accountOptions}
          selectedAccounts={accountIds}
          onAccountsChange={(v) => {
            setAccountIds(v)
            setOffset(0)
          }}
          onClear={handleClearFilters}
        />

        {isPristineEmpty ? (
          <div className="text-center py-20">
            <div className="text-slate-600 text-5xl mb-4">☁</div>
            <h2 className="text-xl font-semibold text-slate-300 mb-2">No cloud accounts connected</h2>
            <p className="text-slate-500 mb-6">Connect your first account to start discovering resources.</p>
            <a
              href="/providers/new"
              className="inline-flex items-center gap-2 px-4 py-2 bg-orange-500 hover:bg-orange-600 text-white text-sm font-medium rounded-lg transition-colors"
            >
              Connect Account
            </a>
          </div>
        ) : (
          <DataTable
            resources={listData?.data ?? []}
            total={listData?.meta.total ?? 0}
            limit={LIMIT}
            offset={offset}
            loading={listLoading}
            onPageChange={setOffset}
            onRowClick={handleRowClick}
          />
        )}
      </main>

      <DetailPanel key={selected?.key} resource={selected} onClose={() => setSelected(null)} />
    </div>
  )
}
