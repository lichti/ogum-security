'use client'
import { clsx } from 'clsx'
import { CATEGORY_LABELS, CATEGORY_ORDER, type ResourceCategory } from '@/lib/inventoryCategories'

const PROVIDERS = ['aws', 'azure', 'gcp', 'k8s'] as const

const PROVIDER_COLORS: Record<string, string> = {
  aws: 'bg-amber-950/40 text-amber-400 border-amber-800 hover:bg-amber-950/60',
  azure: 'bg-blue-950/40 text-blue-400 border-blue-800 hover:bg-blue-950/60',
  gcp: 'bg-sky-950/40 text-sky-400 border-sky-800 hover:bg-sky-950/60',
  k8s: 'bg-indigo-950/40 text-indigo-400 border-indigo-800 hover:bg-indigo-950/60',
}

interface InventorySummaryProps {
  byProvider: Record<string, number>
  byCategory: Record<ResourceCategory, number>
  selectedProviders: string[]
  selectedCategories: string[]
  onProviderClick: (provider: string) => void
  onCategoryClick: (category: string) => void
}

export function InventorySummary({
  byProvider,
  byCategory,
  selectedProviders,
  selectedCategories,
  onProviderClick,
  onCategoryClick,
}: InventorySummaryProps) {
  return (
    <div id="inventory-summary" className="space-y-2">
      <div id="inventory-summary-by-provider" className="flex items-center gap-2 flex-wrap">
        <span className="text-xs font-medium text-slate-500 w-24 flex-shrink-0">By provider</span>
        {PROVIDERS.map((p) => {
          const count = byProvider[p] ?? 0
          const active = selectedProviders.includes(p)
          return (
            <button
              key={p}
              data-testid={`inventory-summary-provider-${p}`}
              type="button"
              onClick={() => onProviderClick(p)}
              aria-label={`Filter by ${p.toUpperCase()}`}
              aria-pressed={active}
              className={clsx(
                'rounded-lg px-3 py-1.5 flex items-center gap-2 border transition-colors cursor-pointer text-xs',
                PROVIDER_COLORS[p],
                active && 'ring-1 ring-inset ring-current',
              )}
            >
              <span className="font-medium">{p.toUpperCase()}</span>
              <span className="font-bold">{count.toLocaleString()}</span>
            </button>
          )
        })}
      </div>

      <div id="inventory-summary-by-category" className="flex items-center gap-2 flex-wrap">
        <span className="text-xs font-medium text-slate-500 w-24 flex-shrink-0">By category</span>
        {CATEGORY_ORDER.map((cat) => {
          const count = byCategory[cat] ?? 0
          const active = selectedCategories.includes(cat)
          return (
            <button
              key={cat}
              data-testid={`inventory-summary-category-${cat}`}
              type="button"
              onClick={() => onCategoryClick(cat)}
              aria-label={`Filter by ${CATEGORY_LABELS[cat]}`}
              aria-pressed={active}
              className={clsx(
                'rounded-lg px-3 py-1.5 flex items-center gap-2 border transition-colors cursor-pointer text-xs',
                active
                  ? 'bg-orange-950/40 text-orange-300 border-orange-700 ring-1 ring-inset ring-orange-500'
                  : 'bg-slate-800/60 text-slate-400 border-slate-700 hover:bg-slate-800',
              )}
            >
              <span className="font-medium">{CATEGORY_LABELS[cat]}</span>
              <span className="font-bold">{count.toLocaleString()}</span>
            </button>
          )
        })}
      </div>
    </div>
  )
}
