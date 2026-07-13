'use client'
import { useQuery } from '@tanstack/react-query'
import { inventoryApi } from '@/lib/api'
import type { NarrativeDeepLink } from '@/lib/types'

interface ResourceNarrativeProps {
  resourceKey: string
  onNavigate: (tab: string, subtab?: string | null) => void
}

export function ResourceNarrative({ resourceKey, onNavigate }: ResourceNarrativeProps) {
  const { data, isLoading } = useQuery({
    queryKey: ['inventory-summary', resourceKey],
    queryFn: () => inventoryApi.summary(resourceKey).then((r) => r.data.data),
    staleTime: 60_000,
  })

  if (isLoading) {
    return <div className="h-4 w-3/4 bg-slate-800 rounded animate-pulse" data-testid="narrative-loading" />
  }
  if (!data) return null

  return (
    <div className="space-y-2">
      <p className="text-slate-300 text-sm leading-relaxed">{data.narrative}</p>
      {data.deep_links.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {data.deep_links.map((link: NarrativeDeepLink) => (
            <button
              key={`${link.tab}-${link.subtab}`}
              type="button"
              onClick={() => onNavigate(link.tab, link.subtab)}
              className="px-2 py-1 rounded bg-slate-800 border border-slate-700 text-orange-400 text-xs hover:border-orange-500"
            >
              {link.count} {link.label} →
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
