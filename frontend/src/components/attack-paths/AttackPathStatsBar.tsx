import { CATEGORY_LABELS } from '@/lib/inventoryCategories'
import type { AttackPathCrownJewelReason, AttackPathStats, AttackPathTargetAssetCategory } from '@/lib/types'

interface Props {
  stats: AttackPathStats
  onSeverityClick: (severity: string) => void
  onAssetCategoryClick?: (category: AttackPathTargetAssetCategory) => void
  onCrownJewelReasonClick?: (reason: AttackPathCrownJewelReason) => void
}

const SEVERITY_COLORS: Record<string, string> = {
  CRITICAL: 'bg-red-900/40 text-red-400 border border-red-800 hover:bg-red-900/60',
  HIGH: 'bg-orange-900/40 text-orange-400 border border-orange-800 hover:bg-orange-900/60',
  MEDIUM: 'bg-yellow-900/40 text-yellow-400 border border-yellow-800 hover:bg-yellow-900/60',
  LOW: 'bg-blue-900/40 text-blue-400 border border-blue-800 hover:bg-blue-900/60',
}

const CROWN_JEWEL_REASON_LABELS: Record<AttackPathCrownJewelReason, string> = {
  internet_facing: 'Internet Facing',
  stores_sensitive_data: 'Stores Sensitive Data',
  high_privilege_identity: 'High-Privilege Identity',
  manually_flagged: 'Manually Flagged',
}

export function AttackPathStatsBar({ stats, onSeverityClick, onAssetCategoryClick, onCrownJewelReasonClick }: Props) {
  const severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const
  const categoryEntries = Object.entries(stats.by_target_asset_category ?? {}) as [
    AttackPathTargetAssetCategory,
    number,
  ][]
  const reasonEntries = Object.entries(stats.by_target_crown_jewel_reason ?? {}) as [
    AttackPathCrownJewelReason,
    number,
  ][]

  return (
    <div className="flex flex-col gap-2">
      <div className="flex items-center gap-3 flex-wrap">
        <div className="bg-slate-800 rounded-lg px-4 py-2.5 flex items-center gap-2">
          <span className="text-slate-400 text-xs">Total</span>
          <span className="text-slate-100 font-bold text-lg">{stats.total}</span>
        </div>

        {severities.map((sev) => (
          <button
            key={sev}
            onClick={() => onSeverityClick(sev)}
            className={`rounded-lg px-3 py-2.5 flex items-center gap-2 transition-colors cursor-pointer ${SEVERITY_COLORS[sev]}`}
            aria-label={`Filter by ${sev}`}
          >
            <span className="text-xs font-medium">{sev}</span>
            <span className="font-bold text-sm">{stats.by_severity[sev] ?? 0}</span>
          </button>
        ))}

        {stats.new_24h > 0 && (
          <div className="bg-slate-800 rounded-lg px-3 py-2.5 flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-orange-500 animate-pulse" />
            <span className="text-slate-400 text-xs">New (24h)</span>
            <span className="text-orange-400 font-bold text-sm">{stats.new_24h}</span>
          </div>
        )}
      </div>

      {(categoryEntries.length > 0 || reasonEntries.length > 0) && (
        <div className="flex items-center gap-2 flex-wrap text-[11px]">
          {categoryEntries.length > 0 && (
            <>
              <span className="text-slate-600 uppercase tracking-wide">Target Asset Category</span>
              {categoryEntries.map(([category, count]) => (
                <button
                  key={category}
                  onClick={() => onAssetCategoryClick?.(category)}
                  aria-label={`Filter by target asset category ${category}`}
                  className="rounded px-2 py-1 bg-slate-800 border border-slate-700 text-slate-400 hover:border-orange-500 hover:text-orange-400 transition-colors"
                >
                  {CATEGORY_LABELS[category] ?? category} <span className="font-semibold">{count}</span>
                </button>
              ))}
            </>
          )}

          {reasonEntries.length > 0 && (
            <>
              <span className="text-slate-600 uppercase tracking-wide ml-2">Target Crown Jewel Reason</span>
              {reasonEntries.map(([reason, count]) => (
                <button
                  key={reason}
                  onClick={() => onCrownJewelReasonClick?.(reason)}
                  aria-label={`Filter by target crown jewel reason ${reason}`}
                  className="rounded px-2 py-1 bg-slate-800 border border-slate-700 text-slate-400 hover:border-orange-500 hover:text-orange-400 transition-colors"
                >
                  {CROWN_JEWEL_REASON_LABELS[reason] ?? reason} <span className="font-semibold">{count}</span>
                </button>
              ))}
            </>
          )}
        </div>
      )}
    </div>
  )
}
