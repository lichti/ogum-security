import { SeverityBadge } from '@/components/ui/SeverityBadge'
import type { ComplianceSummary, SeverityLevel } from '@/lib/types'

interface TopFailingControlsProps {
  items: ComplianceSummary['top_failing']
  scopeLabel: string | null
}

export function TopFailingControls({ items, scopeLabel }: TopFailingControlsProps) {
  if (items.length === 0) return null

  return (
    <section>
      <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">
        Top Failing Controls
        {scopeLabel && <span className="normal-case font-normal text-slate-600"> — {scopeLabel}</span>}
      </h2>
      <div className="space-y-2">
        {items.map((item, i) => (
          <div key={item.check_id} className="flex items-center gap-3 p-3 bg-slate-900 border border-slate-800 rounded">
            <span className="text-slate-600 text-xs font-mono w-4">{i + 1}</span>
            <SeverityBadge severity={item.severity as SeverityLevel} />
            <div className="flex-1 min-w-0">
              <div className="text-slate-300 text-sm truncate">{item.title}</div>
              <div className="text-slate-600 text-xs font-mono">{item.check_id}</div>
            </div>
            <span className="text-slate-500 text-sm font-mono flex-shrink-0">{item.count}×</span>
          </div>
        ))}
      </div>
    </section>
  )
}
