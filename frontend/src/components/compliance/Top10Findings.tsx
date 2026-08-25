import { SeverityBadge } from '@/components/ui/SeverityBadge'
import type { ComplianceTopCheck } from '@/lib/types'

interface Top10FindingsProps {
  items: ComplianceTopCheck[]
  scopeLabel: string
  onSelect: (item: ComplianceTopCheck) => void
}

// One column of the side-by-side Framework/Global comparison in the parent page — no
// "Top 10 Findings" heading of its own, just the scope label and the list, so two
// instances read as one comparison rather than two separate widgets.
export function Top10Findings({ items, scopeLabel, onSelect }: Top10FindingsProps) {
  return (
    <div data-testid={`top10-findings-${scopeLabel.toLowerCase().replace(/\s+/g, '-')}`}>
      <span className="block text-xs font-medium text-slate-400 truncate mb-2">{scopeLabel}</span>
      {items.length === 0 ? (
        <p className="text-slate-600 text-xs px-3 py-2">No failing findings.</p>
      ) : (
        <div className="space-y-2">
          {items.map((item, i) => (
            <button
              key={item.check_id}
              data-testid={`top10-finding-item-${item.check_id}`}
              type="button"
              onClick={() => onSelect(item)}
              className="w-full flex items-center gap-3 p-3 bg-slate-900 border border-slate-800 rounded hover:border-slate-700 transition-colors text-left"
            >
              <span className="text-slate-600 text-xs font-mono w-4">{i + 1}</span>
              <SeverityBadge severity={item.severity} />
              <div className="flex-1 min-w-0">
                <div className="text-slate-300 text-sm truncate">{item.title}</div>
                <div className="text-slate-600 text-xs font-mono">{item.check_id}</div>
              </div>
              <span className="text-slate-500 text-sm font-mono flex-shrink-0">{item.count}×</span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
