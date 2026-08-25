import { Badge, type BadgeVariant } from '@/components/ui/Badge'
import type { ComplianceTopAsset } from '@/lib/types'

function providerVariant(p: string): BadgeVariant {
  const map: Record<string, BadgeVariant> = {
    aws: 'provider-aws',
    azure: 'provider-azure',
    gcp: 'provider-gcp',
    k8s: 'provider-k8s',
  }
  return map[p] ?? 'default'
}

interface Top10AssetsProps {
  items: ComplianceTopAsset[]
  scopeLabel: string
  onSelect: (item: ComplianceTopAsset) => void
}

// One column of the side-by-side Framework/Global comparison in the parent page — see
// Top10Findings for why there's no "Top 10 Assets" heading here.
export function Top10Assets({ items, scopeLabel, onSelect }: Top10AssetsProps) {
  return (
    <div data-testid={`top10-assets-${scopeLabel.toLowerCase().replace(/\s+/g, '-')}`}>
      <span className="block text-xs font-medium text-slate-400 truncate mb-2">{scopeLabel}</span>
      {items.length === 0 ? (
        <p className="text-slate-600 text-xs px-3 py-2">No failing findings.</p>
      ) : (
        <div className="space-y-2">
          {items.map((item, i) => (
            <button
              key={item.resource_id}
              data-testid={`top10-asset-item-${item.resource_id}`}
              type="button"
              onClick={() => onSelect(item)}
              className="w-full flex items-center gap-3 p-3 bg-slate-900 border border-slate-800 rounded hover:border-slate-700 transition-colors text-left"
            >
              <span className="text-slate-600 text-xs font-mono w-4">{i + 1}</span>
              <Badge variant={providerVariant(item.provider)}>{item.provider.toUpperCase()}</Badge>
              <div className="flex-1 min-w-0">
                <div className="text-slate-300 text-sm truncate font-mono">{item.resource_id}</div>
                <div className="text-slate-600 text-xs truncate">
                  {item.resource_type}
                  {item.region ? ` · ${item.region}` : ''} · {item.account_id}
                </div>
              </div>
              <span className="text-slate-500 text-sm font-mono flex-shrink-0">{item.count} findings</span>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}
