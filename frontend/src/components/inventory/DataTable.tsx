'use client'
import { ChevronLeft, ChevronRight, Globe, Lock } from 'lucide-react'
import { Badge, type BadgeVariant } from '@/components/ui/Badge'
import { RiskBadge } from '@/components/ui/RiskBadge'
import { Skeleton } from '@/components/ui/Skeleton'
import type { ResourceSummary } from '@/lib/types'

interface DataTableProps {
  resources: ResourceSummary[]
  total: number
  limit: number
  offset: number
  loading?: boolean
  onPageChange: (offset: number) => void
  onRowClick: (resource: ResourceSummary) => void
}

function providerVariant(p: string): BadgeVariant {
  const map: Record<string, BadgeVariant> = {
    aws: 'provider-aws',
    azure: 'provider-azure',
    gcp: 'provider-gcp',
    k8s: 'provider-k8s',
  }
  return map[p] ?? 'default'
}

export function DataTable({
  resources,
  total,
  limit,
  offset,
  loading,
  onPageChange,
  onRowClick,
}: DataTableProps) {
  const totalPages = Math.ceil(total / limit)
  const currentPage = Math.floor(offset / limit) + 1

  if (loading) {
    return (
      <div id="inventory-table-loading" className="space-y-2">
        {Array.from({ length: 8 }).map((_, i) => (
          <Skeleton key={i} className="h-12 w-full" />
        ))}
      </div>
    )
  }

  if (resources.length === 0) {
    return (
      <div id="inventory-table-empty" className="text-center py-16 text-slate-500">
        <p className="text-lg">No resources found</p>
        <p className="text-sm mt-1">Try adjusting your filters or connect a cloud account.</p>
      </div>
    )
  }

  return (
    <div>
      <table id="inventory-table" className="w-full text-sm">
        <thead>
          <tr className="text-left text-slate-500 border-b border-slate-800">
            <th className="pb-3 pr-4 font-medium">Provider</th>
            <th className="pb-3 pr-4 font-medium">Name / ID</th>
            <th className="pb-3 pr-4 font-medium">Type</th>
            <th className="pb-3 pr-4 font-medium">Account</th>
            <th className="pb-3 pr-4 font-medium">Region</th>
            <th className="pb-3 pr-4 font-medium">Status</th>
            <th className="pb-3 font-medium">Risk</th>
          </tr>
        </thead>
        <tbody>
          {resources.map((r) => (
            <tr
              key={r.key}
              data-testid={`inventory-table-row-${r.key}`}
              onClick={() => onRowClick(r)}
              className="border-b border-slate-800/50 hover:bg-slate-800/50 cursor-pointer transition-colors"
            >
              <td className="py-3 pr-4">
                <Badge variant={providerVariant(r.provider)}>{r.provider.toUpperCase()}</Badge>
              </td>
              <td className="py-3 pr-4">
                <div className="flex items-center gap-2">
                  {r.is_public ? (
                    <Globe className="w-3 h-3 text-orange-400 flex-shrink-0" aria-label="Public" />
                  ) : (
                    <Lock className="w-3 h-3 text-slate-600 flex-shrink-0" aria-label="Private" />
                  )}
                  <div>
                    <div className="text-slate-200 font-medium">{r.name}</div>
                    <div className="text-slate-500 text-xs">{r.resource_id}</div>
                  </div>
                </div>
              </td>
              <td className="py-3 pr-4 text-slate-400">{r.resource_type.replace(/_/g, ' ')}</td>
              <td className="py-3 pr-4 text-slate-500 font-mono text-xs">
                {r.account_id ?? '—'}
              </td>
              <td className="py-3 pr-4 text-slate-400">{r.region ?? '—'}</td>
              <td className="py-3 pr-4">
                <Badge variant={r.status === 'active' ? 'status-active' : 'status-deleted'}>
                  {r.status}
                </Badge>
              </td>
              <td className="py-3">
                <RiskBadge score={r.risk_score} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {totalPages > 1 && (
        <div id="inventory-table-pagination" className="flex items-center justify-between mt-4 text-sm text-slate-400">
          <span>
            Showing {offset + 1}–{Math.min(offset + limit, total)} of {total} resources
          </span>
          <div className="flex gap-2 items-center">
            <button
              onClick={() => onPageChange(Math.max(0, offset - limit))}
              disabled={currentPage === 1}
              className="p-1 rounded hover:bg-slate-800 disabled:opacity-30 disabled:cursor-not-allowed"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            <span>
              Page {currentPage} of {totalPages}
            </span>
            <button
              onClick={() => onPageChange(offset + limit)}
              disabled={currentPage === totalPages}
              className="p-1 rounded hover:bg-slate-800 disabled:opacity-30 disabled:cursor-not-allowed"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
