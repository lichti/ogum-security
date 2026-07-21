'use client'

import { X, ExternalLink } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { inventoryApi } from '@/lib/api'

interface NodeDetailPanelProps {
  nodeId: string | null
  onClose: () => void
}

export function NodeDetailPanel({ nodeId, onClose }: NodeDetailPanelProps) {
  // nodeId is the ArangoDB _id (e.g. "resources/abc123") — extract key and collection
  const [collection, key] = nodeId?.split('/') ?? []
  const isResource = collection === 'resources' || collection === 'data_assets'

  const { data: resource, isLoading } = useQuery({
    queryKey: ['node-detail', key],
    queryFn: () => inventoryApi.detail(key).then((r) => r.data.data),
    enabled: isResource && !!key,
    staleTime: 60_000,
  })

  if (!nodeId) return null

  return (
    <>
      {/* Backdrop */}
      <div className="fixed inset-0 z-40" onClick={onClose} />

      {/* Panel */}
      <div id="node-detail-panel" className="fixed top-0 right-0 h-full w-96 z-50 bg-slate-900 border-l border-slate-800 flex flex-col shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800">
          <h2 className="text-slate-200 font-semibold text-sm">Node Details</h2>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-slate-200 transition-colors p-1 -mr-1"
          >
            <X size={18} />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto px-5 py-4">
          {/* Node ID */}
          <div className="mb-5">
            <p className="text-slate-500 text-[11px] uppercase tracking-wide mb-1">Node ID</p>
            <p className="text-slate-300 text-xs font-mono break-all">{nodeId}</p>
          </div>

          {!isResource && (
            <div id="node-detail-unsupported" className="rounded-lg bg-slate-800/60 border border-slate-700 px-4 py-3 text-slate-400 text-xs">
              Detail view for <span className="text-slate-300 font-medium">{collection}</span> nodes
              is not yet available. Select a resource or data asset node.
            </div>
          )}

          {isResource && isLoading && (
            <div className="flex flex-col gap-3">
              {[...Array(4)].map((_, i) => (
                <div key={i} className="h-10 bg-slate-800 rounded animate-pulse" />
              ))}
            </div>
          )}

          {resource && (
            <div className="flex flex-col gap-5">
              {/* Resource overview */}
              <div id="node-detail-resource-overview" className="rounded-lg bg-slate-800/60 border border-slate-700 px-4 py-3 flex flex-col gap-2">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <p className="text-slate-200 text-sm font-semibold">{resource.name}</p>
                    <p className="text-slate-500 text-xs">{resource.resource_type}</p>
                  </div>
                  <span
                    className={`text-[11px] font-semibold px-2 py-0.5 rounded shrink-0 ${
                      resource.status === 'active'
                        ? 'bg-green-500/15 text-green-400'
                        : 'bg-slate-700 text-slate-400'
                    }`}
                  >
                    {resource.status}
                  </span>
                </div>
              </div>

              {/* Metadata grid */}
              <div id="node-detail-metadata">
                <p className="text-slate-500 text-[11px] uppercase tracking-wide mb-2">Metadata</p>
                <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
                  {[
                    ['Provider', resource.provider],
                    ['Region', resource.region ?? '—'],
                    ['Account', resource.account_id ?? '—'],
                    ['Public', resource.is_public ? 'Yes' : 'No'],
                  ].map(([label, value]) => (
                    <div key={label}>
                      <dt className="text-slate-600 text-[10px] uppercase tracking-wide">{label}</dt>
                      <dd className="text-slate-300 text-xs mt-0.5 truncate">{value}</dd>
                    </div>
                  ))}
                </dl>
              </div>

              {/* Resource ID */}
              <div>
                <p className="text-slate-500 text-[11px] uppercase tracking-wide mb-1">Resource ID</p>
                <p className="text-slate-400 text-[11px] font-mono break-all leading-relaxed">
                  {resource.resource_id}
                </p>
              </div>

              {/* Relationships */}
              {resource.edges && resource.edges.length > 0 && (
                <div id="node-detail-relationships">
                  <p className="text-slate-500 text-[11px] uppercase tracking-wide mb-2">
                    Relationships ({resource.edges.length})
                  </p>
                  <div className="flex flex-col gap-1.5">
                    {resource.edges.slice(0, 8).map((edge, i) => (
                      <div
                        key={i}
                        data-testid={`node-detail-edge-${edge.direction}-${edge.edge_type}-${edge.peer_collection}-${edge.peer_key}`}
                        className="flex items-center gap-2 text-xs text-slate-400 bg-slate-800/60 border border-slate-700/60 rounded px-3 py-1.5"
                      >
                        <span className="text-slate-600 text-[10px] font-mono shrink-0">
                          {edge.direction === 'outbound' ? '→' : '←'}
                        </span>
                        <span className="text-orange-400/80 text-[10px] shrink-0">{edge.edge_type}</span>
                        <span className="truncate text-[11px]">{edge.peer_type ?? edge.peer_collection}</span>
                      </div>
                    ))}
                    {resource.edges.length > 8 && (
                      <p className="text-slate-600 text-[10px] px-1">
                        +{resource.edges.length - 8} more
                      </p>
                    )}
                  </div>
                </div>
              )}

              {/* Link to full detail */}
              <a
                href={`/inventory?key=${key}`}
                className="flex items-center gap-1.5 text-orange-400 hover:text-orange-300 text-xs transition-colors"
              >
                <ExternalLink size={12} />
                View full resource detail
              </a>
            </div>
          )}
        </div>
      </div>
    </>
  )
}
