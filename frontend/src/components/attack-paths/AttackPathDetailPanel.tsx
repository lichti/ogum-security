'use client'

import { useQuery } from '@tanstack/react-query'
import { formatDistanceToNow } from 'date-fns'
import { X, ArrowRight, Flame, Network, AlertTriangle } from 'lucide-react'
import { attackPathsApi } from '@/lib/api'
import type { AttackPathSeverity } from '@/lib/types'

interface Props {
  pathKey: string | null
  onClose: () => void
}

const SEV_CLASSES: Record<AttackPathSeverity, string> = {
  CRITICAL: 'bg-red-900/30 text-red-400 border border-red-800',
  HIGH: 'bg-orange-900/30 text-orange-400 border border-orange-800',
  MEDIUM: 'bg-yellow-900/30 text-yellow-400 border border-yellow-800',
  LOW: 'bg-blue-900/30 text-blue-400 border border-blue-800',
}

const RISK_COLOR: Record<AttackPathSeverity, string> = {
  CRITICAL: 'text-red-400',
  HIGH: 'text-orange-400',
  MEDIUM: 'text-yellow-400',
  LOW: 'text-blue-400',
}

function NodeRow({ node }: { node: Record<string, unknown> }) {
  const name = String(node.name ?? node._key ?? node._id ?? '—')
  const type = String(node.resource_type ?? node.type ?? '—')
  const collection = String(node._id ?? '').split('/')[0] ?? ''

  return (
    <div className="flex items-start gap-3 py-2 border-b border-slate-800 last:border-0">
      <Network size={14} className="text-slate-500 mt-0.5 shrink-0" />
      <div className="min-w-0">
        <div className="text-slate-200 text-sm font-medium truncate">{name}</div>
        <div className="text-slate-500 text-xs mt-0.5">{type} · {collection}</div>
      </div>
      {!!node.is_public && (
        <span className="ml-auto shrink-0 text-xs text-orange-400 bg-orange-900/30 border border-orange-800 px-1.5 py-0.5 rounded">
          Public
        </span>
      )}
    </div>
  )
}

function FindingRow({ finding }: { finding: Record<string, unknown> }) {
  const severity = String(finding.severity ?? 'LOW') as AttackPathSeverity
  const sev = SEV_CLASSES[severity] ?? SEV_CLASSES.LOW
  return (
    <div className="flex items-start gap-3 py-2 border-b border-slate-800 last:border-0">
      <AlertTriangle size={14} className="text-slate-500 mt-0.5 shrink-0" />
      <div className="min-w-0 flex-1">
        <div className="text-slate-200 text-sm truncate">{String(finding.title ?? finding.check_id ?? '—')}</div>
        <div className="text-slate-500 text-xs mt-0.5">{String(finding.resource_id ?? '—')}</div>
      </div>
      <span className={`shrink-0 ml-auto text-xs px-1.5 py-0.5 rounded ${sev}`}>{severity}</span>
    </div>
  )
}

export function AttackPathDetailPanel({ pathKey, onClose }: Props) {
  const { data, isLoading } = useQuery({
    queryKey: ['attack-path-detail', pathKey],
    queryFn: () => attackPathsApi.get(pathKey!).then((r) => r.data.data),
    enabled: !!pathKey,
  })

  if (!pathKey) return null

  return (
    <>
      <div
        className="fixed inset-0 bg-black/40 z-40"
        onClick={onClose}
        aria-label="Close panel"
      />
      <aside
        role="dialog"
        aria-label="Attack path details"
        className="fixed top-0 right-0 h-full w-full max-w-lg bg-slate-900 border-l border-slate-800 z-50 flex flex-col overflow-hidden shadow-2xl"
      >
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800 shrink-0">
          <h2 className="text-slate-100 font-semibold text-base">Attack Path Detail</h2>
          <button
            onClick={onClose}
            className="p-1.5 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-800 transition-colors"
            aria-label="Close"
          >
            <X size={18} />
          </button>
        </div>

        <div className="flex-1 overflow-y-auto">
          {isLoading && (
            <div className="space-y-3 p-5">
              {Array.from({ length: 4 }).map((_, i) => (
                <div key={i} className="h-10 bg-slate-800 rounded animate-pulse" />
              ))}
            </div>
          )}

          {data && (() => {
            const { path, nodes, findings } = data
            const sevClass = SEV_CLASSES[path.severity] ?? SEV_CLASSES.LOW
            const riskColor = RISK_COLOR[path.severity] ?? 'text-slate-400'

            return (
              <div className="p-5 space-y-6">
                {/* Overview */}
                <div className="space-y-3">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`text-xs px-2 py-0.5 rounded font-medium border ${sevClass}`}>
                      {path.severity}
                    </span>
                    <span className={`font-bold text-lg ${riskColor}`}>
                      {path.risk_score.toFixed(0)}
                    </span>
                    <span className="text-slate-500 text-sm">risk score</span>
                    {path.is_toxic_combination && (
                      <span className="flex items-center gap-1 text-xs bg-red-900/30 text-red-400 border border-red-800 px-2 py-0.5 rounded">
                        <Flame size={10} />
                        Toxic Combination
                      </span>
                    )}
                  </div>

                  <div className="bg-slate-800/60 rounded-lg p-3 text-xs font-mono text-slate-400">
                    {path.rule}
                  </div>

                  <div className="text-slate-500 text-xs">
                    Detected {formatDistanceToNow(new Date(path.detected_at), { addSuffix: true })} · {path.hops} hop{path.hops !== 1 ? 's' : ''}
                  </div>
                </div>

                {/* Entry point → Target */}
                <div>
                  <h3 className="text-slate-400 text-xs uppercase tracking-wider mb-3 font-medium">Path</h3>
                  <div className="flex items-center gap-2">
                    <div className="bg-slate-800 rounded-lg p-3 flex-1 min-w-0">
                      <div className="text-slate-500 text-xs mb-1">Entry point</div>
                      <div className="text-slate-200 font-medium text-sm truncate" title={path.entry_point_name}>
                        {path.entry_point_name || path.entry_point_id}
                      </div>
                      <div className="text-slate-500 text-xs mt-0.5">{path.entry_point_type}</div>
                    </div>
                    <ArrowRight size={16} className="text-orange-500 shrink-0" />
                    <div className="bg-slate-800 rounded-lg p-3 flex-1 min-w-0">
                      <div className="text-slate-500 text-xs mb-1">Target</div>
                      <div className="text-slate-200 font-medium text-sm truncate" title={path.target_name}>
                        {path.target_name || path.target_id}
                      </div>
                      <div className="text-slate-500 text-xs mt-0.5">{path.target_type}</div>
                    </div>
                  </div>
                </div>

                {/* Nodes in path */}
                {nodes.length > 0 && (
                  <div>
                    <h3 className="text-slate-400 text-xs uppercase tracking-wider mb-3 font-medium">
                      Path Nodes ({nodes.length})
                    </h3>
                    <div className="bg-slate-800/40 rounded-lg px-3">
                      {nodes.map((node, i) => (
                        <NodeRow key={i} node={node} />
                      ))}
                    </div>
                  </div>
                )}

                {/* Associated findings */}
                <div>
                  <h3 className="text-slate-400 text-xs uppercase tracking-wider mb-3 font-medium">
                    Associated Findings ({findings.length})
                  </h3>
                  {findings.length === 0 ? (
                    <p className="text-slate-600 text-sm">No findings linked to this path</p>
                  ) : (
                    <div className="bg-slate-800/40 rounded-lg px-3">
                      {findings.map((f, i) => (
                        <FindingRow key={i} finding={f} />
                      ))}
                    </div>
                  )}
                </div>

                {/* Technical IDs */}
                <div className="border-t border-slate-800 pt-4">
                  <div className="text-slate-600 text-xs font-mono space-y-1">
                    <div>Path ID: {path.path_id}</div>
                    <div>Status: {path.status}</div>
                  </div>
                </div>
              </div>
            )
          })()}
        </div>
      </aside>
    </>
  )
}
