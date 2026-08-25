'use client'

import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { ArrowRight, Search, X, AlertCircle } from 'lucide-react'
import { graphApi } from '@/lib/api'
import type { ShortestPathResult } from '@/lib/types'

interface PathfindingPanelProps {
  onClose: () => void
  prefilledFrom?: string
  prefilledTo?: string
}

function PathDisplay({ result }: { result: ShortestPathResult }) {
  if (!result.found) {
    return (
      <div className="flex items-center gap-2 text-slate-500 text-sm py-4">
        <AlertCircle size={16} />
        No path found between the two nodes.
      </div>
    )
  }

  return (
    <div id="pathfinding-result" className="flex flex-col gap-3">
      <div className="flex items-center gap-2 text-xs">
        <span className="text-slate-400 font-medium">Shortest path:</span>
        <span className="text-orange-400 font-mono">{result.hops} hop{result.hops !== 1 ? 's' : ''}</span>
      </div>

      {/* Path visualization */}
      <div className="flex flex-col gap-1.5">
        {result.vertices.map((vertex, i) => {
          const v = vertex as Record<string, unknown>
          const edgeAfter = result.edges[i] as Record<string, unknown> | undefined
          const label = (v.name ?? v.resource_type ?? v.identity_type ?? v._id ?? `Node ${i}`) as string
          const collection = (v._id as string | undefined)?.split('/')[0] ?? 'unknown'
          const nodeKey = (v._id as string | undefined) ?? `node-${i}`
          const isFirst = i === 0
          const isLast = i === result.vertices.length - 1

          return (
            <div key={i} data-testid={`pathfinding-result-node-${nodeKey}`}>
              <div
                className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-xs ${
                  isFirst
                    ? 'bg-red-900/20 border-red-800/50 text-red-300'
                    : isLast
                      ? 'bg-yellow-900/20 border-yellow-800/50 text-yellow-300'
                      : 'bg-slate-800/60 border-slate-700/60 text-slate-300'
                }`}
              >
                <span className="text-[10px] text-slate-500 font-mono shrink-0">{collection}</span>
                <span className="font-medium truncate">{label}</span>
                {isFirst && <span className="ml-auto text-[10px] text-red-400 shrink-0">entry</span>}
                {isLast && <span className="ml-auto text-[10px] text-yellow-400 shrink-0">target</span>}
              </div>
              {edgeAfter && (
                <div className="flex items-center gap-1.5 pl-4 py-1 text-[10px] text-slate-500">
                  <div className="w-3 border-l-2 border-slate-700 h-3" />
                  <span className="font-mono text-orange-400/70">
                    {(edgeAfter._type ?? edgeAfter.type ?? '→') as string}
                  </span>
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

export function PathfindingPanel({ onClose, prefilledFrom = '', prefilledTo = '' }: PathfindingPanelProps) {
  const [fromId, setFromId] = useState(prefilledFrom)
  const [toId, setToId] = useState(prefilledTo)
  const [result, setResult] = useState<ShortestPathResult | null>(null)
  const [error, setError] = useState<string | null>(null)

  const findMutation = useMutation({
    mutationFn: () => graphApi.shortestPath(fromId.trim(), toId.trim()).then((r) => r.data.data),
    onSuccess: (data) => {
      setResult(data)
      setError(null)
    },
    onError: (err: unknown) => {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? String(err)
      setError(msg)
      setResult(null)
    },
  })

  const canSearch = fromId.trim().length > 0 && toId.trim().length > 0

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div id="pathfinding-panel" className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl w-full max-w-xl mx-4 flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800">
          <div>
            <h2 className="text-slate-100 font-semibold text-sm">Pathfinding</h2>
            <p className="text-slate-500 text-[11px] mt-0.5">Find shortest path between two graph nodes</p>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-200 transition-colors p-1 -mr-1">
            <X size={18} />
          </button>
        </div>

        {/* Inputs */}
        <div id="pathfinding-form" className="px-5 py-4 flex flex-col gap-3 border-b border-slate-800">
          <div>
            <label className="text-slate-500 text-[11px] uppercase tracking-wide block mb-1">
              From (ArangoDB _id)
            </label>
            <input
              value={fromId}
              onChange={(e) => setFromId(e.target.value)}
              placeholder="resources/abc123"
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 font-mono text-xs focus:outline-none focus:border-orange-500/50 focus:ring-1 focus:ring-orange-500/20"
            />
          </div>
          <div className="flex items-center gap-2 text-slate-600">
            <div className="flex-1 h-px bg-slate-800" />
            <ArrowRight size={14} />
            <div className="flex-1 h-px bg-slate-800" />
          </div>
          <div>
            <label className="text-slate-500 text-[11px] uppercase tracking-wide block mb-1">
              To (ArangoDB _id)
            </label>
            <input
              value={toId}
              onChange={(e) => setToId(e.target.value)}
              placeholder="data_assets/def456"
              className="w-full bg-slate-950 border border-slate-700 rounded-lg px-3 py-2 text-slate-200 font-mono text-xs focus:outline-none focus:border-orange-500/50 focus:ring-1 focus:ring-orange-500/20"
            />
          </div>

          <button
            onClick={() => findMutation.mutate()}
            disabled={!canSearch || findMutation.isPending}
            className="flex items-center justify-center gap-1.5 px-4 py-2.5 rounded-lg bg-orange-600 hover:bg-orange-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium transition-colors"
          >
            <Search size={14} />
            {findMutation.isPending ? 'Searching…' : 'Find Path'}
          </button>
        </div>

        {/* Result */}
        <div id="pathfinding-results" className="px-5 py-4 max-h-96 overflow-y-auto">
          {error && (
            <div className="bg-red-900/20 border border-red-800/50 rounded-lg px-4 py-3 text-red-400 text-xs">
              {error}
            </div>
          )}
          {result && !error && <PathDisplay result={result} />}
          {!result && !error && (
            <p className="text-slate-600 text-xs text-center py-6">
              Enter node IDs above and click Find Path.
            </p>
          )}
        </div>
      </div>
    </div>
  )
}
