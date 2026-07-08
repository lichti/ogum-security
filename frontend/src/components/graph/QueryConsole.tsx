'use client'

import { useState, useRef } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { X, Play, BookmarkPlus, Trash2, ChevronDown, ChevronUp } from 'lucide-react'
import { graphApi } from '@/lib/api'
import type { AqlResult, SavedQuery } from '@/lib/types'

interface QueryConsoleProps {
  onClose: () => void
}

const STARTER_QUERIES: { label: string; query: string }[] = [
  {
    label: 'All resources by provider',
    query: 'FOR r IN resources\n  FILTER r.tenant_id == @tenant_id\n  COLLECT provider = r.provider WITH COUNT INTO cnt\n  RETURN {provider, cnt}',
  },
  {
    label: 'Crown Jewels',
    query: 'FOR r IN resources\n  FILTER r.tenant_id == @tenant_id AND r.is_crown_jewel == true\n  RETURN {name: r.name, type: r.resource_type, provider: r.provider}',
  },
  {
    label: 'High-risk identities',
    query: 'FOR i IN identities\n  FILTER i.tenant_id == @tenant_id AND i.has_admin_policy == true\n  SORT i.risk_score DESC\n  LIMIT 20\n  RETURN {name: i.name, type: i.identity_type, risk_score: i.risk_score}',
  },
  {
    label: 'Public attack paths',
    query: 'FOR ap IN attack_paths\n  FILTER ap.tenant_id == @tenant_id AND ap.severity IN ["CRITICAL", "HIGH"]\n  SORT ap.risk_score DESC\n  LIMIT 10\n  RETURN {rule: ap.rule, severity: ap.severity, score: ap.risk_score}',
  },
]

function ResultTable({ result }: { result: AqlResult }) {
  if (result.rows.length === 0) {
    return <p className="text-slate-500 text-xs py-4 text-center">Query returned no results.</p>
  }

  const first = result.rows[0]
  const isObject = first !== null && typeof first === 'object' && !Array.isArray(first)
  const columns = isObject ? Object.keys(first as Record<string, unknown>) : ['value']

  return (
    <div className="overflow-x-auto">
      {result.truncated && (
        <p className="text-orange-400 text-[11px] px-1 mb-2">
          Results truncated to 200 rows.
        </p>
      )}
      <table className="w-full text-xs">
        <thead>
          <tr className="border-b border-slate-700">
            {columns.map((col) => (
              <th key={col} className="px-3 py-2 text-left text-slate-400 font-medium uppercase tracking-wide text-[10px]">
                {col}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800">
          {result.rows.map((row, i) => (
            <tr key={i} className="hover:bg-slate-800/40">
              {columns.map((col) => {
                const val = isObject ? (row as Record<string, unknown>)[col] : row
                return (
                  <td key={col} className="px-3 py-2 text-slate-300 font-mono truncate max-w-[240px]">
                    {val === null ? <span className="text-slate-600">null</span> : JSON.stringify(val)}
                  </td>
                )
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <p className="text-slate-600 text-[10px] px-1 pt-2">
        {result.count} row{result.count !== 1 ? 's' : ''}
        {result.execution_ms !== null && ` · ${result.execution_ms}ms`}
      </p>
    </div>
  )
}

export function QueryConsole({ onClose }: QueryConsoleProps) {
  const [query, setQuery] = useState(STARTER_QUERIES[0].query)
  const [result, setResult] = useState<AqlResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [showSaved, setShowSaved] = useState(false)
  const [saveDialogOpen, setSaveDialogOpen] = useState(false)
  const [saveName, setSaveName] = useState('')
  const qc = useQueryClient()

  const { data: savedQueriesData } = useQuery({
    queryKey: ['saved-queries'],
    queryFn: () => graphApi.listSavedQueries().then((r) => r.data.data),
    staleTime: 30_000,
  })
  const savedQueries: SavedQuery[] = savedQueriesData ?? []

  const runMutation = useMutation({
    mutationFn: () => graphApi.executeAql(query).then((r) => r.data.data),
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

  const saveMutation = useMutation({
    mutationFn: () => graphApi.saveQuery(saveName.trim(), query).then((r) => r.data.data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['saved-queries'] })
      setSaveDialogOpen(false)
      setSaveName('')
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (key: string) => graphApi.deleteQuery(key),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['saved-queries'] }),
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-slate-900 border border-slate-700 rounded-xl shadow-2xl w-full max-w-4xl mx-4 flex flex-col max-h-[85vh]">
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-slate-800 shrink-0">
          <div>
            <h2 className="text-slate-100 font-semibold text-sm">AQL Console</h2>
            <p className="text-slate-500 text-[11px] mt-0.5">Read-only · Results capped at 200 rows · Use @tenant_id in queries</p>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-200 transition-colors p-1 -mr-1">
            <X size={18} />
          </button>
        </div>

        <div className="flex-1 flex flex-col gap-0 overflow-hidden">
          {/* Starter + Saved query bar */}
          <div className="shrink-0 flex items-center gap-2 px-5 py-3 border-b border-slate-800 flex-wrap">
            <span className="text-slate-500 text-[11px]">Templates:</span>
            {STARTER_QUERIES.map((sq) => (
              <button
                key={sq.label}
                onClick={() => setQuery(sq.query)}
                className="text-[11px] px-2.5 py-1 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
              >
                {sq.label}
              </button>
            ))}
            {savedQueries.length > 0 && (
              <button
                onClick={() => setShowSaved((v) => !v)}
                className="ml-auto flex items-center gap-1 text-[11px] text-slate-400 hover:text-slate-200 transition-colors"
              >
                Saved ({savedQueries.length})
                {showSaved ? <ChevronUp size={12} /> : <ChevronDown size={12} />}
              </button>
            )}
          </div>

          {/* Saved queries dropdown */}
          {showSaved && savedQueries.length > 0 && (
            <div className="shrink-0 px-5 py-2 border-b border-slate-800 flex flex-wrap gap-2">
              {savedQueries.map((sq) => (
                <div key={sq.key} className="flex items-center gap-1">
                  <button
                    onClick={() => { setQuery(sq.query); setShowSaved(false) }}
                    className="text-[11px] px-2.5 py-1 rounded bg-orange-900/30 hover:bg-orange-900/50 text-orange-300 border border-orange-800/50 transition-colors"
                  >
                    {sq.name}
                  </button>
                  <button
                    onClick={() => deleteMutation.mutate(sq.key)}
                    className="p-1 text-slate-600 hover:text-red-400 transition-colors"
                    title="Delete saved query"
                  >
                    <Trash2 size={11} />
                  </button>
                </div>
              ))}
            </div>
          )}

          {/* Query editor */}
          <div className="shrink-0 px-5 py-3 border-b border-slate-800">
            <textarea
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="w-full h-36 bg-slate-950 border border-slate-700 rounded-lg px-4 py-3 text-slate-200 font-mono text-xs resize-none focus:outline-none focus:border-orange-500/50 focus:ring-1 focus:ring-orange-500/20"
              placeholder="FOR r IN resources FILTER r.tenant_id == @tenant_id RETURN r"
              spellCheck={false}
            />
            <div className="flex items-center gap-2 mt-2">
              <button
                onClick={() => runMutation.mutate()}
                disabled={runMutation.isPending || !query.trim()}
                className="flex items-center gap-1.5 px-4 py-2 rounded-lg bg-orange-600 hover:bg-orange-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-xs font-medium transition-colors"
              >
                <Play size={12} />
                {runMutation.isPending ? 'Running...' : 'Run Query'}
              </button>
              <button
                onClick={() => setSaveDialogOpen(true)}
                disabled={!query.trim()}
                className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-300 text-xs border border-slate-700 transition-colors"
              >
                <BookmarkPlus size={12} />
                Save
              </button>
            </div>
          </div>

          {/* Save dialog */}
          {saveDialogOpen && (
            <div className="shrink-0 px-5 py-3 border-b border-slate-800 bg-slate-800/40">
              <div className="flex items-center gap-2">
                <input
                  autoFocus
                  value={saveName}
                  onChange={(e) => setSaveName(e.target.value)}
                  placeholder="Query name…"
                  className="flex-1 bg-slate-950 border border-slate-700 rounded px-3 py-1.5 text-slate-200 text-xs focus:outline-none focus:border-orange-500/50"
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && saveName.trim()) saveMutation.mutate()
                    if (e.key === 'Escape') setSaveDialogOpen(false)
                  }}
                />
                <button
                  onClick={() => saveMutation.mutate()}
                  disabled={!saveName.trim() || saveMutation.isPending}
                  className="px-3 py-1.5 rounded bg-orange-600 hover:bg-orange-500 disabled:opacity-50 text-white text-xs font-medium transition-colors"
                >
                  {saveMutation.isPending ? 'Saving…' : 'Save'}
                </button>
                <button
                  onClick={() => setSaveDialogOpen(false)}
                  className="px-3 py-1.5 rounded bg-slate-700 hover:bg-slate-600 text-slate-300 text-xs transition-colors"
                >
                  Cancel
                </button>
              </div>
            </div>
          )}

          {/* Results */}
          <div className="flex-1 overflow-y-auto px-5 py-4">
            {error && (
              <div className="bg-red-900/20 border border-red-800/50 rounded-lg px-4 py-3 text-red-400 text-xs font-mono whitespace-pre-wrap">
                {error}
              </div>
            )}
            {result && !error && <ResultTable result={result} />}
            {!result && !error && (
              <p className="text-slate-600 text-xs text-center py-8">
                Run a query to see results here.
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
