'use client'
import { useEffect, useState } from 'react'
import Link from 'next/link'
import { X } from 'lucide-react'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { findingsApi } from '@/lib/api'
import type { Finding } from '@/lib/types'

export type DrilldownMode = { kind: 'check'; checkId: string } | { kind: 'resource'; resourceId: string }

interface ComplianceDrilldownPanelProps {
  title: string
  subtitle?: string
  mode: DrilldownMode
  framework?: string
  onClose: () => void
}

const PAGE_SIZE = 20

// Shared by both Top 10 Findings ("which assets are affected by this check", mode
// "check") and Top 10 Assets ("which findings affect this asset", mode "resource") —
// same shape of request (one dimension fixed, FAIL-only, optionally scoped to the
// framework column that was clicked), just emphasising the other dimension in each row.
export function ComplianceDrilldownPanel({ title, subtitle, mode, framework, onClose }: ComplianceDrilldownPanelProps) {
  const [items, setItems] = useState<Finding[]>([])
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const fetchPage = (cursor?: string) =>
    findingsApi.list({
      status: ['FAIL'],
      check_id: mode.kind === 'check' ? mode.checkId : undefined,
      resource_id: mode.kind === 'resource' ? mode.resourceId : undefined,
      framework: framework ? [framework] : undefined,
      limit: PAGE_SIZE,
      cursor,
    })

  useEffect(() => {
    setItems([])
    setNextCursor(null)
    setLoading(true)
    fetchPage()
      .then((r) => {
        setItems(r.data.data.items)
        setNextCursor(r.data.data.next_cursor)
      })
      .finally(() => setLoading(false))
    // mode/framework identify the request; fetchPage is rebuilt from them each render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode.kind, mode.kind === 'check' ? mode.checkId : mode.resourceId, framework])

  const loadMore = () => {
    if (!nextCursor) return
    setLoading(true)
    fetchPage(nextCursor)
      .then((r) => {
        setItems((prev) => [...prev, ...r.data.data.items])
        setNextCursor(r.data.data.next_cursor)
      })
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])

  return (
    <>
      <div className="fixed inset-0 z-40" onClick={onClose} aria-hidden="true" />
      <div
        className="fixed top-0 right-0 h-full w-[440px] bg-slate-900 border-l border-slate-700 shadow-2xl z-50 overflow-y-auto"
        data-testid="compliance-drilldown-panel"
      >
        <div id="compliance-drilldown-header" className="flex items-start justify-between p-4 border-b border-slate-700 sticky top-0 bg-slate-900">
          <div className="flex-1 min-w-0 pr-2">
            <h2 className="text-slate-200 font-semibold text-sm leading-snug">{title}</h2>
            {subtitle && <p className="text-slate-500 text-xs font-mono mt-0.5 truncate">{subtitle}</p>}
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 flex-shrink-0"
            aria-label="Close panel"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div id="compliance-drilldown-results" className="p-4 space-y-2">
          {loading && items.length === 0 ? (
            Array.from({ length: 5 }).map((_, i) => <div key={i} className="h-14 bg-slate-800 rounded animate-pulse" />)
          ) : items.length === 0 ? (
            <p className="text-slate-600 text-sm">No matching findings.</p>
          ) : (
            <>
              {items.map((f) => (
                <Link
                  key={f._key}
                  href={`/findings?finding=${encodeURIComponent(f._key)}`}
                  data-testid={`compliance-drilldown-item-${f._key}`}
                  className="flex items-center gap-3 p-3 bg-slate-950 border border-slate-800 rounded hover:border-slate-700 transition-colors"
                >
                  <SeverityBadge severity={f.severity} />
                  <div className="flex-1 min-w-0">
                    {mode.kind === 'check' ? (
                      <>
                        <div className="text-slate-300 text-sm truncate font-mono">{f.resource_id}</div>
                        <div className="text-slate-600 text-xs truncate">
                          {f.resource_type}
                          {f.region ? ` · ${f.region}` : ''}
                        </div>
                      </>
                    ) : (
                      <>
                        <div className="text-slate-300 text-sm truncate">{f.title}</div>
                        <div className="text-slate-600 text-xs font-mono truncate">{f.check_id}</div>
                      </>
                    )}
                  </div>
                </Link>
              ))}
              {nextCursor && (
                <button
                  type="button"
                  onClick={loadMore}
                  disabled={loading}
                  className="w-full py-2 text-xs text-orange-400 hover:text-orange-300 disabled:opacity-50"
                >
                  {loading ? 'Loading…' : 'Load more'}
                </button>
              )}
            </>
          )}
        </div>
      </div>
    </>
  )
}
