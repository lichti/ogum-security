'use client'
import { useEffect, useState } from 'react'
import Link from 'next/link'
import { ChevronDown, ChevronRight, X } from 'lucide-react'
import { Badge, type BadgeVariant } from '@/components/ui/Badge'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { complianceApi, findingsApi } from '@/lib/api'
import type { ComplianceControlAsset, Finding, FindingStatus } from '@/lib/types'

interface ControlDrilldownPanelProps {
  frameworkId: string
  controlId: string
  title: string
  onClose: () => void
}

type StatusTab = 'all' | 'pass' | 'fail'

// "Pass" folds ACCEPTED in, same rule the By Control score itself uses — an
// accepted-risk finding satisfies the control, so it belongs in the Pass bucket
// here too. "All" omits the status filter entirely (also surfaces MUTED findings,
// which neither Pass nor Fail shows).
const STATUS_TAB_STATUSES: Record<StatusTab, FindingStatus[] | undefined> = {
  all: undefined,
  pass: ['PASS', 'ACCEPTED'],
  fail: ['FAIL'],
}

function findingStatusVariant(status: FindingStatus): BadgeVariant {
  if (status === 'FAIL') return 'severity-high'
  if (status === 'PASS' || status === 'ACCEPTED') return 'status-active'
  return 'default'
}

function StatusFilter({ value, onChange }: { value: StatusTab; onChange: (v: StatusTab) => void }) {
  const options: { key: StatusTab; label: string; activeClass: string }[] = [
    { key: 'all', label: 'All', activeClass: 'bg-slate-700 text-slate-200 border-slate-600' },
    { key: 'pass', label: 'Pass', activeClass: 'bg-green-950 text-green-400 border-green-800' },
    { key: 'fail', label: 'Fail', activeClass: 'bg-red-950 text-red-400 border-red-800' },
  ]
  return (
    <div className="flex gap-1.5" role="group" aria-label="Filter by status">
      {options.map((opt) => (
        <button
          key={opt.key}
          type="button"
          aria-pressed={value === opt.key}
          onClick={() => onChange(opt.key)}
          className={`px-2.5 py-1 rounded text-xs font-medium border transition-colors ${
            value === opt.key
              ? opt.activeClass
              : 'border-slate-800 text-slate-600 hover:text-slate-400 hover:border-slate-700'
          }`}
        >
          {opt.label}
        </button>
      ))}
    </div>
  )
}

const PAGE_SIZE = 20

function FindingRow({ finding }: { finding: Finding }) {
  return (
    <Link
      href={`/findings?finding=${encodeURIComponent(finding._key)}`}
      data-testid={`control-finding-item-${finding._key}`}
      className="flex items-center gap-3 p-3 bg-slate-950 border border-slate-800 rounded hover:border-slate-700 transition-colors"
    >
      <SeverityBadge severity={finding.severity} />
      <Badge variant={findingStatusVariant(finding.status)}>{finding.status}</Badge>
      <div className="flex-1 min-w-0">
        <div className="text-slate-300 text-sm truncate">{finding.title}</div>
        <div className="text-slate-600 text-xs font-mono truncate">
          {finding.resource_id}
          {finding.region ? ` · ${finding.region}` : ''}
        </div>
      </div>
    </Link>
  )
}

function FindingsList({
  items,
  loading,
  nextCursor,
  onLoadMore,
}: {
  items: Finding[]
  loading: boolean
  nextCursor: string | null
  onLoadMore: () => void
}) {
  if (loading && items.length === 0) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="h-14 bg-slate-800 rounded animate-pulse" />
        ))}
      </div>
    )
  }
  if (items.length === 0) {
    return <p className="text-slate-600 text-sm">No matching findings.</p>
  }
  return (
    <div className="space-y-2">
      {items.map((f) => (
        <FindingRow key={f._key} finding={f} />
      ))}
      {nextCursor && (
        <button
          type="button"
          onClick={onLoadMore}
          disabled={loading}
          className="w-full py-2 text-xs text-orange-400 hover:text-orange-300 disabled:opacity-50"
        >
          {loading ? 'Loading…' : 'Load more'}
        </button>
      )}
    </div>
  )
}

// The Findings tab — every finding for this control, filterable by status, each row
// showing the asset it's associated with (resource_id + region) so "which finding,
// on which asset" reads at a glance without opening the finding itself.
function FindingsTab({ frameworkId, controlId }: { frameworkId: string; controlId: string }) {
  const [tab, setTab] = useState<StatusTab>('all')
  const [items, setItems] = useState<Finding[]>([])
  const [nextCursor, setNextCursor] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  const fetchPage = (cursor?: string) =>
    findingsApi.list({
      framework: [`${frameworkId}/${controlId}`],
      status: STATUS_TAB_STATUSES[tab],
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
    // tab/frameworkId/controlId identify the request; fetchPage is rebuilt from them each render.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, frameworkId, controlId])

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

  return (
    <div id="control-drilldown-findings" className="space-y-3">
      <StatusFilter value={tab} onChange={setTab} />
      <FindingsList items={items} loading={loading} nextCursor={nextCursor} onLoadMore={loadMore} />
    </div>
  )
}

// One asset row on the Assets tab — collapsed by default, showing only its Pass/Fail
// tally for this control; expanding fetches (and locally filters) just that asset's
// findings, so opening ten assets doesn't fire ten requests up front.
function AssetRow({
  frameworkId,
  controlId,
  asset,
}: {
  frameworkId: string
  controlId: string
  asset: ComplianceControlAsset
}) {
  const [expanded, setExpanded] = useState(false)
  const [tab, setTab] = useState<StatusTab>('all')
  const [items, setItems] = useState<Finding[]>([])
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!expanded) return
    setLoading(true)
    findingsApi
      .list({
        framework: [`${frameworkId}/${controlId}`],
        resource_id: asset.resource_id,
        status: STATUS_TAB_STATUSES[tab],
        limit: 50,
      })
      .then((r) => setItems(r.data.data.items))
      .finally(() => setLoading(false))
  }, [expanded, tab, frameworkId, controlId, asset.resource_id])

  return (
    <div data-testid={`control-asset-row-${asset.resource_id}`} className="border border-slate-800 rounded">
      <button
        type="button"
        onClick={() => setExpanded((e) => !e)}
        className="w-full flex items-center gap-3 p-3 text-left hover:bg-slate-800/40 transition-colors"
      >
        <div className="flex-1 min-w-0">
          <div className="text-slate-300 text-sm font-mono truncate">{asset.resource_id}</div>
          <div className="text-slate-600 text-xs truncate">
            {asset.resource_type}
            {asset.region ? ` · ${asset.region}` : ''}
          </div>
        </div>
        <span className="text-green-400 text-xs font-mono flex-shrink-0">{asset.pass_count} pass</span>
        <span className="text-red-400 text-xs font-mono flex-shrink-0">{asset.fail_count} fail</span>
        {expanded ? (
          <ChevronDown className="w-4 h-4 text-slate-500 flex-shrink-0" />
        ) : (
          <ChevronRight className="w-4 h-4 text-slate-500 flex-shrink-0" />
        )}
      </button>
      {expanded && (
        <div className="border-t border-slate-800 p-3 space-y-3">
          <StatusFilter value={tab} onChange={setTab} />
          <FindingsList items={items} loading={loading} nextCursor={null} onLoadMore={() => {}} />
        </div>
      )}
    </div>
  )
}

// The Assets tab — which assets this control has been evaluated against, each with
// its own Pass/Fail tally; clicking one expands an inline sub-table instead of
// navigating away, so comparing several assets stays a single scroll.
function AssetsTab({ frameworkId, controlId }: { frameworkId: string; controlId: string }) {
  const [assets, setAssets] = useState<ComplianceControlAsset[] | null>(null)

  useEffect(() => {
    setAssets(null)
    complianceApi.controlAssets(frameworkId, controlId).then((r) => setAssets(r.data.data))
  }, [frameworkId, controlId])

  if (assets === null) {
    return (
      <div id="control-drilldown-assets" className="space-y-2">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="h-14 bg-slate-800 rounded animate-pulse" />
        ))}
      </div>
    )
  }
  if (assets.length === 0) {
    return <p className="text-slate-600 text-sm">No matching assets.</p>
  }
  return (
    <div id="control-drilldown-assets" className="space-y-2">
      {assets.map((asset) => (
        <AssetRow key={asset.resource_id} frameworkId={frameworkId} controlId={controlId} asset={asset} />
      ))}
    </div>
  )
}

// Opened from a leaf control row in Sections (Fail or Pass only — an Unscored
// control has no findings to drill into). Two tabs instead of one flat list: this
// control can span many checks across many assets, so "which findings" and "which
// assets" are both first-class questions, unlike the single-dimension Top 10
// drill-down (ComplianceDrilldownPanel) it's modeled after.
export function ControlDrilldownPanel({ frameworkId, controlId, title, onClose }: ControlDrilldownPanelProps) {
  const [tab, setTab] = useState<'findings' | 'assets'>('findings')

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
        className="fixed top-0 right-0 h-full w-[480px] bg-slate-900 border-l border-slate-700 shadow-2xl z-50 overflow-y-auto"
        data-testid="control-drilldown-panel"
      >
        <div
          id="control-drilldown-header"
          className="flex items-start justify-between p-4 border-b border-slate-700 sticky top-0 bg-slate-900 z-10"
        >
          <div className="flex-1 min-w-0 pr-2">
            <h2 className="text-slate-200 font-semibold text-sm leading-snug">{title}</h2>
            <p className="text-slate-500 text-xs font-mono mt-0.5 truncate">{controlId}</p>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 flex-shrink-0"
            aria-label="Close panel"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex gap-1 px-4 pt-3 border-b border-slate-800" role="tablist" aria-label="Control drilldown view">
          {(['findings', 'assets'] as const).map((t) => (
            <button
              key={t}
              role="tab"
              aria-selected={tab === t}
              onClick={() => setTab(t)}
              className={`px-3 py-2 text-xs font-medium border-b-2 transition-colors capitalize ${
                tab === t
                  ? 'border-orange-500 text-orange-300'
                  : 'border-transparent text-slate-500 hover:text-slate-300'
              }`}
            >
              {t}
            </button>
          ))}
        </div>

        <div id="control-drilldown-body" className="p-4">
          {tab === 'findings' ? (
            <FindingsTab frameworkId={frameworkId} controlId={controlId} />
          ) : (
            <AssetsTab frameworkId={frameworkId} controlId={controlId} />
          )}
        </div>
      </div>
    </>
  )
}
