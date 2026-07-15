'use client'
import { useCallback, useEffect, useRef, useState } from 'react'
import { usePathname, useRouter, useSearchParams } from 'next/navigation'
import { useMutation } from '@tanstack/react-query'
import { CheckCircle2, Copy, ExternalLink, MoreVertical, PlayCircle, X } from 'lucide-react'
import { sideScanApi } from '@/lib/api'
import type { ResourceDetail } from '@/lib/types'
import { DETAIL_PANEL_TABS, defaultSubtab, findTab } from './detailPanelTabs'
import { ResourceNarrative } from './ResourceNarrative'
import { RelationshipGroups } from './RelationshipGroups'
import { BlastRadiusGraph } from './BlastRadiusGraph'
import { SoftwareInventoryPanel } from './SoftwareInventoryPanel'
import { ResourceCompliance } from './ResourceCompliance'

interface DetailPanelProps {
  resource: ResourceDetail | null
  onClose: () => void
}

const SCANNABLE_RESOURCE_TYPES = new Set(['ec2_instance', 'lambda_function'])

function consoleUrl(resource: ResourceDetail): string | null {
  if (resource.provider === 'aws' && resource.arn) {
    const region = resource.region ?? 'us-east-1'
    const base = `https://${region}.console.aws.amazon.com`
    if (resource.resource_type === 'ec2_instance')
      return `${base}/ec2/home?region=${region}#Instances:instanceId=${resource.resource_id}`
    if (resource.resource_type === 's3_bucket')
      return `https://s3.console.aws.amazon.com/s3/buckets/${resource.resource_id}`
  }
  return null
}

export function DetailPanel({ resource, onClose }: DetailPanelProps) {
  const router = useRouter()
  const pathname = usePathname()
  const searchParams = useSearchParams()

  const [scanError, setScanError] = useState<string | null>(null)
  const [kebabOpen, setKebabOpen] = useState(false)
  const [complianceFramework, setComplianceFramework] = useState<string | undefined>(undefined)
  const kebabRef = useRef<HTMLDivElement>(null)

  const initialTab = searchParams.get('tab') ?? DETAIL_PANEL_TABS[0].key
  const [activeTabKey, setActiveTabKey] = useState(initialTab)
  const [subtabByTab, setSubtabByTab] = useState<Record<string, string | undefined>>(() => ({
    [initialTab]: searchParams.get('subtab') ?? defaultSubtab(findTab(initialTab)),
  }))

  const activeTab = findTab(activeTabKey)
  const activeSubtabKey = subtabByTab[activeTabKey] ?? defaultSubtab(activeTab)

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (kebabRef.current && !kebabRef.current.contains(event.target as Node)) {
        setKebabOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const navigateTo = useCallback(
    (tabKey: string, subtabKey?: string | null) => {
      const tab = findTab(tabKey)
      const resolvedSubtab = subtabKey ?? subtabByTab[tabKey] ?? defaultSubtab(tab)
      setActiveTabKey(tabKey)
      setSubtabByTab((prev) => ({ ...prev, [tabKey]: resolvedSubtab }))

      const params = new URLSearchParams(searchParams.toString())
      params.set('tab', tabKey)
      if (resolvedSubtab) params.set('subtab', resolvedSubtab)
      else params.delete('subtab')
      router.replace(`${pathname}?${params.toString()}`, { scroll: false })
    },
    [pathname, router, searchParams, subtabByTab],
  )

  const tabButtonRefs = useRef<Record<string, HTMLButtonElement | null>>({})

  const handleTabKeyDown = useCallback(
    (event: React.KeyboardEvent) => {
      if (event.key !== 'ArrowRight' && event.key !== 'ArrowLeft') return
      event.preventDefault()
      const idx = DETAIL_PANEL_TABS.findIndex((t) => t.key === activeTabKey)
      const delta = event.key === 'ArrowRight' ? 1 : -1
      const next = DETAIL_PANEL_TABS[(idx + delta + DETAIL_PANEL_TABS.length) % DETAIL_PANEL_TABS.length]
      navigateTo(next.key)
      // Roving tabindex: move DOM focus with the selection, not just the active styling.
      tabButtonRefs.current[next.key]?.focus()
    },
    [activeTabKey, navigateTo],
  )

  const scanMutation = useMutation({
    mutationFn: () => sideScanApi.triggerScan(resource?.key ?? ''),
    onSuccess: () => setScanError(null),
    onError: () => setScanError('Failed to trigger scan.'),
  })

  if (!resource) return null

  const url = consoleUrl(resource)
  const canScan = SCANNABLE_RESOURCE_TYPES.has(resource.resource_type) && resource.status === 'active'
  const scanSuccessJobId = scanMutation.isSuccess ? scanMutation.data.data.job_id : null

  return (
    <div
      className="fixed top-0 right-0 h-full w-full lg:w-[58%] bg-slate-900 border-l border-slate-700 shadow-2xl z-50 overflow-y-auto"
      data-testid="detail-panel"
    >
      <div className="border-b border-slate-700 sticky top-0 bg-slate-900 z-10">
        <div className="flex items-center justify-between px-4 pt-3">
          <p className="text-slate-500 text-xs truncate">
            {resource.account_id ?? '—'} <span className="mx-1">›</span> {resource.region ?? '—'}{' '}
            <span className="mx-1">›</span> <span className="text-slate-300">{resource.name}</span>
          </p>
          <button
            onClick={onClose}
            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors flex-shrink-0"
            aria-label="Close panel"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div className="flex items-center justify-between px-4 pt-1 pb-3">
          <h2 className="text-slate-200 font-semibold flex items-center gap-1.5">
            {resource.name}
            <button
              type="button"
              title="Copy Resource ID"
              onClick={() => navigator.clipboard.writeText(resource.resource_id)}
              className="text-slate-500 hover:text-slate-300"
            >
              <Copy className="w-3 h-3" />
            </button>
          </h2>

          <div className="flex items-center gap-2">
            {canScan && (
              <button
                onClick={() => scanMutation.mutate()}
                disabled={scanMutation.isPending}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-orange-500 hover:bg-orange-600 disabled:opacity-50 text-white text-xs font-medium rounded-lg transition-colors"
              >
                <PlayCircle className="w-3.5 h-3.5" />
                {scanMutation.isPending ? 'Queuing...' : 'Scan Now'}
              </button>
            )}
            {url && (
              <a
                href={url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1.5 px-3 py-1.5 border border-slate-700 hover:border-slate-600 text-slate-300 text-xs rounded-lg transition-colors"
              >
                Open in Console <ExternalLink className="w-3 h-3" />
              </a>
            )}
            <div className="relative" ref={kebabRef}>
              <button
                type="button"
                onClick={() => setKebabOpen((o) => !o)}
                aria-label="More actions"
                className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200"
              >
                <MoreVertical className="w-4 h-4" />
              </button>
              {kebabOpen && (
                <div className="absolute right-0 mt-1 w-44 bg-slate-800 border border-slate-700 rounded-md shadow-lg py-1 z-20">
                  <button
                    type="button"
                    onClick={() => {
                      navigator.clipboard.writeText(resource.arn ?? resource.resource_id)
                      setKebabOpen(false)
                    }}
                    className="w-full text-left px-3 py-1.5 text-sm text-slate-300 hover:bg-slate-700/50"
                  >
                    Copy ARN
                  </button>
                  <button
                    type="button"
                    onClick={() => {
                      navigator.clipboard.writeText(resource.resource_id)
                      setKebabOpen(false)
                    }}
                    className="w-full text-left px-3 py-1.5 text-sm text-slate-300 hover:bg-slate-700/50"
                  >
                    Copy Resource ID
                  </button>
                </div>
              )}
            </div>
          </div>
        </div>

        {(scanSuccessJobId || scanError) && (
          <div className="px-4 pb-3">
            {scanSuccessJobId && (
              <div className="p-2 bg-green-950 border border-green-800 rounded text-green-400 text-xs flex items-center gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0" />
                Side-scan queued — job {scanSuccessJobId}
              </div>
            )}
            {scanError && (
              <div className="p-2 bg-red-950 border border-red-800 rounded text-red-400 text-xs">{scanError}</div>
            )}
          </div>
        )}

        <div role="tablist" aria-label="Resource detail tabs" onKeyDown={handleTabKeyDown} className="flex px-4 gap-4 border-t border-slate-800">
          {DETAIL_PANEL_TABS.map((tab) => (
            <button
              key={tab.key}
              ref={(el) => {
                tabButtonRefs.current[tab.key] = el
              }}
              role="tab"
              aria-selected={tab.key === activeTabKey}
              tabIndex={tab.key === activeTabKey ? 0 : -1}
              onClick={() => navigateTo(tab.key)}
              className={`py-2 text-sm border-b-2 transition-colors ${
                tab.key === activeTabKey
                  ? 'border-orange-500 text-orange-400'
                  : 'border-transparent text-slate-400 hover:text-slate-200'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {activeTab.subtabs.length > 0 && (
          <div role="tablist" aria-label="Resource detail sub-tabs" className="flex px-4 gap-4 pb-2 pt-1">
            {activeTab.subtabs.map((sub) => (
              <button
                key={sub.key}
                role="tab"
                aria-selected={sub.key === activeSubtabKey}
                onClick={() => navigateTo(activeTabKey, sub.key)}
                className={`text-xs ${
                  sub.key === activeSubtabKey ? 'text-orange-400 font-medium' : 'text-slate-500 hover:text-slate-300'
                }`}
              >
                {sub.label}
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="p-4 space-y-6">
        {activeTabKey === 'info' && activeSubtabKey === 'overview' && (
          <>
            <ResourceNarrative resourceKey={resource.key} onNavigate={navigateTo} />

            {Object.keys(resource.tags).length > 0 && (
              <section>
                <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">Tags</h3>
                <div className="flex flex-wrap gap-1.5">
                  {Object.entries(resource.tags).map(([k, v]) => (
                    <span
                      key={k}
                      className="px-2 py-0.5 bg-slate-800 border border-slate-700 rounded text-xs text-slate-300"
                    >
                      {k}: {v}
                    </span>
                  ))}
                </div>
              </section>
            )}

            <section>
              <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">
                Relationships ({resource.edges.length})
              </h3>
              <RelationshipGroups edges={resource.edges} onViewInGraph={() => navigateTo('risk', 'blast_radius')} />
            </section>

            <section>
              <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">Blast Radius</h3>
              <BlastRadiusGraph resource={resource} onViewFull={() => navigateTo('risk', 'blast_radius')} />
            </section>
          </>
        )}

        {activeTabKey === 'risk' && activeSubtabKey === 'blast_radius' && (
          <section>
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">
              Blast Radius — Reachable Assets
            </h3>
            <BlastRadiusGraph resource={resource} />
          </section>
        )}

        {activeTabKey === 'software' && activeSubtabKey && (
          <section>
            <SoftwareInventoryPanel resource={resource} subtabKey={activeSubtabKey} />
          </section>
        )}

        {activeTabKey === 'compliance' && (
          <section>
            <ResourceCompliance
              resource={resource}
              framework={complianceFramework}
              onFrameworkChange={setComplianceFramework}
            />
          </section>
        )}

        {!(activeTabKey === 'info' && activeSubtabKey === 'overview') &&
          !(activeTabKey === 'risk' && activeSubtabKey === 'blast_radius') &&
          activeTabKey !== 'software' &&
          activeTabKey !== 'compliance' && (
            <p className="text-slate-600 text-sm">This section isn&apos;t available yet.</p>
          )}
      </div>
    </div>
  )
}
