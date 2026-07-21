'use client'

import { useCallback, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Flame, ArrowRight, Terminal, Milestone, Copy } from 'lucide-react'
import { AttackPathStatsBar } from '@/components/attack-paths/AttackPathStatsBar'
import { AttackPathNarrative } from '@/components/attack-paths/AttackPathNarrative'
import { TakeActionMenu } from '@/components/attack-paths/TakeActionMenu'
import { AttackPathCanvas } from '@/components/graph/AttackPathCanvas'
import { AttackPathList, type AttackPathViewMode } from '@/components/graph/AttackPathList'
import { NodeDetailPanel } from '@/components/graph/NodeDetailPanel'
import { QueryConsole } from '@/components/graph/QueryConsole'
import { PathfindingPanel } from '@/components/graph/PathfindingPanel'
import { ExposureBadge, type ExposureLevel } from '@/components/ui/ExposureBadge'
import { attackPathsApi } from '@/lib/api'
import type {
  AttackPath,
  AttackPathCrownJewelReason,
  AttackPathSeverity,
  AttackPathTargetAssetCategory,
} from '@/lib/types'

const SEVERITY_COLOR: Record<AttackPathSeverity, string> = {
  CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/30',
  HIGH: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
  MEDIUM: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
  LOW: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
}

const VIEW_MODES: { value: AttackPathViewMode; label: string }[] = [
  { value: 'paths', label: 'Paths' },
  { value: 'alerts', label: 'Alerts' },
  { value: 'assets', label: 'Assets' },
]

export default function AttackPathsPage() {
  const [selectedPath, setSelectedPath] = useState<AttackPath | null>(null)
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [severityFilter, setSeverityFilter] = useState<AttackPathSeverity | undefined>()
  const [categoryFilter, setCategoryFilter] = useState<AttackPathTargetAssetCategory | undefined>()
  const [reasonFilter, setReasonFilter] = useState<AttackPathCrownJewelReason | undefined>()
  const [viewMode, setViewMode] = useState<AttackPathViewMode>('paths')
  const [showQueryConsole, setShowQueryConsole] = useState(false)
  const [showPathfinding, setShowPathfinding] = useState(false)

  const { data: statsData } = useQuery({
    queryKey: ['attack-paths-stats'],
    queryFn: () => attackPathsApi.stats().then((r) => r.data.data),
    staleTime: 30_000,
  })

  const { data: listData, isLoading: listLoading } = useQuery({
    queryKey: ['attack-paths', severityFilter, categoryFilter, reasonFilter],
    queryFn: () =>
      attackPathsApi
        .list({
          limit: 100,
          severity: severityFilter,
          target_asset_category: categoryFilter,
          target_crown_jewel_reason: reasonFilter,
        })
        .then((r) => r.data.data),
    staleTime: 30_000,
  })

  const { data: detailData, isLoading: detailLoading } = useQuery({
    queryKey: ['attack-path-detail', selectedPath?._key],
    queryFn: () =>
      attackPathsApi.get(selectedPath!._key).then((r) => r.data.data),
    enabled: !!selectedPath,
    staleTime: 60_000,
  })

  const paths = listData?.items ?? []

  const handleSelectPath = useCallback((path: AttackPath) => {
    setSelectedPath(path)
    setSelectedNodeId(null)
  }, [])

  const handleSeverityClick = useCallback((severity: string) => {
    setSeverityFilter(severity as AttackPathSeverity)
  }, [])

  const handleAssetCategoryClick = useCallback((category: AttackPathTargetAssetCategory) => {
    setCategoryFilter(category)
  }, [])

  const handleCrownJewelReasonClick = useCallback((reason: AttackPathCrownJewelReason) => {
    setReasonFilter(reason)
  }, [])

  const handleNodeClick = useCallback((nodeId: string) => {
    setSelectedNodeId(nodeId)
  }, [])

  return (
    <div id="attack-paths-page" className="h-screen flex flex-col bg-slate-950 text-slate-200 overflow-hidden">
      {/* Header + Stats */}
      <div className="shrink-0 px-6 pt-6 pb-4">
        <div className="mb-4 flex items-start justify-end">
          <div className="flex items-center gap-2 shrink-0">
            <div className="flex items-center gap-0.5 p-0.5 rounded-lg bg-slate-800 border border-slate-700">
              {VIEW_MODES.map((mode) => (
                <button
                  key={mode.value}
                  onClick={() => setViewMode(mode.value)}
                  aria-pressed={viewMode === mode.value}
                  className={`px-2.5 py-1.5 rounded-md text-xs font-medium transition-colors ${
                    viewMode === mode.value
                      ? 'bg-orange-500/20 text-orange-400'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {mode.label}
                </button>
              ))}
            </div>
            <button
              onClick={() => setShowPathfinding(true)}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs border border-slate-700 transition-colors"
            >
              <Milestone size={13} />
              Pathfinding
            </button>
            <button
              onClick={() => setShowQueryConsole(true)}
              className="flex items-center gap-1.5 px-3 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs border border-slate-700 transition-colors"
            >
              <Terminal size={13} />
              AQL Console
            </button>
          </div>
        </div>
        {statsData && (
          <AttackPathStatsBar
            stats={statsData}
            onSeverityClick={handleSeverityClick}
            onAssetCategoryClick={handleAssetCategoryClick}
            onCrownJewelReasonClick={handleCrownJewelReasonClick}
          />
        )}
      </div>

      {/* Main split layout */}
      <div id="attack-paths-split-layout" className="flex-1 flex gap-4 px-6 pb-4 min-h-0">
        {/* Left: path list */}
        <AttackPathList
          paths={paths}
          selectedKey={selectedPath?._key ?? null}
          loading={listLoading}
          viewMode={viewMode}
          onSelect={handleSelectPath}
        />

        {/* Right: canvas */}
        <div id="attack-paths-canvas-column" className="flex-1 flex flex-col gap-3 min-w-0 overflow-y-auto">
          <AttackPathCanvas
            detail={detailData ?? null}
            loading={!!selectedPath && detailLoading}
            onNodeClick={handleNodeClick}
          />

          {/* Bottom detail — visible when a path is selected */}
          {selectedPath && detailData && (
            <div className="shrink-0 flex flex-col gap-3 px-4 py-3 bg-slate-900 border border-slate-800 rounded-lg">
              <div className="flex items-center gap-4">
                <span
                  className={`text-[11px] font-semibold px-2 py-1 rounded border ${SEVERITY_COLOR[selectedPath.severity]}`}
                >
                  {selectedPath.severity}
                </span>

                <div className="flex items-center gap-1.5 text-sm text-slate-400 min-w-0 flex-1">
                  <span className="text-slate-200 font-medium truncate">{selectedPath.entry_point_name}</span>
                  <ArrowRight size={14} className="text-slate-600 shrink-0" />
                  <span className="text-slate-200 font-medium truncate">{selectedPath.target_name}</span>
                </div>

                <div className="flex items-center gap-4 shrink-0 text-xs text-slate-500">
                  <span>
                    Score: <span className="text-slate-300 font-semibold">{selectedPath.risk_score.toFixed(0)}</span>
                  </span>
                  <span>
                    {selectedPath.hops} hop{selectedPath.hops !== 1 ? 's' : ''}
                  </span>
                  {selectedPath.is_toxic_combination && (
                    <span className="flex items-center gap-1 text-orange-400">
                      <Flame size={12} />
                      Toxic
                    </span>
                  )}
                </div>

                <TakeActionMenu detail={detailData} />
              </div>

              <div className="grid grid-cols-2 gap-4 pt-3 border-t border-slate-800">
                {/* Path Info (US-14.13) */}
                <dl className="grid grid-cols-2 gap-x-3 gap-y-2 text-xs content-start">
                  <dt className="text-slate-500">Status</dt>
                  <dd className="text-slate-300">{selectedPath.status}</dd>
                  <dt className="text-slate-500">Status Changed</dt>
                  <dd className="text-slate-600 italic">not available yet</dd>
                  <dt className="text-slate-500">Created</dt>
                  <dd className="text-slate-300">{new Date(selectedPath.detected_at).toLocaleString()}</dd>
                  <dt className="text-slate-500">Length</dt>
                  <dd className="text-slate-300">
                    {selectedPath.hops} hop{selectedPath.hops !== 1 ? 's' : ''}
                  </dd>
                  <dt className="text-slate-500">ID</dt>
                  <dd className="text-slate-400 flex items-center gap-1 truncate">
                    <span className="truncate">{selectedPath._key}</span>
                    <button
                      type="button"
                      aria-label="Copy path ID"
                      onClick={() => navigator.clipboard?.writeText(selectedPath._key)}
                      className="text-slate-600 hover:text-slate-300 shrink-0"
                    >
                      <Copy size={11} />
                    </button>
                  </dd>
                  <dt className="text-slate-500">Exposure</dt>
                  <dd>
                    {selectedPath.exposure ? (
                      <ExposureBadge exposure={selectedPath.exposure as ExposureLevel} />
                    ) : (
                      <span className="text-slate-600 italic">not available</span>
                    )}
                  </dd>
                  <dt className="text-slate-500">Cross Account</dt>
                  <dd className="text-slate-300">
                    {selectedPath.is_cross_account === undefined
                      ? '—'
                      : selectedPath.is_cross_account
                        ? `Yes (${selectedPath.account_ids?.length ?? 0})`
                        : 'No'}
                  </dd>
                  <dt className="text-slate-500">Cross Cloud Provider</dt>
                  <dd className="text-slate-300">
                    {selectedPath.is_cross_cloud_provider === undefined
                      ? '—'
                      : selectedPath.is_cross_cloud_provider
                        ? 'Yes'
                        : 'No'}
                  </dd>
                  <dt className="text-slate-500">Account</dt>
                  <dd className="text-slate-300 truncate">{selectedPath.account_ids?.join(', ') || '—'}</dd>
                </dl>

                {/* Paginated narrative (US-14.13) */}
                <AttackPathNarrative pathKey={selectedPath._key} />
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Node detail panel */}
      <NodeDetailPanel
        nodeId={selectedNodeId}
        onClose={() => setSelectedNodeId(null)}
      />

      {/* AQL Console modal */}
      {showQueryConsole && (
        <QueryConsole onClose={() => setShowQueryConsole(false)} />
      )}

      {/* Pathfinding modal */}
      {showPathfinding && (
        <PathfindingPanel onClose={() => setShowPathfinding(false)} />
      )}
    </div>
  )
}
