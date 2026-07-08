'use client'

import { useCallback, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Flame, ArrowRight, Wand2, Terminal, Milestone } from 'lucide-react'
import { AttackPathStatsBar } from '@/components/attack-paths/AttackPathStatsBar'
import { AttackPathCanvas } from '@/components/graph/AttackPathCanvas'
import { AttackPathList } from '@/components/graph/AttackPathList'
import { NodeDetailPanel } from '@/components/graph/NodeDetailPanel'
import { QueryConsole } from '@/components/graph/QueryConsole'
import { PathfindingPanel } from '@/components/graph/PathfindingPanel'
import { attackPathsApi } from '@/lib/api'
import type { AttackPath, AttackPathSeverity } from '@/lib/types'

const SEVERITY_COLOR: Record<AttackPathSeverity, string> = {
  CRITICAL: 'text-red-400 bg-red-500/10 border-red-500/30',
  HIGH: 'text-orange-400 bg-orange-500/10 border-orange-500/30',
  MEDIUM: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
  LOW: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
}

export default function AttackPathsPage() {
  const [selectedPath, setSelectedPath] = useState<AttackPath | null>(null)
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null)
  const [severityFilter, setSeverityFilter] = useState<AttackPathSeverity | undefined>()
  const [showQueryConsole, setShowQueryConsole] = useState(false)
  const [showPathfinding, setShowPathfinding] = useState(false)

  const { data: statsData } = useQuery({
    queryKey: ['attack-paths-stats'],
    queryFn: () => attackPathsApi.stats().then((r) => r.data.data),
    staleTime: 30_000,
  })

  const { data: listData, isLoading: listLoading } = useQuery({
    queryKey: ['attack-paths', severityFilter],
    queryFn: () =>
      attackPathsApi.list({ limit: 100, severity: severityFilter }).then((r) => r.data.data),
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

  const handleNodeClick = useCallback((nodeId: string) => {
    setSelectedNodeId(nodeId)
  }, [])

  return (
    <div className="h-screen flex flex-col bg-slate-950 text-slate-200 overflow-hidden">
      {/* Header + Stats */}
      <div className="shrink-0 px-6 pt-6 pb-4">
        <div className="mb-4 flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold text-slate-100">Attack Paths</h1>
            <p className="text-slate-500 text-sm mt-0.5">
              Contextual risk graph — paths from internet exposure to sensitive data
            </p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
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
          <AttackPathStatsBar stats={statsData} onSeverityClick={handleSeverityClick} />
        )}
      </div>

      {/* Main split layout */}
      <div className="flex-1 flex gap-4 px-6 pb-4 min-h-0">
        {/* Left: path list */}
        <AttackPathList
          paths={paths}
          selectedKey={selectedPath?._key ?? null}
          loading={listLoading}
          onSelect={handleSelectPath}
        />

        {/* Right: canvas */}
        <div className="flex-1 flex flex-col gap-3 min-w-0">
          <AttackPathCanvas
            detail={detailData ?? null}
            loading={!!selectedPath && detailLoading}
            onNodeClick={handleNodeClick}
          />

          {/* Bottom info bar — visible when a path is selected */}
          {selectedPath && (
            <div className="shrink-0 flex items-center gap-4 px-4 py-3 bg-slate-900 border border-slate-800 rounded-lg">
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

              <button
                disabled
                title="Ogum.AI remediation — coming in Sprint 4"
                className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md bg-slate-800 text-slate-500 border border-slate-700 cursor-not-allowed"
              >
                <Wand2 size={12} />
                Remediate with AI
              </button>
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
