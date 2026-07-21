'use client'

import { useEffect, useCallback } from 'react'
import {
  ReactFlow,
  Controls,
  MiniMap,
  Background,
  BackgroundVariant,
  useNodesState,
  useEdgesState,
  type NodeTypes,
  type Node,
  type Edge,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'

import { ResourceNode } from './nodes/ResourceNode'
import { EntryPointNode } from './nodes/EntryPointNode'
import { TargetNode } from './nodes/TargetNode'
import { IdentityNode } from './nodes/IdentityNode'
import { CenterNode } from './nodes/CenterNode'
import { RiskInsightNode } from './nodes/RiskInsightNode'
import { attachRiskInsightNodes, buildFlowGraph } from '@/lib/graph-layout'
import type { AttackPathDetail } from '@/lib/types'

const NODE_TYPES: NodeTypes = {
  resource: ResourceNode,
  entryPoint: EntryPointNode,
  target: TargetNode,
  identity: IdentityNode,
  center: CenterNode,
  riskInsight: RiskInsightNode,
}

interface AttackPathCanvasProps {
  /** 'mini' reuses this same canvas at a reduced size/toolbar for embedded context graphs (US-14.03/US-14.09) — never fork this component. */
  mode?: 'full' | 'mini'
  detail?: AttackPathDetail | null
  /** Pre-built graph for mode="mini" — the caller (e.g. blast-radius) owns its own layout adapter. */
  miniGraph?: { nodes: Node[]; edges: Edge[] } | null
  loading?: boolean
  onNodeClick?: (nodeId: string) => void
  /** mode="mini" only — renders a "View full in Attack Paths →" link in the toolbar. */
  onViewFull?: () => void
  emptyLabel?: string
}

export function AttackPathCanvas({
  mode = 'full',
  detail = null,
  miniGraph = null,
  loading,
  onNodeClick,
  onViewFull,
  emptyLabel,
}: AttackPathCanvasProps) {
  const isMini = mode === 'mini'
  // Mini mode isn't guaranteed a flex ancestor (it's embedded in plain detail-panel sections), so it
  // needs a definite height — ReactFlow's internal height:100% chain collapses to 0 with min-height alone.
  const sizeClasses = isMini ? 'h-[220px]' : 'flex-1 min-h-[460px]'
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([])

  useEffect(() => {
    if (isMini) {
      setNodes(miniGraph?.nodes ?? [])
      setEdges(miniGraph?.edges ?? [])
      return
    }
    if (!detail || detail.nodes.length === 0) {
      setNodes([])
      setEdges([])
      return
    }
    const base = buildFlowGraph(detail.nodes, detail.path)
    const { nodes: n, edges: e } = attachRiskInsightNodes(base, detail.findings)
    setNodes(n)
    setEdges(e)
  }, [isMini, miniGraph, detail, setNodes, setEdges])

  const handleNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      onNodeClick?.(node.id)
    },
    [onNodeClick],
  )

  const isEmpty = isMini ? (miniGraph?.nodes.length ?? 0) === 0 : detail !== null && detail.nodes.length === 0

  if (!isMini && !detail && !loading) {
    return (
      <div
        id="attack-path-canvas-placeholder"
        className={`${sizeClasses} flex items-center justify-center rounded-lg border border-slate-800 bg-slate-900/50`}
      >
        <div className="text-center">
          <p className="text-slate-400 text-sm font-medium">Select a path to visualize</p>
          <p className="text-slate-600 text-xs mt-1">Click any item in the list on the left</p>
        </div>
      </div>
    )
  }

  if (loading) {
    return (
      <div
        id="attack-path-canvas-loading"
        className={`${sizeClasses} flex items-center justify-center rounded-lg border border-slate-800 bg-slate-900/50`}
      >
        <div className="flex flex-col items-center gap-2">
          <div className="w-6 h-6 border-2 border-orange-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-slate-500 text-xs">Loading graph...</p>
        </div>
      </div>
    )
  }

  if (isEmpty) {
    return (
      <div
        id="attack-path-canvas-empty"
        className={`${sizeClasses} flex items-center justify-center rounded-lg border border-slate-800 bg-slate-900/50`}
      >
        <p className="text-slate-500 text-sm">{emptyLabel ?? 'No graph data available for this path'}</p>
      </div>
    )
  }

  return (
    <div id="attack-path-canvas" className={`${sizeClasses} rounded-lg overflow-hidden border border-slate-800 relative`}>
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={handleNodeClick}
        nodeTypes={NODE_TYPES}
        fitView
        fitViewOptions={{ padding: 0.25 }}
        minZoom={0.2}
        maxZoom={2.5}
        colorMode="dark"
        className="bg-slate-950"
        proOptions={{ hideAttribution: false }}
        nodesDraggable={!isMini}
      >
        <Controls
          showInteractive={!isMini}
          className="!bg-slate-800 !border-slate-700 [&>button]:!bg-slate-800 [&>button]:!border-slate-700 [&>button]:!text-slate-300"
        />
        {!isMini && (
          <MiniMap
            className="!bg-slate-900 !border-slate-700"
            nodeColor={(node) => {
              if (node.type === 'entryPoint') return '#ef4444'
              if (node.type === 'target') return '#eab308'
              if (node.type === 'identity') return '#a855f7'
              if (node.type === 'riskInsight') return '#f59e0b'
              return '#475569'
            }}
            maskColor="rgba(2, 6, 23, 0.7)"
          />
        )}
        <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="#1e293b" />
      </ReactFlow>
      {isMini && onViewFull && (
        <button
          type="button"
          onClick={onViewFull}
          className="absolute bottom-2 right-2 z-10 px-2 py-1 rounded bg-slate-900/90 border border-slate-700 text-orange-400 text-xs hover:border-orange-500"
        >
          View full in Attack Paths →
        </button>
      )}
    </div>
  )
}
