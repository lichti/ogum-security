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
import { buildFlowGraph } from '@/lib/graph-layout'
import type { AttackPathDetail } from '@/lib/types'

const NODE_TYPES: NodeTypes = {
  resource: ResourceNode,
  entryPoint: EntryPointNode,
  target: TargetNode,
  identity: IdentityNode,
}

interface AttackPathCanvasProps {
  detail: AttackPathDetail | null
  loading?: boolean
  onNodeClick?: (nodeId: string) => void
}

export function AttackPathCanvas({ detail, loading, onNodeClick }: AttackPathCanvasProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([])
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([])

  useEffect(() => {
    if (!detail || detail.nodes.length === 0) {
      setNodes([])
      setEdges([])
      return
    }
    const { nodes: n, edges: e } = buildFlowGraph(detail.nodes, detail.path)
    setNodes(n)
    setEdges(e)
  }, [detail, setNodes, setEdges])

  const handleNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      onNodeClick?.(node.id)
    },
    [onNodeClick],
  )

  if (!detail && !loading) {
    return (
      <div className="flex-1 flex items-center justify-center rounded-lg border border-slate-800 bg-slate-900/50 min-h-[460px]">
        <div className="text-center">
          <p className="text-slate-400 text-sm font-medium">Select a path to visualize</p>
          <p className="text-slate-600 text-xs mt-1">Click any item in the list on the left</p>
        </div>
      </div>
    )
  }

  if (loading) {
    return (
      <div className="flex-1 flex items-center justify-center rounded-lg border border-slate-800 bg-slate-900/50 min-h-[460px]">
        <div className="flex flex-col items-center gap-2">
          <div className="w-6 h-6 border-2 border-orange-500 border-t-transparent rounded-full animate-spin" />
          <p className="text-slate-500 text-xs">Loading graph...</p>
        </div>
      </div>
    )
  }

  if (detail && detail.nodes.length === 0) {
    return (
      <div className="flex-1 flex items-center justify-center rounded-lg border border-slate-800 bg-slate-900/50 min-h-[460px]">
        <p className="text-slate-500 text-sm">No graph data available for this path</p>
      </div>
    )
  }

  return (
    <div className="flex-1 min-h-[460px] rounded-lg overflow-hidden border border-slate-800">
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
      >
        <Controls className="!bg-slate-800 !border-slate-700 [&>button]:!bg-slate-800 [&>button]:!border-slate-700 [&>button]:!text-slate-300" />
        <MiniMap
          className="!bg-slate-900 !border-slate-700"
          nodeColor={(node) => {
            if (node.type === 'entryPoint') return '#ef4444'
            if (node.type === 'target') return '#eab308'
            if (node.type === 'identity') return '#a855f7'
            return '#475569'
          }}
          maskColor="rgba(2, 6, 23, 0.7)"
        />
        <Background variant={BackgroundVariant.Dots} gap={20} size={1} color="#1e293b" />
      </ReactFlow>
    </div>
  )
}
