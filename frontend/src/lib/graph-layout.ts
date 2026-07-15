import dagre from '@dagrejs/dagre'
import type { Node, Edge } from '@xyflow/react'
import type { AttackPath, BlastRadiusEdge, BlastRadiusNode } from './types'

const NODE_WIDTH = 180
const NODE_HEIGHT = 72

export type PathNode = Record<string, unknown>
export type GraphNodeType = 'entryPoint' | 'target' | 'identity' | 'resource' | 'riskInsight'

export function getNodeType(node: PathNode, path: AttackPath): GraphNodeType {
  const id = node['_id'] as string | undefined
  if (id === path.entry_point_id) return 'entryPoint'
  if (id === path.target_id) return 'target'
  const collection = id?.split('/')[0] ?? ''
  if (collection === 'identities') return 'identity'
  return 'resource'
}

function inferEdgeLabel(source: GraphNodeType, target: GraphNodeType): string {
  if (source === 'entryPoint' && target === 'identity') return 'ASSUMES_ROLE'
  if (source === 'identity' && target === 'identity') return 'ASSUMES_ROLE'
  if (source === 'identity' && (target === 'resource' || target === 'target')) return 'HAS_ACCESS'
  if (source === 'resource' && target === 'target') return 'STORES_DATA'
  if (source === 'entryPoint') return 'EXPOSED_TO'
  return 'ROUTES_TRAFFIC'
}

export function buildFlowGraph(
  nodes: PathNode[],
  path: AttackPath,
): { nodes: Node[]; edges: Edge[] } {
  const g = new dagre.graphlib.Graph()
  g.setDefaultEdgeLabel(() => ({}))
  g.setGraph({ rankdir: 'LR', ranksep: 90, nodesep: 40 })

  const flowNodes: Node[] = nodes.map((n, i) => {
    const id = (n['_id'] as string | undefined) ?? `node-${i}`
    g.setNode(id, { width: NODE_WIDTH, height: NODE_HEIGHT })
    return {
      id,
      type: getNodeType(n, path),
      data: { node: n, path },
      position: { x: 0, y: 0 },
    }
  })

  const flowEdges: Edge[] = []
  for (let i = 0; i < nodes.length - 1; i++) {
    const srcId = (nodes[i]['_id'] as string | undefined) ?? `node-${i}`
    const tgtId = (nodes[i + 1]['_id'] as string | undefined) ?? `node-${i + 1}`
    const srcType = getNodeType(nodes[i], path)
    const tgtType = getNodeType(nodes[i + 1], path)
    g.setEdge(srcId, tgtId)
    flowEdges.push({
      id: `e-${i}`,
      source: srcId,
      target: tgtId,
      label: inferEdgeLabel(srcType, tgtType),
      type: 'smoothstep',
      animated: true,
      style: { stroke: '#475569' },
      labelStyle: { fill: '#94a3b8', fontSize: 10 },
      labelBgStyle: { fill: '#1e293b', fillOpacity: 0.85 },
    })
  }

  dagre.layout(g)

  flowNodes.forEach((node) => {
    const pos = g.node(node.id)
    node.position = { x: pos.x - NODE_WIDTH / 2, y: pos.y - NODE_HEIGHT / 2 }
  })

  return { nodes: flowNodes, edges: flowEdges }
}

/**
 * Attaches synthetic "risk insight" nodes (US-14.12) below the resource node each
 * finding explains, connected by a dotted edge. One insight per resource (the first
 * finding returned for it — findings are already severity-sorted server-side) to
 * keep the canvas legible instead of one node per finding.
 */
export function attachRiskInsightNodes(
  baseGraph: { nodes: Node[]; edges: Edge[] },
  findings: Record<string, unknown>[],
): { nodes: Node[]; edges: Edge[] } {
  const nodeById = new Map(baseGraph.nodes.map((n) => [n.id, n]))
  const seenResource = new Set<string>()
  const insightNodes: Node[] = []
  const insightEdges: Edge[] = []

  findings.forEach((finding) => {
    const resourceId = finding['resource_id'] as string | undefined
    if (!resourceId || seenResource.has(resourceId)) return
    const parent = nodeById.get(resourceId)
    if (!parent) return
    seenResource.add(resourceId)

    const insightId = `risk-insight-${resourceId}`
    insightNodes.push({
      id: insightId,
      type: 'riskInsight',
      data: { finding },
      position: { x: parent.position.x, y: parent.position.y + NODE_HEIGHT + 32 },
    })
    insightEdges.push({
      id: `risk-insight-edge-${insightId}`,
      source: parent.id,
      target: insightId,
      type: 'straight',
      style: { stroke: '#f59e0b', strokeDasharray: '4 4' },
    })
  })

  return {
    nodes: [...baseGraph.nodes, ...insightNodes],
    edges: [...baseGraph.edges, ...insightEdges],
  }
}

/** Builds a small, non-linear graph (a resource and its reachable neighbors) for the mini blast-radius canvas. */
export function buildMiniGraph(
  centerId: string,
  centerNode: Record<string, unknown>,
  nodes: BlastRadiusNode[],
  edges: BlastRadiusEdge[],
): { nodes: Node[]; edges: Edge[] } {
  const g = new dagre.graphlib.Graph()
  g.setDefaultEdgeLabel(() => ({}))
  g.setGraph({ rankdir: 'LR', ranksep: 70, nodesep: 30 })

  const flowNodes: Node[] = [
    { id: centerId, type: 'center', data: { node: centerNode }, position: { x: 0, y: 0 } },
    ...nodes.map((n) => ({
      id: n.id,
      type: 'resource' as const,
      data: { node: { name: n.name, resource_type: n.resource_type } },
      position: { x: 0, y: 0 },
    })),
  ]
  flowNodes.forEach((n) => g.setNode(n.id, { width: NODE_WIDTH, height: NODE_HEIGHT }))

  const flowEdges: Edge[] = edges.map((e, i) => {
    g.setEdge(e.source, e.target)
    return {
      id: `mini-e-${i}`,
      source: e.source,
      target: e.target,
      label: e.edge_type,
      type: 'smoothstep',
      style: { stroke: '#475569' },
      labelStyle: { fill: '#94a3b8', fontSize: 10 },
      labelBgStyle: { fill: '#1e293b', fillOpacity: 0.85 },
    }
  })

  dagre.layout(g)

  flowNodes.forEach((node) => {
    const pos = g.node(node.id)
    node.position = { x: pos.x - NODE_WIDTH / 2, y: pos.y - NODE_HEIGHT / 2 }
  })

  return { nodes: flowNodes, edges: flowEdges }
}
