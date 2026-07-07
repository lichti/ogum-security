import dagre from '@dagrejs/dagre'
import type { Node, Edge } from '@xyflow/react'
import type { AttackPath } from './types'

const NODE_WIDTH = 180
const NODE_HEIGHT = 72

export type PathNode = Record<string, unknown>
export type GraphNodeType = 'entryPoint' | 'target' | 'identity' | 'resource'

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
