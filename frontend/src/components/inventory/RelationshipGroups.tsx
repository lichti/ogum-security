import type { EdgeSummary } from '@/lib/types'

interface RelationshipGroupsProps {
  edges: EdgeSummary[]
  onViewInGraph?: () => void
}

function groupByType(edges: EdgeSummary[]): [string, EdgeSummary[]][] {
  const groups = new Map<string, EdgeSummary[]>()
  for (const edge of edges) {
    const list = groups.get(edge.edge_type) ?? []
    list.push(edge)
    groups.set(edge.edge_type, list)
  }
  return [...groups.entries()].sort((a, b) => a[0].localeCompare(b[0]))
}

export function RelationshipGroups({ edges, onViewInGraph }: RelationshipGroupsProps) {
  if (edges.length === 0) {
    return <p className="text-slate-600 text-sm">No relationships found.</p>
  }

  const groups = groupByType(edges)

  return (
    <div id="relationship-groups" className="space-y-4">
      {groups.map(([edgeType, groupEdges]) => (
        <div key={edgeType} data-testid={`relationship-group-${edgeType}`}>
          <div className="flex items-center justify-between mb-1.5">
            <h4 className="text-xs font-semibold text-slate-400">
              {groupEdges.length} {edgeType.replace(/_/g, ' ')}
            </h4>
            {onViewInGraph && (
              <button type="button" onClick={onViewInGraph} className="text-orange-400 text-xs hover:underline">
                View in graph →
              </button>
            )}
          </div>
          <table className="w-full text-xs">
            <thead>
              <tr className="text-slate-500 text-left border-b border-slate-800">
                <th className="font-normal py-1">Direction</th>
                <th className="font-normal py-1">Resource</th>
                <th className="font-normal py-1">Type</th>
              </tr>
            </thead>
            <tbody>
              {groupEdges.map((edge, i) => (
                <tr
                  key={i}
                  data-testid={`relationship-edge-row-${edgeType}-${edge.peer_key}-${edge.direction}`}
                  className="border-b border-slate-800/50"
                >
                  <td className="py-1 text-slate-500">{edge.direction === 'outbound' ? '→' : '←'}</td>
                  <td className="py-1 text-slate-300 font-mono">{edge.peer_key}</td>
                  <td className="py-1 text-slate-500">{edge.peer_type ?? '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ))}
    </div>
  )
}
