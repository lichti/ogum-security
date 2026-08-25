'use client'
import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AttackPathCanvas } from '@/components/graph/AttackPathCanvas'
import { buildMiniGraph } from '@/lib/graph-layout'
import { inventoryApi } from '@/lib/api'
import type { ResourceDetail } from '@/lib/types'

interface BlastRadiusGraphProps {
  resource: ResourceDetail
  onViewFull?: () => void
}

export function BlastRadiusGraph({ resource, onViewFull }: BlastRadiusGraphProps) {
  const { data, isLoading } = useQuery({
    queryKey: ['inventory-blast-radius', resource.key],
    queryFn: () => inventoryApi.blastRadius(resource.key).then((r) => r.data.data),
    staleTime: 60_000,
  })

  const miniGraph = useMemo(() => {
    // buildMiniGraph always includes the center node, so an empty `data.nodes` must stay
    // an empty graph here too — otherwise the canvas's "no exposure edges" state never shows.
    if (!data || data.nodes.length === 0) return { nodes: [], edges: [] }
    return buildMiniGraph(
      `resources/${resource.key}`,
      { name: resource.name, resource_type: resource.resource_type },
      data.nodes,
      data.edges,
    )
  }, [data, resource])

  const countsLabel = data
    ? Object.entries(data.grouped_counts)
        .map(([type, count]) => `${count} ${type.replace(/_/g, ' ')}`)
        .join(', ')
    : null

  return (
    <div id="blast-radius-graph" className="space-y-2">
      {countsLabel && <p className="text-slate-500 text-xs">Reachable: {countsLabel}</p>}
      <AttackPathCanvas
        mode="mini"
        miniGraph={miniGraph}
        loading={isLoading}
        onViewFull={onViewFull}
        emptyLabel="No exposure edges detected for this resource"
      />
    </div>
  )
}
