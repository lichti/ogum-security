'use client'
import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { AttackPathCanvas } from '@/components/graph/AttackPathCanvas'
import { buildMiniGraph } from '@/lib/graph-layout'
import { findingsApi } from '@/lib/api'
import type { FindingDetail } from '@/lib/types'

interface FindingExposurePathGraphProps {
  finding: FindingDetail
}

export function FindingExposurePathGraph({ finding }: FindingExposurePathGraphProps) {
  const { data, isLoading } = useQuery({
    queryKey: ['finding-exposure-path', finding._key],
    queryFn: () => findingsApi.exposurePath(finding._key).then((r) => r.data.data),
    staleTime: 60_000,
  })

  const miniGraph = useMemo(() => {
    // `data.resource_key` is the resolved ArangoDB resource key the backend traversal
    // is rooted at — it must match `nodes`/`edges` ids exactly (finding.resource_id is
    // the business/cloud resource id, a different value, so it can't be used here).
    if (!data || data.nodes.length === 0) return { nodes: [], edges: [] }
    return buildMiniGraph(
      `resources/${data.resource_key}`,
      { name: finding.resource?.name ?? finding.resource_id, resource_type: finding.resource_type },
      data.nodes,
      data.edges,
    )
  }, [data, finding])

  return (
    <AttackPathCanvas
      mode="mini"
      miniGraph={miniGraph}
      loading={isLoading}
      emptyLabel="No exposure path detected for this finding"
    />
  )
}
