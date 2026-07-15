'use client'
import { useRouter } from 'next/navigation'
import { useQuery } from '@tanstack/react-query'
import { Badge } from '@/components/ui/Badge'
import { Skeleton } from '@/components/ui/Skeleton'
import { inventoryApi } from '@/lib/api'
import type { ResourceDetail } from '@/lib/types'

interface ResourceComplianceProps {
  resource: ResourceDetail
  framework?: string
  onFrameworkChange: (framework: string) => void
}

export function ResourceCompliance({ resource, framework, onFrameworkChange }: ResourceComplianceProps) {
  const router = useRouter()

  const { data, isLoading } = useQuery({
    queryKey: ['inventory-compliance', resource.key, framework],
    queryFn: () => inventoryApi.compliance(resource.key, framework).then((r) => r.data.data),
    staleTime: 60_000,
  })

  if (isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-8 w-full" />
        ))}
      </div>
    )
  }

  if (!data || data.available_frameworks.length === 0) {
    return <p className="text-slate-600 text-sm">No compliance data found for this resource.</p>
  }

  return (
    <div className="space-y-3">
      <select
        value={data.selected_framework ?? ''}
        onChange={(e) => onFrameworkChange(e.target.value)}
        className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-xs text-slate-200"
      >
        {data.available_frameworks.map((fw) => (
          <option key={fw.id} value={fw.id}>
            {fw.label}
          </option>
        ))}
      </select>

      {data.controls.length === 0 ? (
        <p className="text-slate-600 text-sm">No controls found for this framework.</p>
      ) : (
        <table className="w-full text-xs">
          <thead>
            <tr className="text-slate-500 text-left border-b border-slate-800">
              <th className="font-normal py-1">Status</th>
              <th className="font-normal py-1">Control</th>
              <th className="font-normal py-1">Category</th>
              <th className="font-normal py-1">Priority</th>
              <th className="font-normal py-1" />
            </tr>
          </thead>
          <tbody>
            {data.controls.map((control) => (
              <tr key={`${control.control_id}-${control.finding_key}`} className="border-b border-slate-800/50">
                <td className="py-1.5">
                  <Badge variant={control.status === 'PASS' ? 'status-active' : 'severity-high'}>
                    {control.status}
                  </Badge>
                </td>
                <td className="py-1.5 text-slate-300">{control.title}</td>
                <td className="py-1.5 text-slate-400">{control.category}</td>
                <td className="py-1.5 text-slate-400">{control.severity}</td>
                <td className="py-1.5">
                  <button
                    type="button"
                    onClick={() => router.push(`/findings?finding=${control.finding_key}`)}
                    className="text-orange-400 hover:underline"
                  >
                    View finding →
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
