import { memo } from 'react'
import { Handle, Position, type NodeProps } from '@xyflow/react'
import { Database } from 'lucide-react'

export const TargetNode = memo(function TargetNode({ data }: NodeProps) {
  const node = data['node'] as Record<string, unknown>
  const name =
    (node['name'] as string | undefined) ??
    (node['resource_id'] as string | undefined) ??
    'Unknown'
  const resourceType = (node['resource_type'] as string | undefined) ?? 'data asset'

  return (
    <div className="bg-slate-800 border-2 border-yellow-500 rounded-lg px-3 py-2 w-44 shadow-lg shadow-yellow-900/20">
      <Handle type="target" position={Position.Left} className="!bg-slate-600 !border-slate-500" />
      <div className="flex items-center gap-1.5 mb-1">
        <Database size={12} className="text-yellow-400 shrink-0" />
        <span className="text-yellow-400 text-[10px] font-semibold uppercase tracking-wide">Target</span>
      </div>
      <p className="text-slate-200 text-xs font-medium truncate">{name}</p>
      <p className="text-slate-500 text-[10px] truncate">{resourceType}</p>
    </div>
  )
})
