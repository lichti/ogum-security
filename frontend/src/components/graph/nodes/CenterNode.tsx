import { memo } from 'react'
import { Handle, Position, type NodeProps } from '@xyflow/react'
import { Crosshair } from 'lucide-react'

export const CenterNode = memo(function CenterNode({ data }: NodeProps) {
  const node = data['node'] as Record<string, unknown>
  const name = (node['name'] as string | undefined) ?? 'Unknown'
  const resourceType = (node['resource_type'] as string | undefined) ?? 'resource'

  return (
    <div className="bg-slate-800 border-2 border-orange-500 rounded-lg px-3 py-2 w-44 shadow-lg shadow-orange-900/20">
      <Handle type="source" position={Position.Right} className="!bg-slate-600 !border-slate-500" />
      <div className="flex items-center gap-1.5 mb-1">
        <Crosshair size={12} className="text-orange-400 shrink-0" />
        <span className="text-orange-400 text-[10px] font-semibold uppercase tracking-wide">This resource</span>
      </div>
      <p className="text-slate-200 text-xs font-medium truncate">{name}</p>
      <p className="text-slate-500 text-[10px] truncate">{resourceType}</p>
    </div>
  )
})
