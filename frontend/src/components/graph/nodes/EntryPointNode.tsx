import { memo } from 'react'
import { Handle, Position, type NodeProps } from '@xyflow/react'
import { Globe } from 'lucide-react'

export const EntryPointNode = memo(function EntryPointNode({ data }: NodeProps) {
  const node = data['node'] as Record<string, unknown>
  const name =
    (node['name'] as string | undefined) ??
    (node['resource_id'] as string | undefined) ??
    'Unknown'
  const resourceType = (node['resource_type'] as string | undefined) ?? 'resource'

  return (
    <div className="bg-slate-800 border-2 border-red-500 rounded-lg px-3 py-2 w-44 shadow-lg shadow-red-900/20">
      <Handle type="source" position={Position.Right} className="!bg-slate-600 !border-slate-500" />
      <div className="flex items-center gap-1.5 mb-1">
        <Globe size={12} className="text-red-400 shrink-0" />
        <span className="text-red-400 text-[10px] font-semibold uppercase tracking-wide">Entry</span>
      </div>
      <p className="text-slate-200 text-xs font-medium truncate">{name}</p>
      <p className="text-slate-500 text-[10px] truncate">{resourceType}</p>
    </div>
  )
})
