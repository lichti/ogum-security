import { memo } from 'react'
import { Handle, Position, type NodeProps } from '@xyflow/react'
import { User } from 'lucide-react'

export const IdentityNode = memo(function IdentityNode({ data }: NodeProps) {
  const node = data['node'] as Record<string, unknown>
  const name =
    (node['name'] as string | undefined) ??
    (node['_key'] as string | undefined) ??
    'Unknown'
  const resourceType = (node['resource_type'] as string | undefined) ?? 'identity'

  return (
    <div className="bg-slate-800 border-2 border-purple-500 rounded-lg px-3 py-2 w-44 shadow-lg shadow-purple-900/20">
      <Handle type="target" position={Position.Left} className="!bg-slate-600 !border-slate-500" />
      <Handle type="source" position={Position.Right} className="!bg-slate-600 !border-slate-500" />
      <div className="flex items-center gap-1.5 mb-1">
        <User size={12} className="text-purple-400 shrink-0" />
        <span className="text-purple-400 text-[10px] font-semibold uppercase tracking-wide">Identity</span>
      </div>
      <p className="text-slate-200 text-xs font-medium truncate">{name}</p>
      <p className="text-slate-500 text-[10px] truncate">{resourceType}</p>
    </div>
  )
})
