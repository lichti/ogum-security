import { memo } from 'react'
import { Handle, Position, type NodeProps } from '@xyflow/react'
import { Server } from 'lucide-react'

const SEVERITY_COLOR: Record<string, string> = {
  CRITICAL: 'text-red-400',
  HIGH: 'text-orange-400',
  MEDIUM: 'text-yellow-400',
  LOW: 'text-blue-400',
}

export const ResourceNode = memo(function ResourceNode({ data, selected }: NodeProps) {
  const node = data['node'] as Record<string, unknown>
  const name =
    (node['name'] as string | undefined) ??
    (node['resource_id'] as string | undefined) ??
    'Unknown'
  const resourceType = (node['resource_type'] as string | undefined) ?? 'resource'
  const severity = node['max_severity'] as string | undefined

  return (
    <div
      className={`bg-slate-800 border rounded-lg px-3 py-2 w-44 shadow-lg transition-colors ${
        selected ? 'border-orange-500 shadow-orange-900/20' : 'border-slate-700'
      }`}
    >
      <Handle type="target" position={Position.Left} className="!bg-slate-600 !border-slate-500" />
      <Handle type="source" position={Position.Right} className="!bg-slate-600 !border-slate-500" />
      <div className="flex items-center gap-1.5 mb-1">
        <Server size={12} className="text-slate-400 shrink-0" />
        {severity && (
          <span className={`text-[10px] font-semibold uppercase tracking-wide ${SEVERITY_COLOR[severity] ?? 'text-slate-400'}`}>
            {severity}
          </span>
        )}
      </div>
      <p className="text-slate-200 text-xs font-medium truncate">{name}</p>
      <p className="text-slate-500 text-[10px] truncate">{resourceType}</p>
    </div>
  )
})
