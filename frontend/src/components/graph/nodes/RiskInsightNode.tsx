import { memo } from 'react'
import { Handle, Position, type NodeProps } from '@xyflow/react'
import { Lightbulb, CircleDot, Lock } from 'lucide-react'

/** Synthetic node (not part of the traversal path) explaining *why* a resource is risky (US-14.12). */
export const RiskInsightNode = memo(function RiskInsightNode({ data }: NodeProps) {
  const finding = data['finding'] as Record<string, unknown>
  const title = (finding['title'] as string | undefined) ?? (finding['check_id'] as string | undefined) ?? 'Finding'
  const severity = ((finding['severity'] as string | undefined) ?? 'MEDIUM').toUpperCase()
  const status = finding['status'] as string | undefined
  const isExpandable = status === 'FAIL'
  const isContained = status === 'MUTED' || status === 'ACCEPTED'

  return (
    <div className="bg-amber-950/40 border-2 border-amber-500 rounded px-3 py-2 w-44 shadow-lg shadow-amber-900/20 relative">
      <Handle type="target" position={Position.Top} className="!bg-amber-600 !border-amber-500" />
      <div className="absolute -top-2 -right-2 flex gap-0.5">
        {isExpandable && (
          <span
            title="Expandable — active finding"
            className="w-4 h-4 rounded-full bg-amber-500 text-slate-950 text-[10px] font-bold flex items-center justify-center"
          >
            <CircleDot size={10} />
          </span>
        )}
        {isContained && (
          <span
            title="Contained/restricted — muted or accepted"
            className="w-4 h-4 rounded-full bg-slate-700 text-slate-300 text-[10px] flex items-center justify-center"
          >
            <Lock size={9} />
          </span>
        )}
      </div>
      <div className="flex items-center gap-1.5 mb-1">
        <Lightbulb size={12} className="text-amber-400 shrink-0" />
        <span className="text-amber-400 text-[10px] font-semibold uppercase tracking-wide">{severity}</span>
      </div>
      <p className="text-slate-200 text-[11px] font-medium truncate leading-tight">{title}</p>
    </div>
  )
})
