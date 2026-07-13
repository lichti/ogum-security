export type SLAStatus = 'within_sla' | 'at_risk' | 'overdue'

const SLA_META: Record<SLAStatus, { label: string; classes: string }> = {
  within_sla: { label: 'Within SLA', classes: 'text-green-400 bg-green-950 border-green-800' },
  at_risk: { label: 'At Risk', classes: 'text-yellow-400 bg-yellow-950 border-yellow-800' },
  overdue: { label: 'Overdue', classes: 'text-red-400 bg-red-950 border-red-800' },
}

interface SLABadgeProps {
  status: SLAStatus
  className?: string
}

export function SLABadge({ status, className }: SLABadgeProps) {
  const meta = SLA_META[status]
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${meta.classes}${className ? ` ${className}` : ''}`}
    >
      {meta.label}
    </span>
  )
}

/** At Risk = within 20% of the remaining SLA window. Overdue = past the deadline. */
export function classifySLA(detectedAt: Date, deadlineDays: number, now: Date = new Date()): SLAStatus {
  const deadline = new Date(detectedAt.getTime() + deadlineDays * 24 * 60 * 60 * 1000)
  const totalMs = deadline.getTime() - detectedAt.getTime()
  const remainingMs = deadline.getTime() - now.getTime()

  if (remainingMs <= 0) return 'overdue'
  if (remainingMs <= totalMs * 0.2) return 'at_risk'
  return 'within_sla'
}
