import { Badge } from '@/components/ui/Badge'
import type { BadgeVariant } from '@/components/ui/Badge'
import type { SeverityLevel } from '@/lib/types'

const SEV_VARIANT: Record<SeverityLevel, BadgeVariant> = {
  CRITICAL: 'severity-critical',
  HIGH: 'severity-high',
  MEDIUM: 'severity-medium',
  LOW: 'severity-low',
  INFORMATIONAL: 'severity-info',
}

interface SeverityBadgeProps {
  severity: SeverityLevel
  className?: string
}

export function SeverityBadge({ severity, className }: SeverityBadgeProps) {
  return (
    <Badge variant={SEV_VARIANT[severity]} className={className}>
      {severity}
    </Badge>
  )
}
