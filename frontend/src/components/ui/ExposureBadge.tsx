export type ExposureLevel = 'internet_facing' | 'public_facing' | 'trusted_access' | 'none'

const EXPOSURE_META: Record<ExposureLevel, { label: string; icon: string; classes: string; tooltip: string }> = {
  internet_facing: {
    label: 'Internet Facing',
    icon: '⊕',
    classes: 'text-red-400 bg-red-950 border-red-800',
    tooltip: 'Has a route to the public internet via an Internet Gateway or NAT device.',
  },
  public_facing: {
    label: 'Public Facing',
    icon: '⊙',
    classes: 'text-red-400 bg-red-950 border-red-800',
    tooltip: 'Has a public IP assigned, regardless of whether a route to it exists.',
  },
  trusted_access: {
    label: 'Trusted Access',
    icon: '◐',
    classes: 'text-slate-400 bg-slate-800 border-slate-700',
    tooltip: 'Only reachable from within a trusted network (VPC peering, private link).',
  },
  none: {
    label: 'None',
    icon: '',
    classes: 'text-slate-500 bg-slate-800 border-slate-700',
    tooltip: 'No network exposure detected.',
  },
}

interface ExposureBadgeProps {
  exposure: ExposureLevel
  className?: string
}

export function ExposureBadge({ exposure, className }: ExposureBadgeProps) {
  const meta = EXPOSURE_META[exposure]
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium border ${meta.classes}${className ? ` ${className}` : ''}`}
    >
      {meta.icon && <span aria-hidden="true">{meta.icon}</span>}
      {meta.label}
      <span title={meta.tooltip} aria-label={`${meta.label} explanation`} className="text-slate-500 cursor-help">
        ?
      </span>
    </span>
  )
}
