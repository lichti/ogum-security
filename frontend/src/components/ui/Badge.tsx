import { clsx } from 'clsx'

export type BadgeVariant =
  | 'provider-aws'
  | 'provider-azure'
  | 'provider-gcp'
  | 'provider-k8s'
  | 'status-active'
  | 'status-deleted'
  | 'severity-critical'
  | 'severity-high'
  | 'severity-medium'
  | 'severity-low'
  | 'severity-info'
  | 'default'

interface BadgeProps {
  variant?: BadgeVariant
  children: React.ReactNode
  className?: string
}

const variantClasses: Record<BadgeVariant, string> = {
  'provider-aws': 'bg-amber-500/10 text-amber-400 border border-amber-500/30',
  'provider-azure': 'bg-blue-500/10 text-blue-400 border border-blue-500/30',
  'provider-gcp': 'bg-blue-500/10 text-blue-300 border border-blue-400/30',
  'provider-k8s': 'bg-blue-600/10 text-blue-400 border border-blue-600/30',
  'status-active': 'bg-green-950 text-green-400 border border-green-800',
  'status-deleted': 'bg-slate-800 text-slate-500 border border-slate-700',
  'severity-critical': 'bg-red-950 text-red-400 border border-red-800',
  'severity-high': 'bg-orange-950 text-orange-400 border border-orange-800',
  'severity-medium': 'bg-yellow-950 text-yellow-400 border border-yellow-800',
  'severity-low': 'bg-blue-950 text-blue-400 border border-blue-800',
  'severity-info': 'bg-slate-800 text-slate-400 border border-slate-700',
  default: 'bg-slate-800 text-slate-300 border border-slate-700',
}

export function Badge({ variant = 'default', children, className }: BadgeProps) {
  return (
    <span
      className={clsx(
        'inline-flex items-center px-2 py-0.5 rounded text-xs font-medium',
        variantClasses[variant],
        className,
      )}
    >
      {children}
    </span>
  )
}
