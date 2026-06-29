'use client'
import { clsx } from 'clsx'

const PROVIDERS = [
  { key: 'all', label: 'All' },
  { key: 'aws', label: 'AWS' },
  { key: 'azure', label: 'Azure' },
  { key: 'gcp', label: 'GCP' },
  { key: 'k8s', label: 'Kubernetes' },
] as const

interface ProviderTabsProps {
  active: string
  counts: Record<string, number>
  onChange: (provider: string) => void
}

export function ProviderTabs({ active, counts, onChange }: ProviderTabsProps) {
  const total = Object.values(counts).reduce((s, n) => s + n, 0)
  return (
    <div className="flex gap-1 border-b border-slate-700">
      {PROVIDERS.map(({ key, label }) => {
        const count = key === 'all' ? total : (counts[key] ?? 0)
        return (
          <button
            key={key}
            onClick={() => onChange(key)}
            className={clsx(
              'px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors',
              active === key
                ? 'border-orange-500 text-orange-400'
                : 'border-transparent text-slate-400 hover:text-slate-200',
            )}
          >
            {label}
            <span
              className={clsx(
                'ml-1.5 rounded px-1.5 py-0.5 text-xs',
                active === key
                  ? 'bg-orange-950 text-orange-400'
                  : 'bg-slate-800 text-slate-400',
              )}
            >
              {count}
            </span>
          </button>
        )
      })}
    </div>
  )
}
