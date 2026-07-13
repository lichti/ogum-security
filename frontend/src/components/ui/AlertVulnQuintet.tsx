import type { SeverityLevel } from '@/lib/types'

const ORDER: { level: SeverityLevel; letter: string; classes: string }[] = [
  { level: 'CRITICAL', letter: 'C', classes: 'bg-red-950 text-red-400' },
  { level: 'HIGH', letter: 'H', classes: 'bg-orange-950 text-orange-400' },
  { level: 'MEDIUM', letter: 'M', classes: 'bg-yellow-950 text-yellow-400' },
  { level: 'LOW', letter: 'L', classes: 'bg-blue-950 text-blue-400' },
  { level: 'INFORMATIONAL', letter: 'I', classes: 'bg-slate-800 text-slate-400' },
]

interface AlertVulnQuintetProps {
  counts: Partial<Record<SeverityLevel, number>>
  className?: string
}

export function AlertVulnQuintet({ counts, className }: AlertVulnQuintetProps) {
  return (
    <div className={`inline-flex items-center gap-0.5${className ? ` ${className}` : ''}`}>
      {ORDER.map(({ level, letter, classes }) => {
        const count = counts[level] ?? 0
        return (
          <span
            key={level}
            title={level}
            className={`w-6 text-center text-xs font-semibold rounded-sm ${count === 0 ? 'text-slate-600 bg-slate-900' : classes}`}
          >
            <span className="sr-only">{letter}: </span>
            {count === 0 ? '—' : count}
          </span>
        )
      })}
    </div>
  )
}
