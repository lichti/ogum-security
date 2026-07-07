interface RiskBadgeProps {
  score: number | null | undefined
  className?: string
}

function riskTier(score: number): { label: string; badgeClass: string } {
  if (score >= 75) return { label: 'CRITICAL', badgeClass: 'text-red-400 bg-red-500/10 border-red-500/30' }
  if (score >= 50) return { label: 'HIGH', badgeClass: 'text-orange-400 bg-orange-500/10 border-orange-500/30' }
  if (score >= 25) return { label: 'MEDIUM', badgeClass: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30' }
  if (score > 0) return { label: 'LOW', badgeClass: 'text-blue-400 bg-blue-500/10 border-blue-500/30' }
  return { label: 'NONE', badgeClass: 'text-slate-500 bg-slate-800/50 border-slate-700/30' }
}

export function RiskBadge({ score, className }: RiskBadgeProps) {
  if (score == null) {
    return <span className={`text-slate-600 text-xs${className ? ` ${className}` : ''}`}>—</span>
  }

  const { label, badgeClass } = riskTier(score)

  return (
    <div className={`flex items-center gap-1.5${className ? ` ${className}` : ''}`}>
      <span
        className={`inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium border ${badgeClass}`}
        title={`Risk score: ${score}`}
      >
        {score}
      </span>
      <span className="text-slate-600 text-xs hidden xl:inline">{label}</span>
    </div>
  )
}
