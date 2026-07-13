interface RiskScoreBadgeProps {
  score: number
  className?: string
}

function scoreTier(score: number): string {
  if (score >= 9.0) return 'border-red-500 text-red-400'
  if (score >= 7.0) return 'border-orange-500 text-orange-400'
  if (score >= 4.0) return 'border-yellow-500 text-yellow-400'
  return 'border-blue-500 text-blue-400'
}

export function RiskScoreBadge({ score, className }: RiskScoreBadgeProps) {
  return (
    <span
      className={`inline-flex items-center justify-center px-1.5 py-0.5 rounded bg-slate-800 border-2 font-mono font-semibold text-sm ${scoreTier(score)}${className ? ` ${className}` : ''}`}
      title={`Score: ${score.toFixed(1)}`}
    >
      {score.toFixed(1)}
    </span>
  )
}
