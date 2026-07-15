export function ScoreGauge({ score }: { score: number }) {
  const color = score >= 80 ? 'bg-green-500' : score >= 50 ? 'bg-yellow-500' : 'bg-red-500'
  return (
    <div className="w-full bg-slate-800 rounded-full h-2 mt-2">
      <div className={`${color} h-2 rounded-full transition-all`} style={{ width: `${score}%` }} />
    </div>
  )
}

export function scoreColor(score: number): string {
  return score >= 80 ? 'text-green-400' : score >= 50 ? 'text-yellow-400' : 'text-red-400'
}

export function scoreBgColor(score: number): string {
  return score >= 80 ? 'bg-green-500/20' : score >= 50 ? 'bg-yellow-500/20' : 'bg-red-500/20'
}
