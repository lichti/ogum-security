import { scoreColor } from './ScoreGauge'

interface ScoreDualityProps {
  scoreByControl: number
  scoreByAsset: number
  unscoredCount: number
  catalogAvailable: boolean
}

export function ScoreDuality({ scoreByControl, scoreByAsset, unscoredCount, catalogAvailable }: ScoreDualityProps) {
  return (
    <div className="flex flex-wrap items-center gap-6">
      <div title="Share of controls with zero failing assets. Controls with no evaluated asset yet (Unscored) are excluded from this ratio.">
        <div className={`text-xl font-bold font-mono ${scoreColor(scoreByControl)}`}>{scoreByControl}%</div>
        <div className="text-xs text-slate-500">By control</div>
      </div>
      <div title="Share of individual asset checks passing (each asset+control evaluation counted separately) — the same score shown before this dashboard split it in two.">
        <div className={`text-xl font-bold font-mono ${scoreColor(scoreByAsset)}`}>{scoreByAsset}%</div>
        <div className="text-xs text-slate-500">By asset</div>
      </div>
      {catalogAvailable && (
        <div
          title="Controls this framework defines that no asset has been evaluated against yet — neither passing nor failing."
        >
          <div className="text-xl font-bold font-mono text-slate-400">{unscoredCount}</div>
          <div className="text-xs text-slate-500">Unscored</div>
        </div>
      )}
    </div>
  )
}
