import { scoreColor } from './ScoreGauge'
import type { ComplianceSectionNode } from '@/lib/types'

function barColor(score: number): string {
  return score >= 80 ? 'bg-green-500' : score >= 50 ? 'bg-yellow-500' : 'bg-red-500'
}

export function SectionHeatmap({ sections }: { sections: ComplianceSectionNode[] }) {
  if (sections.length === 0) {
    return <p className="text-slate-600 text-sm">No sections to show yet.</p>
  }

  return (
    <div className="space-y-2">
      {sections.map((section) => (
        <div
          key={section.key}
          className="flex items-center gap-3"
          title={`${section.label}: ${section.pass_count}/${section.total} controls passing (${section.score_by_control}%), ${section.unscored_count} unscored`}
        >
          <span className="text-slate-400 text-sm w-48 truncate flex-shrink-0">{section.label}</span>
          <div className="flex-1 bg-slate-800 rounded-full h-2">
            <div
              className={`${barColor(section.score_by_control)} h-2 rounded-full transition-all`}
              style={{ width: `${section.score_by_control}%` }}
            />
          </div>
          <span className={`text-xs font-mono w-12 text-right flex-shrink-0 ${scoreColor(section.score_by_control)}`}>
            {section.score_by_control}%
          </span>
          <span className="text-slate-600 text-xs font-mono w-16 text-right flex-shrink-0">
            {section.pass_count}/{section.total}
          </span>
        </div>
      ))}
    </div>
  )
}
