import { scoreBgColor, scoreColor } from './ScoreGauge'
import type { ComplianceSectionNode } from '@/lib/types'

export function SectionHeatmap({ sections }: { sections: ComplianceSectionNode[] }) {
  if (sections.length === 0) {
    return <p className="text-slate-600 text-sm">No sections to show yet.</p>
  }

  return (
    <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2">
      {sections.map((section) => (
        <div
          key={section.key}
          title={`${section.label}: ${section.pass_count}/${section.total} controls passing (${section.score_by_control}%), ${section.unscored_count} unscored`}
          className={`rounded-md p-3 border border-slate-800 ${scoreBgColor(section.score_by_control)}`}
        >
          <div className="text-xs text-slate-300 truncate">{section.label}</div>
          <div className={`text-lg font-bold font-mono ${scoreColor(section.score_by_control)}`}>
            {section.score_by_control}%
          </div>
          <div className="text-[11px] text-slate-500 font-mono">
            {section.pass_count}/{section.total}
          </div>
        </div>
      ))}
    </div>
  )
}
