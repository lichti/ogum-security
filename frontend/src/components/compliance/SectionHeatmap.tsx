import { scoreColor } from './ScoreGauge'
import type { ComplianceSectionNode, ComplianceView } from '@/lib/types'

function barColor(score: number): string {
  return score >= 80 ? 'bg-green-500' : score >= 50 ? 'bg-yellow-500' : 'bg-red-500'
}

export function SectionHeatmap({ sections, view }: { sections: ComplianceSectionNode[]; view: ComplianceView }) {
  if (sections.length === 0) {
    return <p className="text-slate-600 text-sm">No sections to show yet.</p>
  }

  return (
    <div className="space-y-2">
      {sections.map((section) => {
        const score = view === 'control' ? section.score_by_control : section.score_by_asset
        const title =
          view === 'control'
            ? `${section.label}: ${section.control_pass_count}/${section.control_total} controls passing (${score}%), ${section.control_unscored_count} unscored`
            : `${section.label}: ${section.finding_pass_count} pass, ${section.finding_fail_count} fail, ${section.finding_accepted_count} accepted, ${section.finding_muted_count} muted, ${section.control_unscored_count} unscored (${score}%)`
        const countLabel =
          view === 'control'
            ? `${section.control_pass_count}/${section.control_total}`
            : `${section.finding_pass_count}/${section.finding_pass_count + section.finding_fail_count}`

        return (
          <div key={section.key} className="flex items-center gap-3" title={title}>
            <span className="text-slate-400 text-sm w-48 truncate flex-shrink-0">{section.label}</span>
            <div className="flex-1 bg-slate-800 rounded-full h-2">
              <div
                className={`${barColor(score)} h-2 rounded-full transition-all`}
                style={{ width: `${score}%` }}
              />
            </div>
            <span className={`text-xs font-mono w-12 text-right flex-shrink-0 ${scoreColor(score)}`}>{score}%</span>
            <span className="text-slate-600 text-xs font-mono w-16 text-right flex-shrink-0">{countLabel}</span>
          </div>
        )
      })}
    </div>
  )
}
