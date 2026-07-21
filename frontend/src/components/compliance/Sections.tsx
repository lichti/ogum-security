'use client'
import { useState } from 'react'
import { ChevronDown, ChevronRight, HelpCircle } from 'lucide-react'
import { Badge, type BadgeVariant } from '@/components/ui/Badge'
import { scoreColor } from './ScoreGauge'
import type { ComplianceControlStatus, ComplianceRequirementNode, ComplianceSectionNode } from '@/lib/types'

function barColor(score: number): string {
  return score >= 80 ? 'bg-green-500' : score >= 50 ? 'bg-yellow-500' : 'bg-red-500'
}

function statusVariant(status: ComplianceControlStatus): BadgeVariant {
  if (status === 'PASS') return 'status-active'
  if (status === 'FAIL') return 'severity-high'
  return 'default'
}

// Only a scored control (Fail or Pass) has findings worth drilling into — an
// Unscored control has none, so it stays a static row instead of opening an empty panel.
function RequirementRow({
  requirement,
  onOpenControl,
}: {
  requirement: ComplianceRequirementNode
  onOpenControl: (requirement: ComplianceRequirementNode) => void
}) {
  const clickable = requirement.status === 'PASS' || requirement.status === 'FAIL'
  const content = (
    <div className="flex items-center gap-2 min-w-0">
      <Badge variant={statusVariant(requirement.status)}>{requirement.status}</Badge>
      <span className="text-slate-300 truncate" title={requirement.description ?? undefined}>
        {requirement.name}
      </span>
    </div>
  )

  if (!clickable) {
    return (
      <div
        data-testid={`compliance-requirement-row-${requirement.control_id}`}
        className="flex items-center py-1.5 pl-4 border-b border-slate-800/50 text-xs"
      >
        {content}
      </div>
    )
  }

  return (
    <button
      type="button"
      data-testid={`compliance-requirement-row-${requirement.control_id}`}
      onClick={() => onOpenControl(requirement)}
      className="w-full flex items-center py-1.5 pl-4 pr-2 border-b border-slate-800/50 text-xs text-left hover:bg-slate-800/40 transition-colors"
    >
      {content}
    </button>
  )
}

// A section row doubles as the heatmap bar (score + P/F/U/T, like the old
// SectionHeatmap) and the accordion toggle (like the old RequirementAccordion) —
// merged so a section's status and its requirements live in one place instead of
// two separate, redundantly-labeled lists.
function SectionRow({
  section,
  depth,
  onOpenControl,
}: {
  section: ComplianceSectionNode
  depth: number
  onOpenControl: (requirement: ComplianceRequirementNode) => void
}) {
  const [expanded, setExpanded] = useState(false)
  const hasChildren = section.subsections.length > 0 || section.requirements.length > 0
  const score = section.score_by_control
  const title = `${section.label}: ${section.control_pass_count}/${section.control_total} controls passing (${score}%), ${section.control_unscored_count} unscored`
  const countLabel = `${section.control_pass_count}/${section.control_fail_count}/${section.control_unscored_count}/${section.control_total}`

  return (
    <div
      data-testid={`compliance-section-node-${section.key}`}
      className={depth > 0 ? 'ml-4 border-l border-slate-800' : ''}
    >
      <button
        type="button"
        onClick={() => setExpanded((e) => !e)}
        disabled={!hasChildren}
        title={title}
        className="w-full flex items-center gap-3 py-2 px-2 text-left hover:bg-slate-800/40 rounded disabled:hover:bg-transparent disabled:cursor-default"
      >
        <span className="text-sm text-slate-300 truncate w-48 flex-shrink-0">{section.label}</span>
        <div className="flex-1 bg-slate-800 rounded-full h-2">
          <div className={`${barColor(score)} h-2 rounded-full transition-all`} style={{ width: `${score}%` }} />
        </div>
        <span className={`text-xs font-mono w-12 text-right flex-shrink-0 ${scoreColor(score)}`}>{score}%</span>
        <span className="text-slate-600 text-xs font-mono w-28 text-right flex-shrink-0">{countLabel}</span>
        <span className="w-4 flex-shrink-0 flex justify-center text-slate-500">
          {hasChildren ? expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} /> : null}
        </span>
      </button>
      {expanded && (
        <div>
          {section.subsections.map((sub) => (
            <SectionRow key={sub.key} section={sub} depth={depth + 1} onOpenControl={onOpenControl} />
          ))}
          {section.requirements.map((req) => (
            <RequirementRow key={req.control_id} requirement={req} onOpenControl={onOpenControl} />
          ))}
        </div>
      )}
    </div>
  )
}

const LEGEND_TITLE =
  'Pass / Fail / Unscored / Total controls in this section. Score = (Pass + Unscored) / Total; Unscored controls (no finding yet, or only muted findings) count toward the score, same as Pass. Click a section to see its requirements.'

interface SectionsProps {
  sections: ComplianceSectionNode[]
  onOpenControl: (requirement: ComplianceRequirementNode) => void
}

export function Sections({ sections, onOpenControl }: SectionsProps) {
  if (sections.length === 0) {
    return <p className="text-slate-600 text-sm">No sections to show yet.</p>
  }
  return (
    <div id="compliance-sections" className="space-y-1">
      <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">
        Sections ({sections.length})
      </h3>
      <div className="flex items-center gap-3 px-2">
        <span className="w-48 flex-shrink-0" />
        <span className="flex-1" />
        <span className="w-12 flex-shrink-0" />
        <span
          className="w-28 flex items-center justify-end gap-1 flex-shrink-0 text-slate-600 text-[10px] uppercase tracking-wide cursor-help"
          title={LEGEND_TITLE}
        >
          P/F/U/T
          <HelpCircle className="w-3 h-3" />
        </span>
        <span className="w-4 flex-shrink-0" />
      </div>
      {sections.map((section) => (
        <SectionRow key={section.key} section={section} depth={0} onOpenControl={onOpenControl} />
      ))}
    </div>
  )
}
