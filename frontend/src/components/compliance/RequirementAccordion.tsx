'use client'
import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { Badge, type BadgeVariant } from '@/components/ui/Badge'
import type { ComplianceControlStatus, ComplianceRequirementNode, ComplianceSectionNode } from '@/lib/types'

function statusVariant(status: ComplianceControlStatus): BadgeVariant {
  if (status === 'PASS') return 'status-active'
  if (status === 'FAIL') return 'severity-high'
  return 'default'
}

function RequirementRow({ requirement }: { requirement: ComplianceRequirementNode }) {
  const router = useRouter()
  return (
    <div className="flex items-center justify-between py-1.5 pl-4 border-b border-slate-800/50 text-xs">
      <div className="flex items-center gap-2 min-w-0">
        <Badge variant={statusVariant(requirement.status)}>{requirement.status}</Badge>
        <span className="text-slate-300 truncate" title={requirement.description ?? undefined}>
          {requirement.name}
        </span>
      </div>
      {requirement.finding_key && (
        <button
          type="button"
          onClick={() => router.push(`/findings?finding=${requirement.finding_key}`)}
          className="text-orange-400 hover:underline flex-shrink-0 ml-2"
        >
          View finding →
        </button>
      )}
    </div>
  )
}

function SectionNode({ section, depth }: { section: ComplianceSectionNode; depth: number }) {
  const [expanded, setExpanded] = useState(false)
  const hasChildren = section.subsections.length > 0 || section.requirements.length > 0

  return (
    <div className={depth > 0 ? 'ml-4 border-l border-slate-800' : ''}>
      <button
        type="button"
        onClick={() => setExpanded((e) => !e)}
        disabled={!hasChildren}
        className="w-full flex items-center justify-between py-2 px-2 text-left hover:bg-slate-800/40 rounded disabled:hover:bg-transparent disabled:cursor-default"
      >
        <span className="text-sm text-slate-300 truncate">{section.label}</span>
        <span className="flex items-center gap-3 text-xs font-mono flex-shrink-0 ml-2">
          <span className="text-slate-500">
            {section.pass_count}/{section.total}
          </span>
          {hasChildren && <span className="text-slate-500">{expanded ? '▾' : '▸'}</span>}
        </span>
      </button>
      {expanded && (
        <div>
          {section.subsections.map((sub) => (
            <SectionNode key={sub.key} section={sub} depth={depth + 1} />
          ))}
          {section.requirements.map((req) => (
            <RequirementRow key={req.control_id} requirement={req} />
          ))}
        </div>
      )}
    </div>
  )
}

export function RequirementAccordion({ sections }: { sections: ComplianceSectionNode[] }) {
  if (sections.length === 0) {
    return <p className="text-slate-600 text-sm">No requirements to show yet.</p>
  }
  return (
    <div className="space-y-1">
      {sections.map((section) => (
        <SectionNode key={section.key} section={section} depth={0} />
      ))}
    </div>
  )
}
