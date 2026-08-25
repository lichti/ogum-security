'use client'
import { useEffect, useState } from 'react'
import { keepPreviousData, useQuery } from '@tanstack/react-query'
import { FrameworkSidebar } from '@/components/compliance/FrameworkSidebar'
import { FrameworkDetail } from '@/components/compliance/FrameworkDetail'
import { Top10Findings } from '@/components/compliance/Top10Findings'
import { Top10Assets } from '@/components/compliance/Top10Assets'
import { ComplianceDrilldownPanel, type DrilldownMode } from '@/components/compliance/ComplianceDrilldownPanel'
import { CollapsibleSection } from '@/components/ui/CollapsibleSection'
import { complianceApi } from '@/lib/api'
import type { ComplianceTopAsset, ComplianceTopCheck, SeverityLevel } from '@/lib/types'

interface DrilldownState {
  title: string
  subtitle: string
  mode: DrilldownMode
  framework?: string
}

const ALL_SEVERITIES: SeverityLevel[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']
const SEVERITY_LABEL: Record<SeverityLevel, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
  INFORMATIONAL: 'Info',
}
const SEVERITY_ACTIVE_CLASSES: Record<SeverityLevel, string> = {
  CRITICAL: 'bg-red-950 text-red-400 border-red-800',
  HIGH: 'bg-orange-950 text-orange-400 border-orange-800',
  MEDIUM: 'bg-yellow-950 text-yellow-400 border-yellow-800',
  LOW: 'bg-blue-950 text-blue-400 border-blue-800',
  INFORMATIONAL: 'bg-slate-800 text-slate-400 border-slate-700',
}
// A finding's severity is always one of ALL_SEVERITIES, so this value matches none of
// them — sent when every toggle is switched off, so the backend's `severity IN [...]`
// filter naturally returns zero rows instead of the empty-array-means-"no filter"
// ambiguity (see complianceApi.summary / serializeParams, which drops empty arrays
// entirely, making "filter to nothing" indistinguishable from "no filter" otherwise).
const NO_SEVERITIES_SENTINEL = '__none__'

function severityParam(selected: Set<SeverityLevel>): string[] | undefined {
  if (selected.size === ALL_SEVERITIES.length) return undefined
  if (selected.size === 0) return [NO_SEVERITIES_SENTINEL]
  return Array.from(selected)
}

function SeverityFilter({
  selected,
  onToggle,
}: {
  selected: Set<SeverityLevel>
  onToggle: (severity: SeverityLevel) => void
}) {
  return (
    <div className="flex gap-1.5" role="group" aria-label="Filter Top 10 Findings by severity">
      {ALL_SEVERITIES.map((sev) => {
        const active = selected.has(sev)
        return (
          <button
            key={sev}
            type="button"
            aria-pressed={active}
            onClick={() => onToggle(sev)}
            className={`px-2.5 py-1 rounded text-xs font-medium border transition-colors ${
              active
                ? SEVERITY_ACTIVE_CLASSES[sev]
                : 'border-slate-800 text-slate-600 hover:text-slate-400 hover:border-slate-700'
            }`}
          >
            {SEVERITY_LABEL[sev]}
          </button>
        )
      })}
    </div>
  )
}

export default function CompliancePage() {
  const [selectedFamily, setSelectedFamily] = useState<string | null>(null)
  const [selectedVersionId, setSelectedVersionId] = useState<string | null>(null)
  const [selectedSeverities, setSelectedSeverities] = useState<Set<SeverityLevel>>(new Set(ALL_SEVERITIES))
  const severity = severityParam(selectedSeverities)
  const [drilldown, setDrilldown] = useState<DrilldownState | null>(null)

  const openFindingDrilldown = (item: ComplianceTopCheck, framework?: string) => {
    setDrilldown({
      title: item.title,
      subtitle: item.check_id,
      mode: { kind: 'check', checkId: item.check_id },
      framework,
    })
  }

  const openAssetDrilldown = (item: ComplianceTopAsset, framework?: string) => {
    setDrilldown({
      title: item.resource_id,
      subtitle: item.resource_type,
      mode: { kind: 'resource', resourceId: item.resource_id },
      framework,
    })
  }

  const toggleSeverity = (sev: SeverityLevel) => {
    setSelectedSeverities((prev) => {
      const next = new Set(prev)
      if (next.has(sev)) next.delete(sev)
      else next.add(sev)
      return next
    })
  }

  // Always fetched (unscoped) — feeds the Global column of the risk-list comparison
  // and, before a framework version is selected, everything else too. `families` on
  // this response is never severity-filtered (only top_failing is, server-side) so
  // the sidebar stays stable as the toggle changes.
  // keepPreviousData: `severity` is part of the query key, so every toggle click is a
  // brand-new key with no cache — without this, isLoading would flip true again and
  // blank the *entire* page (sidebar, everything) just to refresh one section's risk
  // list.
  const { data, isLoading } = useQuery({
    queryKey: ['compliance-summary', undefined, severity],
    queryFn: () => complianceApi.summary(undefined, severity).then((r) => r.data.data),
    placeholderData: keepPreviousData,
  })

  const families = data?.families ?? []

  const activeFamily = families.find((f) => f.family === selectedFamily) ?? families[0] ?? null
  const activeVersion =
    activeFamily?.versions.find((v) => v.id === selectedVersionId) ?? activeFamily?.versions[0] ?? null

  // Scoped query — only fires once a framework version is actually selected. Fetched
  // in parallel with the unscoped one above so the Framework/Global comparison renders
  // both columns at once instead of swapping one dataset in and out.
  const { data: scopedData } = useQuery({
    queryKey: ['compliance-summary', activeVersion?.id, severity],
    queryFn: () => complianceApi.summary(activeVersion!.id, severity).then((r) => r.data.data),
    enabled: !!activeVersion,
    placeholderData: keepPreviousData,
  })

  const frameworkData = activeVersion ? scopedData : data
  const frameworkScopeLabel = activeFamily?.label ?? 'Framework'

  const handleFamilySelect = (familyKey: string) => {
    setSelectedFamily(familyKey)
    setSelectedVersionId(null) // reset to the family's latest version
  }

  // Keep selectedVersionId in sync once data loads and a family becomes active.
  useEffect(() => {
    if (activeFamily && !selectedVersionId) {
      setSelectedVersionId(activeFamily.versions[0]?.id ?? null)
    }
  }, [activeFamily, selectedVersionId])

  if (isLoading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="text-slate-500">Loading compliance data…</div>
      </div>
    )
  }

  if (families.length === 0) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="text-center text-slate-500">
          <p className="text-lg">No compliance data yet</p>
          <p className="text-sm mt-1">Run a CSPM scan to see framework scores.</p>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200">
      <div className="max-w-screen-xl mx-auto px-6 py-8">
        <div className="grid grid-cols-[300px_1fr] gap-6">
          {/* self-start keeps this column at its own height instead of stretching to
              match the right column, which is what lets sticky actually pin it while
              the (now much taller, with two side-by-side risk lists) right column
              scrolls past. */}
          <div className="sticky top-8 self-start">
            <FrameworkSidebar
              families={families}
              selectedFamily={activeFamily?.family ?? null}
              onSelect={handleFamilySelect}
            />
          </div>

          <div className="space-y-6">
            {activeFamily && activeVersion && (
              <FrameworkDetail
                family={activeFamily}
                selectedVersionId={activeVersion.id}
                onVersionChange={setSelectedVersionId}
              />
            )}

            <CollapsibleSection
              title="Top 10 Findings"
              headerExtra={<SeverityFilter selected={selectedSeverities} onToggle={toggleSeverity} />}
            >
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Top10Findings
                  items={frameworkData?.top_failing ?? []}
                  scopeLabel={frameworkScopeLabel}
                  onSelect={(item) => openFindingDrilldown(item, activeVersion?.id)}
                />
                <Top10Findings
                  items={data?.top_failing ?? []}
                  scopeLabel="Global"
                  onSelect={(item) => openFindingDrilldown(item, undefined)}
                />
              </div>
            </CollapsibleSection>

            <CollapsibleSection title="Top 10 Assets">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Top10Assets
                  items={frameworkData?.top_assets ?? []}
                  scopeLabel={frameworkScopeLabel}
                  onSelect={(item) => openAssetDrilldown(item, activeVersion?.id)}
                />
                <Top10Assets
                  items={data?.top_assets ?? []}
                  scopeLabel="Global"
                  onSelect={(item) => openAssetDrilldown(item, undefined)}
                />
              </div>
            </CollapsibleSection>
          </div>
        </div>
      </div>

      {drilldown && (
        <ComplianceDrilldownPanel
          title={drilldown.title}
          subtitle={drilldown.subtitle}
          mode={drilldown.mode}
          framework={drilldown.framework}
          onClose={() => setDrilldown(null)}
        />
      )}
    </div>
  )
}
