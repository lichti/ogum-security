'use client'
import { useState } from 'react'
import Link from 'next/link'
import { ExternalLink } from 'lucide-react'
import { clsx } from 'clsx'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { ScoreGauge, scoreColor } from './ScoreGauge'
import { GoalIndicator } from './GoalIndicator'
import { Sections } from './Sections'
import { ScoreTrendChart } from './ScoreTrendChart'
import { ControlDrilldownPanel } from './ControlDrilldownPanel'
import { complianceApi, settingsApi } from '@/lib/api'
import type {
  ComplianceFamily,
  ComplianceFrameworkDetail,
  ComplianceRequirementNode,
  ComplianceVersion,
} from '@/lib/types'

interface FrameworkDetailProps {
  family: ComplianceFamily
  selectedVersionId: string
  onVersionChange: (versionId: string) => void
}

function VersionTabs({
  versions,
  selectedVersionId,
  onVersionChange,
}: {
  versions: ComplianceVersion[]
  selectedVersionId: string
  onVersionChange: (versionId: string) => void
}) {
  if (versions.length <= 1) return null
  return (
    <div id="framework-version-tabs" className="flex flex-wrap gap-1.5 mb-4" role="tablist" aria-label="Framework version">
      {versions.map((v) => (
        <button
          key={v.id}
          role="tab"
          aria-selected={v.id === selectedVersionId}
          onClick={() => onVersionChange(v.id)}
          className={clsx(
            'px-2.5 py-1 rounded text-xs font-medium border transition-colors',
            v.id === selectedVersionId
              ? 'border-orange-500 bg-orange-500/10 text-orange-300'
              : 'border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-600',
          )}
        >
          {v.version_label || v.id}
        </button>
      ))}
    </div>
  )
}

function Count({ label, value, className }: { label: string; value: number; className: string }) {
  return (
    <div>
      <span className="text-slate-500">{label} </span>
      <span className={`font-mono font-semibold ${className}`}>{value}</span>
    </div>
  )
}

function StatusCounts({ detail }: { detail: ComplianceFrameworkDetail }) {
  return (
    <div id="framework-status-counts" className="flex flex-wrap gap-6 text-sm">
      <Count label="Pass" value={detail.control_pass_count} className="text-green-400" />
      <Count label="Fail" value={detail.control_fail_count} className="text-red-400" />
      <Count label="Unscored" value={detail.control_unscored_count} className="text-slate-400" />
      <Count label="Total" value={detail.control_total} className="text-slate-300" />
    </div>
  )
}

export function FrameworkDetail({ family, selectedVersionId, onVersionChange }: FrameworkDetailProps) {
  const version = family.versions.find((v) => v.id === selectedVersionId) ?? family.versions[0]
  const queryClient = useQueryClient()
  const [saving, setSaving] = useState(false)
  const [openControl, setOpenControl] = useState<ComplianceRequirementNode | null>(null)

  const { data: detail, isLoading: detailLoading } = useQuery({
    queryKey: ['compliance-framework-detail', version?.id],
    queryFn: () => complianceApi.frameworkDetail(version!.id).then((r) => r.data.data),
    enabled: !!version,
  })

  // Lets a goal be set/changed right on /compliance instead of only on the
  // dedicated Compliance Settings page — same underlying per-family target,
  // just edited from wherever the score is already visible.
  const setTarget = useMutation({
    mutationFn: (value: number | null) =>
      settingsApi.updateCompliance(
        family.family,
        value === null ? { clear_target_by_control: true } : { target_by_control: value },
      ),
    onMutate: () => setSaving(true),
    onSettled: () => setSaving(false),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['compliance-summary'] })
      queryClient.invalidateQueries({ queryKey: ['compliance-framework-detail', version?.id] })
      queryClient.invalidateQueries({ queryKey: ['compliance-settings'] })
    },
  })

  if (!version) return null

  return (
    <section id="compliance-framework-detail" className="bg-slate-900 border border-slate-800 rounded-lg p-5">
      <div className="flex items-start justify-between mb-1">
        <h2 className="text-slate-200 font-semibold text-lg">{family.label}</h2>
        <div
          className={
            detail?.catalog_available
              ? 'grid grid-cols-[auto_auto] gap-x-4 gap-y-0.5 items-baseline'
              : 'text-right'
          }
        >
          {detail?.catalog_available && (
            <div
              className="text-xl font-bold font-mono text-slate-400 text-right leading-none"
              title="Controls this framework defines that no asset has been evaluated against yet — not failing, and counted toward the score same as Pass."
            >
              {detail.control_unscored_count}
            </div>
          )}
          <div className={`text-2xl font-bold font-mono text-right leading-none ${scoreColor(version.score)}`}>
            {version.score}%
          </div>
          {detail?.catalog_available && <div className="text-xs text-slate-500 text-center">Unscored</div>}
          {detail && (
            <div className="text-center">
              <GoalIndicator
                score={version.score}
                target={detail.target_by_control}
                onSetTarget={(value) => setTarget.mutate(value)}
                saving={saving}
              />
            </div>
          )}
        </div>
      </div>

      <VersionTabs versions={family.versions} selectedVersionId={version.id} onVersionChange={onVersionChange} />

      <ScoreGauge score={version.score} />

      <div className="flex items-center justify-between mt-2">
        {detail ? (
          <StatusCounts detail={detail} />
        ) : (
          <div className="flex gap-6 text-sm">
            <Count label="Pass" value={version.pass} className="text-green-400" />
            <Count label="Fail" value={version.fail} className="text-red-400" />
            <Count label="Total" value={version.total} className="text-slate-300" />
          </div>
        )}
        <Link
          href={`/findings?framework=${encodeURIComponent(version.id)}`}
          className="flex items-center gap-1.5 text-xs text-orange-400 hover:text-orange-300 transition-colors flex-shrink-0 ml-4"
        >
          View findings
          <ExternalLink className="w-3 h-3" />
        </Link>
      </div>

      {detailLoading && <p className="text-slate-600 text-sm mt-5 pt-4 border-t border-slate-800">Loading detail…</p>}

      {detail && (
        <div className="mt-5 pt-4 border-t border-slate-800 space-y-6">
          <ScoreTrendChart frameworkId={version.id} />

          <Sections sections={detail.sections} onOpenControl={setOpenControl} />
        </div>
      )}

      {openControl && (
        <ControlDrilldownPanel
          frameworkId={version.id}
          controlId={openControl.control_id}
          title={openControl.name}
          onClose={() => setOpenControl(null)}
        />
      )}
    </section>
  )
}
