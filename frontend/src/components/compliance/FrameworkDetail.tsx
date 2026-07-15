'use client'
import { useState } from 'react'
import Link from 'next/link'
import { ExternalLink } from 'lucide-react'
import { clsx } from 'clsx'
import { useQuery } from '@tanstack/react-query'
import { ScoreGauge, scoreColor } from './ScoreGauge'
import { ScoreDuality } from './ScoreDuality'
import { SectionHeatmap } from './SectionHeatmap'
import { RequirementAccordion } from './RequirementAccordion'
import { ScoreTrendChart } from './ScoreTrendChart'
import { complianceApi } from '@/lib/api'
import type { ComplianceFamily, ComplianceFrameworkDetail, ComplianceVersion, ComplianceView } from '@/lib/types'

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
    <div className="flex flex-wrap gap-1.5 mb-4" role="tablist" aria-label="Framework version">
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

function ViewToggle({ view, onChange }: { view: ComplianceView; onChange: (v: ComplianceView) => void }) {
  return (
    <div className="flex gap-1" role="tablist" aria-label="Compliance view">
      {(
        [
          { value: 'control', label: 'By Control' },
          { value: 'findings', label: 'By Findings' },
        ] as const
      ).map((opt) => (
        <button
          key={opt.value}
          role="tab"
          aria-selected={opt.value === view}
          onClick={() => onChange(opt.value)}
          className={clsx(
            'px-2.5 py-1 rounded text-xs font-medium border transition-colors',
            opt.value === view
              ? 'border-orange-500 bg-orange-500/10 text-orange-300'
              : 'border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-600',
          )}
        >
          {opt.label}
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

function StatusCounts({ detail, view }: { detail: ComplianceFrameworkDetail; view: ComplianceView }) {
  if (view === 'control') {
    return (
      <div className="flex flex-wrap gap-6 text-sm">
        <Count label="Pass" value={detail.control_pass_count} className="text-green-400" />
        <Count label="Fail" value={detail.control_fail_count} className="text-red-400" />
        <Count label="Unscored" value={detail.control_unscored_count} className="text-slate-400" />
        <Count label="Total" value={detail.control_total} className="text-slate-300" />
      </div>
    )
  }
  const total =
    detail.finding_pass_count +
    detail.finding_fail_count +
    detail.finding_accepted_count +
    detail.finding_muted_count +
    detail.control_unscored_count
  return (
    <div className="flex flex-wrap gap-6 text-sm">
      <Count label="Pass" value={detail.finding_pass_count} className="text-green-400" />
      <Count label="Fail" value={detail.finding_fail_count} className="text-red-400" />
      <Count label="Accepted" value={detail.finding_accepted_count} className="text-blue-400" />
      <Count label="Muted" value={detail.finding_muted_count} className="text-slate-500" />
      <Count label="Unscored" value={detail.control_unscored_count} className="text-slate-400" />
      <Count label="Total" value={total} className="text-slate-300" />
    </div>
  )
}

export function FrameworkDetail({ family, selectedVersionId, onVersionChange }: FrameworkDetailProps) {
  const version = family.versions.find((v) => v.id === selectedVersionId) ?? family.versions[0]
  const [view, setView] = useState<ComplianceView>('control')

  const { data: detail, isLoading: detailLoading } = useQuery({
    queryKey: ['compliance-framework-detail', version?.id],
    queryFn: () => complianceApi.frameworkDetail(version!.id).then((r) => r.data.data),
    enabled: !!version,
  })

  if (!version) return null

  return (
    <section className="bg-slate-900 border border-slate-800 rounded-lg p-5">
      <div className="flex items-start justify-between mb-1">
        <h2 className="text-slate-200 font-semibold text-lg">{family.label}</h2>
        <span className={`text-2xl font-bold font-mono ${scoreColor(version.score)}`}>{version.score}%</span>
      </div>

      <VersionTabs versions={family.versions} selectedVersionId={version.id} onVersionChange={onVersionChange} />

      <ScoreGauge score={version.score} />

      {detail && (
        <div className="flex justify-end mt-3">
          <ViewToggle view={view} onChange={setView} />
        </div>
      )}

      <div className="flex items-center justify-between mt-2">
        {detail ? (
          <StatusCounts detail={detail} view={view} />
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
          <ScoreDuality
            scoreByControl={detail.score_by_control}
            scoreByAsset={detail.score_by_asset}
            unscoredCount={detail.control_unscored_count}
            catalogAvailable={detail.catalog_available}
          />

          <div>
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">
              Sections ({detail.sections.length})
            </h3>
            <SectionHeatmap sections={detail.sections} view={view} />
          </div>

          <ScoreTrendChart frameworkId={version.id} />

          <div>
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">Requirements</h3>
            <RequirementAccordion sections={detail.sections} />
          </div>
        </div>
      )}
    </section>
  )
}
