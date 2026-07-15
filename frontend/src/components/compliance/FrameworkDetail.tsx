'use client'
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
import type { ComplianceFamily, ComplianceVersion } from '@/lib/types'

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

export function FrameworkDetail({ family, selectedVersionId, onVersionChange }: FrameworkDetailProps) {
  const version = family.versions.find((v) => v.id === selectedVersionId) ?? family.versions[0]

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
      <div className="flex items-center justify-between mt-4">
        <div className="flex gap-6 text-sm">
          <div>
            <span className="text-slate-500">Pass </span>
            <span className="text-green-400 font-mono font-semibold">{version.pass}</span>
          </div>
          <div>
            <span className="text-slate-500">Fail </span>
            <span className="text-red-400 font-mono font-semibold">{version.fail}</span>
          </div>
          <div>
            <span className="text-slate-500">Total </span>
            <span className="text-slate-300 font-mono font-semibold">{version.total}</span>
          </div>
        </div>
        <Link
          href={`/findings?framework=${encodeURIComponent(version.id)}`}
          className="flex items-center gap-1.5 text-xs text-orange-400 hover:text-orange-300 transition-colors"
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
            unscoredCount={detail.unscored_count}
            catalogAvailable={detail.catalog_available}
          />

          <div>
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">
              Sections ({detail.sections.length})
            </h3>
            <SectionHeatmap sections={detail.sections} />
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
