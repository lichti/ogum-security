'use client'
import Link from 'next/link'
import { ExternalLink } from 'lucide-react'
import { clsx } from 'clsx'
import { ScoreGauge, scoreColor } from './ScoreGauge'
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

      {version.sections.length > 0 && (
        <div className="mt-5 pt-4 border-t border-slate-800 space-y-2">
          <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-2">
            Sections ({version.sections.length})
          </h3>
          {version.sections.map((sec) => (
            <div key={sec.key} className="flex items-center gap-3">
              <span className="text-slate-400 text-sm w-48 truncate flex-shrink-0" title={sec.label}>
                {sec.label}
              </span>
              <div className="flex-1">
                <ScoreGauge score={sec.score} />
              </div>
              <span className={`text-xs font-mono w-12 text-right flex-shrink-0 ${scoreColor(sec.score)}`}>
                {sec.score}%
              </span>
              <span className="text-slate-600 text-xs font-mono w-16 text-right flex-shrink-0">
                {sec.pass}/{sec.total}
              </span>
            </div>
          ))}
        </div>
      )}
    </section>
  )
}
