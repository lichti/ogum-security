'use client'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { complianceApi } from '@/lib/api'
import type { FrameworkScore, SeverityLevel } from '@/lib/types'

function ScoreGauge({ score }: { score: number }) {
  const color =
    score >= 80 ? 'bg-green-500' : score >= 50 ? 'bg-yellow-500' : 'bg-red-500'
  return (
    <div className="w-full bg-slate-800 rounded-full h-2 mt-2">
      <div className={`${color} h-2 rounded-full transition-all`} style={{ width: `${score}%` }} />
    </div>
  )
}

function FrameworkCard({
  fw,
  selected,
  onClick,
}: {
  fw: FrameworkScore
  selected: boolean
  onClick: () => void
}) {
  const color =
    fw.score >= 80
      ? 'text-green-400'
      : fw.score >= 50
        ? 'text-yellow-400'
        : 'text-red-400'

  return (
    <button
      onClick={onClick}
      className={`w-full text-left p-3 rounded border transition-colors ${
        selected
          ? 'border-orange-500 bg-orange-500/5'
          : 'border-slate-800 hover:border-slate-700 bg-slate-900'
      }`}
    >
      <div className="flex items-center justify-between">
        <span className="text-slate-300 text-sm font-medium truncate pr-2">{fw.id}</span>
        <span className={`text-sm font-bold font-mono ${color}`}>{fw.score}%</span>
      </div>
      <ScoreGauge score={fw.score} />
      <div className="flex gap-3 mt-2 text-xs text-slate-500">
        <span className="text-green-400">{fw.pass} pass</span>
        <span className="text-red-400">{fw.fail} fail</span>
      </div>
    </button>
  )
}

function ThreatScoreBadge({ score }: { score: number }) {
  const level = score >= 70 ? 'good' : score >= 40 ? 'warning' : 'critical'
  const color =
    level === 'good'
      ? 'text-green-400 border-green-500/30 bg-green-500/10'
      : level === 'warning'
        ? 'text-yellow-400 border-yellow-500/30 bg-yellow-500/10'
        : 'text-red-400 border-red-500/30 bg-red-500/10'
  const label = level === 'good' ? 'Good' : level === 'warning' ? 'Fair' : 'Critical'
  return (
    <div className={`inline-flex items-center gap-3 border rounded-lg px-4 py-3 ${color}`}>
      <div>
        <div className="text-3xl font-bold font-mono">{score}</div>
        <div className="text-xs opacity-70">/ 100</div>
      </div>
      <div>
        <div className="text-sm font-semibold">ThreatScore</div>
        <div className="text-xs opacity-70">{label}</div>
      </div>
    </div>
  )
}

export default function CompliancePage() {
  const [selectedFw, setSelectedFw] = useState<string | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['compliance-summary'],
    queryFn: () => complianceApi.summary().then((r) => r.data.data),
  })

  const frameworks = data?.frameworks ?? []
  const topFailing = data?.top_failing ?? []
  const threatScore = data?.threat_score ?? 0

  const activeFramework = frameworks.find((f) => f.id === selectedFw) ?? frameworks[0] ?? null

  if (isLoading) {
    return (
      <div className="min-h-screen bg-slate-950 flex items-center justify-center">
        <div className="text-slate-500">Loading compliance data…</div>
      </div>
    )
  }

  if (frameworks.length === 0) {
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
        {/* Header */}
        <div className="flex items-start justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-slate-100">Compliance</h1>
            <p className="text-slate-500 text-sm mt-1">Framework scores and control status</p>
          </div>
          <ThreatScoreBadge score={threatScore} />
        </div>

        <div className="grid grid-cols-[280px_1fr] gap-6">
          {/* Sidebar — framework list */}
          <div className="space-y-2">
            <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">
              Frameworks
            </h2>
            {frameworks.map((fw) => (
              <FrameworkCard
                key={fw.id}
                fw={fw}
                selected={
                  selectedFw ? fw.id === selectedFw : fw.id === (frameworks[0]?.id ?? '')
                }
                onClick={() => setSelectedFw(fw.id)}
              />
            ))}
          </div>

          {/* Main — selected framework detail + top failing */}
          <div className="space-y-6">
            {activeFramework && (
              <section className="bg-slate-900 border border-slate-800 rounded-lg p-5">
                <div className="flex items-center justify-between mb-4">
                  <h2 className="text-slate-200 font-semibold text-lg">{activeFramework.id}</h2>
                  <span className="text-2xl font-bold font-mono text-orange-400">
                    {activeFramework.score}%
                  </span>
                </div>
                <ScoreGauge score={activeFramework.score} />
                <div className="flex gap-6 mt-4 text-sm">
                  <div>
                    <span className="text-slate-500">Pass </span>
                    <span className="text-green-400 font-mono font-semibold">{activeFramework.pass}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Fail </span>
                    <span className="text-red-400 font-mono font-semibold">{activeFramework.fail}</span>
                  </div>
                  <div>
                    <span className="text-slate-500">Total </span>
                    <span className="text-slate-300 font-mono font-semibold">{activeFramework.total}</span>
                  </div>
                </div>
              </section>
            )}

            {/* Top failing controls */}
            {topFailing.length > 0 && (
              <section>
                <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">
                  Top Failing Controls
                </h2>
                <div className="space-y-2">
                  {topFailing.map((item, i) => (
                    <div
                      key={item.check_id}
                      className="flex items-center gap-3 p-3 bg-slate-900 border border-slate-800 rounded"
                    >
                      <span className="text-slate-600 text-xs font-mono w-4">{i + 1}</span>
                      <SeverityBadge severity={item.severity as SeverityLevel} />
                      <div className="flex-1 min-w-0">
                        <div className="text-slate-300 text-sm truncate">{item.title}</div>
                        <div className="text-slate-600 text-xs font-mono">{item.check_id}</div>
                      </div>
                      <span className="text-slate-500 text-sm font-mono flex-shrink-0">
                        {item.count}×
                      </span>
                    </div>
                  ))}
                </div>
              </section>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
