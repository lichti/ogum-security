'use client'
import { useEffect, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { FrameworkSidebar } from '@/components/compliance/FrameworkSidebar'
import { FrameworkDetail } from '@/components/compliance/FrameworkDetail'
import { TopFailingControls } from '@/components/compliance/TopFailingControls'
import { complianceApi } from '@/lib/api'

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
  const [selectedFamily, setSelectedFamily] = useState<string | null>(null)
  const [selectedVersionId, setSelectedVersionId] = useState<string | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['compliance-summary'],
    queryFn: () => complianceApi.summary().then((r) => r.data.data),
  })

  const families = data?.families ?? []
  const threatScore = data?.threat_score ?? 0

  const activeFamily = families.find((f) => f.family === selectedFamily) ?? families[0] ?? null
  const activeVersion =
    activeFamily?.versions.find((v) => v.id === selectedVersionId) ?? activeFamily?.versions[0] ?? null

  // Scoped top-failing query — only fires once a framework version is actually selected.
  const { data: scopedData } = useQuery({
    queryKey: ['compliance-summary', activeVersion?.id],
    queryFn: () => complianceApi.summary(activeVersion!.id).then((r) => r.data.data),
    enabled: !!activeVersion,
  })

  const topFailing = activeVersion ? (scopedData?.top_failing ?? []) : (data?.top_failing ?? [])

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
        {/* Header */}
        <div className="flex items-start justify-between mb-8">
          <div>
            <h1 className="text-2xl font-bold text-slate-100">Compliance</h1>
            <p className="text-slate-500 text-sm mt-1">Framework scores and control status</p>
          </div>
          <ThreatScoreBadge score={threatScore} />
        </div>

        <div className="grid grid-cols-[300px_1fr] gap-6">
          <FrameworkSidebar families={families} selectedFamily={activeFamily?.family ?? null} onSelect={handleFamilySelect} />

          <div className="space-y-6">
            {activeFamily && activeVersion && (
              <FrameworkDetail
                family={activeFamily}
                selectedVersionId={activeVersion.id}
                onVersionChange={setSelectedVersionId}
              />
            )}

            <TopFailingControls items={topFailing} scopeLabel={activeFamily?.label ?? null} />
          </div>
        </div>
      </div>
    </div>
  )
}
