'use client'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { CollapsibleSection } from '@/components/ui/CollapsibleSection'
import { complianceApi } from '@/lib/api'
import type { ComplianceScoreTrendPoint, CompliancePeriod } from '@/lib/types'

// Validated for the dark slate-900 chart surface (dataviz skill, scripts/validate_
// palette.js). Unscored isn't plotted alongside the score above — it's a count, not
// a %, so it lives on its own mini-chart (see the "one axis" rule: two measures of
// different scale get two charts, never a dual-axis line chart). Muted slate to match
// how "Unscored" is already inked everywhere else on this page (the framework header, StatusCounts).
const COLOR_BY_CONTROL = '#d95926'
const COLOR_UNSCORED = '#94a3b8'

const LEGEND_STYLE = { wrapperStyle: { fontSize: 12 }, formatter: (value: string) => <LegendLabel value={value} /> }

function LegendLabel({ value }: { value: string }) {
  return <span className="text-slate-400">{value}</span>
}

function TooltipRow({
  color,
  label,
  value,
  suffix,
}: {
  color: string
  label: string
  value: number | null
  suffix: string
}) {
  return (
    <div className="flex items-center justify-between gap-4">
      <span className="flex items-center gap-1.5 text-slate-400">
        <span className="w-2 h-2 rounded-full flex-shrink-0" style={{ backgroundColor: color }} />
        {label}
      </span>
      <span className="font-mono text-slate-200 tabular-nums">{value === null ? '—' : `${value}${suffix}`}</span>
    </div>
  )
}

// One combined tooltip for both stacked charts (score % and unscored count share the
// same `points` row, just plotted on two y-scales per the "no dual-axis chart" rule).
// Rendered only by the top chart — the bottom chart's Tooltip is content-suppressed
// (see `cursor`-only Tooltip below) so hovering never produces two floating boxes.
export function ScoreTrendTooltip({
  active,
  label,
  points,
}: {
  active?: boolean
  label?: string
  points: ComplianceScoreTrendPoint[]
}) {
  if (!active || !label) return null
  const point = points.find((p) => p.date === label)
  if (!point) return null
  return (
    <div className="bg-slate-950 border border-slate-800 rounded-md px-3 py-2 text-xs shadow-lg space-y-1 min-w-[180px]">
      <div className="text-slate-500 mb-1">{label}</div>
      <TooltipRow color={COLOR_BY_CONTROL} label="By control" value={point.score_by_control} suffix="%" />
      <div className="border-t border-slate-800 pt-1 mt-1">
        <TooltipRow color={COLOR_UNSCORED} label="Unscored controls" value={point.unscored_count} suffix="" />
      </div>
    </div>
  )
}

const CURSOR_STYLE = { stroke: '#334155', strokeWidth: 1 }

const PERIOD_OPTIONS: { value: CompliancePeriod; label: string }[] = [
  { value: '7d', label: '7D' },
  { value: '14d', label: '14D' },
  { value: '1m', label: '1M' },
]

function PeriodSelector({ value, onChange }: { value: CompliancePeriod; onChange: (p: CompliancePeriod) => void }) {
  return (
    <div id="score-trend-period-selector" className="flex gap-1" role="tablist" aria-label="Trend period">
      {PERIOD_OPTIONS.map((opt) => (
        <button
          key={opt.value}
          role="tab"
          aria-selected={opt.value === value}
          onClick={() => onChange(opt.value)}
          className={`px-2 py-1 rounded text-xs font-medium border transition-colors ${
            opt.value === value
              ? 'border-orange-500 bg-orange-500/10 text-orange-300'
              : 'border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-600'
          }`}
        >
          {opt.label}
        </button>
      ))}
    </div>
  )
}

export function ScoreTrendChart({ frameworkId }: { frameworkId: string }) {
  const [period, setPeriod] = useState<CompliancePeriod>('7d')

  const { data, isLoading } = useQuery({
    queryKey: ['compliance-trend', frameworkId, period],
    queryFn: () => complianceApi.trend(frameworkId, period).then((r) => r.data.data),
  })

  const points = data ?? []

  return (
    <section id="compliance-score-trend-chart" className="bg-slate-900 border border-slate-800 rounded-lg p-5">
      <CollapsibleSection
        title="Score Trend"
        headerExtra={<PeriodSelector value={period} onChange={setPeriod} />}
      >
        {isLoading ? (
          <div className="h-32 flex items-center justify-center text-slate-600 text-sm">Loading…</div>
        ) : points.length === 0 ? (
          <div className="h-32 flex items-center justify-center text-slate-600 text-sm text-center px-6">
            No history yet — trend starts populating after the next scan.
          </div>
        ) : (
          <div className="space-y-2">
            <div className="h-32">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={points} syncId="compliance-trend" margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="date" stroke="#64748b" tick={false} axisLine={false} height={4} />
                  <YAxis
                    domain={[0, 100]}
                    stroke="#64748b"
                    tick={{ fontSize: 11 }}
                    tickLine={false}
                    axisLine={false}
                    tickFormatter={(v: number) => `${v}%`}
                    width={40}
                  />
                  <Tooltip content={<ScoreTrendTooltip points={points} />} cursor={CURSOR_STYLE} />
                  <Legend {...LEGEND_STYLE} />
                  <Line
                    type="monotone"
                    dataKey="score_by_control"
                    name="By control"
                    stroke={COLOR_BY_CONTROL}
                    strokeWidth={2}
                    dot={{ r: 3, fill: COLOR_BY_CONTROL, strokeWidth: 0 }}
                    activeDot={{ r: 5 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>

            <div className="h-16">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={points} syncId="compliance-trend" margin={{ top: 4, right: 8, bottom: 0, left: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="date" stroke="#64748b" tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
                  <YAxis
                    allowDecimals={false}
                    stroke="#64748b"
                    tick={{ fontSize: 11 }}
                    tickLine={false}
                    axisLine={false}
                    width={32}
                  />
                  <Tooltip content={() => null} cursor={CURSOR_STYLE} />
                  <Legend {...LEGEND_STYLE} />
                  <Line
                    type="monotone"
                    dataKey="unscored_count"
                    name="Unscored controls"
                    stroke={COLOR_UNSCORED}
                    strokeWidth={2}
                    dot={{ r: 3, fill: COLOR_UNSCORED, strokeWidth: 0 }}
                    activeDot={{ r: 5 }}
                  />
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}
      </CollapsibleSection>
    </section>
  )
}
