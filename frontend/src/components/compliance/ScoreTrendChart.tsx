'use client'
import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { CartesianGrid, Legend, Line, LineChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from 'recharts'
import { complianceApi } from '@/lib/api'
import type { CompliancePeriod } from '@/lib/types'

// Categorical pair validated for the dark slate-900 chart surface (dataviz skill,
// scripts/validate_palette.js) — worst-adjacent CVD ΔE 97.3, all lightness/contrast
// checks pass. Fixed assignment, not cycled: control is always the accent hue.
const COLOR_BY_CONTROL = '#d95926'
const COLOR_BY_ASSET = '#3987e5'

const PERIOD_OPTIONS: { value: CompliancePeriod; label: string }[] = [
  { value: '7d', label: '7D' },
  { value: '14d', label: '14D' },
  { value: '1m', label: '1M' },
]

function PeriodSelector({ value, onChange }: { value: CompliancePeriod; onChange: (p: CompliancePeriod) => void }) {
  return (
    <div className="flex gap-1" role="tablist" aria-label="Trend period">
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
    <section className="bg-slate-900 border border-slate-800 rounded-lg p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">Score Trend</h3>
        <PeriodSelector value={period} onChange={setPeriod} />
      </div>

      {isLoading ? (
        <div className="h-48 flex items-center justify-center text-slate-600 text-sm">Loading…</div>
      ) : points.length === 0 ? (
        <div className="h-48 flex items-center justify-center text-slate-600 text-sm text-center px-6">
          No history yet — trend starts populating after the next scan.
        </div>
      ) : (
        <div className="h-48">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={points} margin={{ top: 4, right: 8, bottom: 0, left: -16 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis dataKey="date" stroke="#64748b" tick={{ fontSize: 11 }} tickLine={false} axisLine={false} />
              <YAxis
                domain={[0, 100]}
                stroke="#64748b"
                tick={{ fontSize: 11 }}
                tickLine={false}
                axisLine={false}
                width={32}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#0f172a',
                  border: '1px solid #1e293b',
                  borderRadius: 6,
                  fontSize: 12,
                }}
                labelStyle={{ color: '#cbd5e1' }}
              />
              <Legend wrapperStyle={{ fontSize: 12 }} formatter={(value) => <span className="text-slate-400">{value}</span>} />
              <Line
                type="monotone"
                dataKey="score_by_control"
                name="By control"
                stroke={COLOR_BY_CONTROL}
                strokeWidth={2}
                dot={{ r: 3, fill: COLOR_BY_CONTROL, strokeWidth: 0 }}
                activeDot={{ r: 5 }}
              />
              <Line
                type="monotone"
                dataKey="score_by_asset"
                name="By asset"
                stroke={COLOR_BY_ASSET}
                strokeWidth={2}
                dot={{ r: 3, fill: COLOR_BY_ASSET, strokeWidth: 0 }}
                activeDot={{ r: 5 }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}
    </section>
  )
}
