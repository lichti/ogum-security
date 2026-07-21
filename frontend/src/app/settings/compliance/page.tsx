'use client'
import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { settingsApi } from '@/lib/api'
import type { ComplianceFamilySettingsView } from '@/lib/types'

function TargetInput({ value, onChange }: { value: number | null; onChange: (next: number | null) => void }) {
  return (
    <div className="flex items-center gap-1">
      <input
        type="number"
        min={0}
        max={100}
        placeholder="—"
        value={value ?? ''}
        onChange={(e) => onChange(e.target.value === '' ? null : Number(e.target.value))}
        className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-sm text-slate-200 w-20"
      />
      <span className="text-slate-500 text-xs">%</span>
    </div>
  )
}

function ComplianceSettingsRow({ row }: { row: ComplianceFamilySettingsView }) {
  const queryClient = useQueryClient()
  const [draft, setDraft] = useState(row.target_by_control)
  const [enabled, setEnabled] = useState(row.enabled)

  useEffect(() => {
    setDraft(row.target_by_control)
    setEnabled(row.enabled)
  }, [row])

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['compliance-settings'] })

  const saveTarget = useMutation({
    mutationFn: () =>
      settingsApi.updateCompliance(row.family_key, {
        target_by_control: draft ?? undefined,
        clear_target_by_control: draft === null,
      }),
    onSuccess: invalidate,
  })

  const toggleEnabled = useMutation({
    mutationFn: (next: boolean) => settingsApi.updateCompliance(row.family_key, { enabled: next }),
    onError: () => setEnabled(row.enabled), // roll back the optimistic flip
    onSuccess: invalidate,
  })

  const isDirty = draft !== row.target_by_control

  return (
    <tr data-testid={`compliance-settings-row-${row.family_key}`} className={enabled ? '' : 'opacity-50'}>
      <td className="py-2 pr-4">
        <input
          type="checkbox"
          checked={enabled}
          onChange={(e) => {
            setEnabled(e.target.checked) // optimistic — flips immediately, invalidate() confirms on success
            toggleEnabled.mutate(e.target.checked)
          }}
          className="w-4 h-4 accent-orange-500"
          aria-label={`Enable ${row.family_label} on the Compliance page`}
        />
      </td>
      <td className="py-2 pr-4">
        <TargetInput value={draft} onChange={setDraft} />
      </td>
      <td className="py-2 pr-4 text-sm text-slate-200">{row.family_label}</td>
      <td className="py-2">
        {isDirty && (
          <button
            type="button"
            onClick={() => saveTarget.mutate()}
            disabled={saveTarget.isPending}
            className="px-3 py-1 bg-orange-500 hover:bg-orange-600 disabled:opacity-50 text-white text-xs font-medium rounded-lg transition-colors"
          >
            {saveTarget.isPending ? 'Saving...' : 'Save'}
          </button>
        )}
      </td>
    </tr>
  )
}

export default function ComplianceSettingsPage() {
  const { data, isLoading } = useQuery({
    queryKey: ['compliance-settings'],
    queryFn: () => settingsApi.listCompliance().then((r) => r.data.data),
  })

  return (
    <div id="settings-compliance-page" className="min-h-screen bg-slate-950 text-slate-200">
      <div className="max-w-screen-lg mx-auto px-6 py-8">
        <p className="text-slate-500 text-sm mt-1 mb-6">
          Choose which frameworks are listed on the Compliance page — and count toward ThreatScore and the top
          failing checks list — and set a target By Control score. Disabled frameworks stay listed here so they can
          be re-enabled; the target shows as a vs-goal indicator wherever the score already appears.
        </p>

        {isLoading ? (
          <p className="text-slate-600 text-sm">Loading…</p>
        ) : !data || data.length === 0 ? (
          <p className="text-slate-600 text-sm">
            No frameworks discovered yet — settings appear here once the first CSPM scan produces compliance
            findings.
          </p>
        ) : (
          <table id="compliance-settings-table" className="w-full text-left">
            <thead>
              <tr className="border-b border-slate-800 text-xs text-slate-500 uppercase tracking-wider">
                <th className="py-2 pr-4 font-medium">Enabled</th>
                <th className="py-2 pr-4 font-medium">Goal</th>
                <th className="py-2 pr-4 font-medium">Framework</th>
                <th className="py-2 font-medium" />
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {data.map((row) => (
                <ComplianceSettingsRow key={row.family_key} row={row} />
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
