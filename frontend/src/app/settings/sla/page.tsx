'use client'
import { useEffect, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { settingsApi } from '@/lib/api'
import type { SLASettings } from '@/lib/types'

const FIELDS: { key: keyof SLASettings; label: string }[] = [
  { key: 'critical_days', label: 'Critical' },
  { key: 'high_days', label: 'High' },
  { key: 'medium_days', label: 'Medium' },
  { key: 'low_days', label: 'Low' },
]

export default function SlaSettingsPage() {
  const queryClient = useQueryClient()
  const { data } = useQuery({
    queryKey: ['sla-settings'],
    queryFn: () => settingsApi.getSla().then((r) => r.data.data),
  })

  const [form, setForm] = useState<SLASettings | null>(null)

  useEffect(() => {
    if (data) setForm(data)
  }, [data])

  const mutation = useMutation({
    mutationFn: (body: Partial<SLASettings>) => settingsApi.updateSla(body),
    onSuccess: (r) => {
      setForm(r.data.data)
      queryClient.invalidateQueries({ queryKey: ['sla-settings'] })
    },
  })

  if (!form) return null

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200">
      <div className="max-w-screen-md mx-auto px-6 py-8">
        <h1 className="text-2xl font-bold text-slate-100">SLA Settings</h1>
        <p className="text-slate-500 text-sm mt-1 mb-6">
          Remediation deadline per finding severity, used across Findings for SLA tracking.
        </p>

        <form
          onSubmit={(e) => {
            e.preventDefault()
            mutation.mutate(form)
          }}
          className="space-y-4"
        >
          {FIELDS.map(({ key, label }) => (
            <div key={key} className="flex items-center gap-4">
              <label htmlFor={key} className="w-24 text-sm text-slate-400">
                {label}
              </label>
              <input
                id={key}
                type="number"
                min={1}
                value={form[key]}
                onChange={(e) => setForm({ ...form, [key]: Number(e.target.value) })}
                className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-sm text-slate-200 w-24"
              />
              <span className="text-slate-500 text-sm">days</span>
            </div>
          ))}

          <button
            type="submit"
            disabled={mutation.isPending}
            className="px-4 py-2 bg-orange-500 hover:bg-orange-600 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
          >
            {mutation.isPending ? 'Saving...' : 'Save'}
          </button>
          {mutation.isSuccess && <span className="ml-3 text-green-400 text-sm">Saved.</span>}
        </form>
      </div>
    </div>
  )
}
