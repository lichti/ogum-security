'use client'
import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { scansApi } from '@/lib/api'
import type { ProviderConfig } from '@/lib/types'

interface TriggerScanModalProps {
  providers: ProviderConfig[]
  onClose: () => void
  onTriggered: () => void
}

export function TriggerScanModal({ providers, onClose, onTriggered }: TriggerScanModalProps) {
  const [providerId, setProviderId] = useState(providers[0]?.key ?? '')

  const mutation = useMutation({
    mutationFn: () => scansApi.trigger({ provider_id: providerId }),
    onSuccess: () => {
      onTriggered()
      onClose()
    },
  })

  return (
    <>
      <div className="fixed inset-0 z-40" onClick={onClose} aria-hidden="true" />
      <div className="fixed inset-0 z-50 flex items-center justify-center pointer-events-none">
        <div
          data-testid="trigger-scan-modal"
          className="bg-slate-900 border border-slate-700 rounded-xl p-5 w-full max-w-sm shadow-2xl pointer-events-auto"
        >
          <h2 className="text-slate-200 font-semibold text-sm mb-4">Trigger a new scan</h2>

          {providers.length === 0 ? (
            <p className="text-slate-500 text-sm mb-4">
              No cloud provider connected yet — connect one on the Cloud Providers page first.
            </p>
          ) : (
            <>
              <label htmlFor="trigger-scan-provider" className="text-xs text-slate-500 mb-1 block">
                Cloud provider
              </label>
              <select
                id="trigger-scan-provider"
                value={providerId}
                onChange={(e) => setProviderId(e.target.value)}
                className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm text-slate-200 mb-4 focus:outline-none focus:border-orange-500"
              >
                {providers.map((p) => (
                  <option key={p.key} value={p.key}>
                    {p.display_name} ({p.provider.toUpperCase()})
                  </option>
                ))}
              </select>
            </>
          )}

          {mutation.isError && (
            <p className="text-red-400 text-xs mb-3">Failed to trigger scan — check provider credentials.</p>
          )}

          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={onClose}
              className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200 transition-colors"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={() => mutation.mutate()}
              disabled={!providerId || mutation.isPending}
              className="px-3 py-1.5 bg-orange-500 hover:bg-orange-600 disabled:opacity-50 text-white text-xs font-medium rounded-lg transition-colors"
            >
              {mutation.isPending ? 'Starting…' : 'Start Scan'}
            </button>
          </div>
        </div>
      </div>
    </>
  )
}
