'use client'
import { useState } from 'react'
import { X } from 'lucide-react'

interface MuteModalProps {
  findingTitle: string
  onConfirm: (reason: string) => void
  onCancel: () => void
  loading?: boolean
}

export function MuteModal({ findingTitle, onConfirm, onCancel, loading }: MuteModalProps) {
  const [reason, setReason] = useState('')

  return (
    <div className="fixed inset-0 z-60 flex items-center justify-center bg-black/60" data-testid="mute-modal">
      <div className="bg-slate-900 border border-slate-700 rounded-lg w-[480px] shadow-2xl">
        <div className="flex items-center justify-between p-4 border-b border-slate-700">
          <h3 className="text-slate-200 font-semibold">Mute Finding</h3>
          <button onClick={onCancel} className="text-slate-500 hover:text-slate-300">
            <X className="w-4 h-4" />
          </button>
        </div>
        <div className="p-4 space-y-4">
          <p className="text-sm text-slate-400">
            Muting: <span className="text-slate-200 font-medium">{findingTitle}</span>
          </p>
          <div>
            <label className="block text-xs text-slate-500 mb-1.5">
              Reason <span className="text-red-400">*</span>
            </label>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="e.g. Accepted by security team — compensating control in place"
              rows={3}
              className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-sm text-slate-300 placeholder-slate-600 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500/30 resize-none"
              aria-label="Mute reason"
            />
          </div>
        </div>
        <div className="flex justify-end gap-2 p-4 border-t border-slate-700">
          <button
            onClick={onCancel}
            className="px-4 py-2 text-sm text-slate-400 hover:text-slate-200 rounded hover:bg-slate-800"
          >
            Cancel
          </button>
          <button
            onClick={() => reason.trim() && onConfirm(reason.trim())}
            disabled={!reason.trim() || loading}
            className="px-4 py-2 text-sm bg-orange-600 hover:bg-orange-500 text-white rounded disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {loading ? 'Muting…' : 'Confirm Mute'}
          </button>
        </div>
      </div>
    </div>
  )
}
