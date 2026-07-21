'use client'
import { useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { X } from 'lucide-react'
import { scansApi } from '@/lib/api'
import type { ScanJob } from '@/lib/types'

interface ScanLogsPanelProps {
  job: ScanJob
  onClose: () => void
}

export function ScanLogsPanel({ job, onClose }: ScanLogsPanelProps) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['scan-logs', job.job_id],
    queryFn: () => scansApi.logs(job.job_id).then((r) => r.data.data),
  })

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])

  return (
    <>
      <div className="fixed inset-0 z-40" onClick={onClose} aria-hidden="true" />
      <div
        className="fixed top-0 right-0 h-full w-[560px] bg-slate-900 border-l border-slate-700 shadow-2xl z-50 overflow-y-auto"
        data-testid="scan-logs-panel"
      >
        <div
          id="scan-logs-panel-header"
          className="flex items-center justify-between p-4 border-b border-slate-700 sticky top-0 bg-slate-900"
        >
          <div className="min-w-0">
            <h2 className="text-slate-200 font-semibold text-sm">Scan logs</h2>
            <p className="text-slate-500 text-xs font-mono truncate">{job.job_id}</p>
          </div>
          <button
            onClick={onClose}
            aria-label="Close panel"
            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors flex-shrink-0"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        <div id="scan-logs-panel-content" className="p-4">
          {isLoading && <p className="text-slate-600 text-sm">Loading logs…</p>}
          {isError && <p className="text-red-400 text-sm">Failed to load logs.</p>}
          {data && data.logs.length === 0 && (
            <p className="text-slate-600 text-sm">No logs available for this scan.</p>
          )}
          {data && data.logs.length > 0 && (
            <pre
              data-testid="scan-log-viewer"
              className="bg-slate-950 border border-slate-800 rounded p-3 text-xs text-slate-400 font-mono whitespace-pre-wrap break-words max-h-[calc(100vh-140px)] overflow-y-auto"
            >
              {data.logs.join('\n')}
            </pre>
          )}
        </div>
      </div>
    </>
  )
}
