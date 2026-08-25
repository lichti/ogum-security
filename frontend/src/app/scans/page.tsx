'use client'
import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { Play } from 'lucide-react'
import { providersApi, scansApi } from '@/lib/api'
import type { ScanJob, ScanJobStatus } from '@/lib/types'
import { ScanTable } from '@/components/scans/ScanTable'
import { TriggerScanModal } from '@/components/scans/TriggerScanModal'
import { ScanLogsPanel } from '@/components/scans/ScanLogsPanel'

const STATUS_OPTIONS: ScanJobStatus[] = ['queued', 'running', 'completed', 'failed']

function StatusFilter({
  selected,
  onToggle,
}: {
  selected: Set<ScanJobStatus>
  onToggle: (status: ScanJobStatus) => void
}) {
  return (
    <div className="flex gap-1.5" role="group" aria-label="Filter scans by status">
      {STATUS_OPTIONS.map((s) => {
        const active = selected.has(s)
        return (
          <button
            key={s}
            type="button"
            aria-pressed={active}
            onClick={() => onToggle(s)}
            className={`px-2.5 py-1 rounded text-xs font-medium border capitalize transition-colors ${
              active
                ? 'border-orange-500 bg-orange-500/10 text-orange-300'
                : 'border-slate-800 text-slate-600 hover:text-slate-400 hover:border-slate-700'
            }`}
          >
            {s}
          </button>
        )
      })}
    </div>
  )
}

export default function ScansPage() {
  const queryClient = useQueryClient()
  const [selectedStatuses, setSelectedStatuses] = useState<Set<ScanJobStatus>>(new Set(STATUS_OPTIONS))
  const [cursors, setCursors] = useState<string[]>([])
  const [showTrigger, setShowTrigger] = useState(false)
  const [logsJob, setLogsJob] = useState<ScanJob | null>(null)

  const cursor = cursors[cursors.length - 1]
  const statusParam = selectedStatuses.size === STATUS_OPTIONS.length ? undefined : Array.from(selectedStatuses)

  const { data, isLoading } = useQuery({
    queryKey: ['scans', statusParam, cursor],
    queryFn: () => scansApi.list({ status: statusParam, cursor, limit: 20 }).then((r) => r.data.data),
    // Keeps the queue/running rows moving without a manual refresh — this page's
    // whole purpose is watching a scan you just triggered progress to completion.
    refetchInterval: 10_000,
  })

  const { data: providers } = useQuery({
    queryKey: ['providers'],
    queryFn: () => providersApi.list().then((r) => r.data.data),
  })

  const invalidate = () => {
    setCursors([])
    queryClient.invalidateQueries({ queryKey: ['scans'] })
  }

  const toggleStatus = (status: ScanJobStatus) => {
    setCursors([])
    setSelectedStatuses((prev) => {
      const next = new Set(prev)
      if (next.has(status)) next.delete(status)
      else next.add(status)
      return next
    })
  }

  const jobs = data?.items ?? []

  return (
    <div id="scans-page" className="min-h-screen bg-slate-950 text-slate-200">
      <div className="max-w-screen-xl mx-auto px-6 py-8">
        <div className="flex items-center justify-between mb-6">
          <StatusFilter selected={selectedStatuses} onToggle={toggleStatus} />
          <button
            type="button"
            onClick={() => setShowTrigger(true)}
            className="flex items-center gap-2 px-4 py-2 bg-orange-500 hover:bg-orange-600 text-white text-sm font-medium rounded-lg transition-colors flex-shrink-0"
          >
            <Play className="w-4 h-4" />
            Trigger Scan
          </button>
        </div>

        <div id="scans-table-container" className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          {isLoading && jobs.length === 0 ? (
            <div className="py-16 text-center text-slate-500 text-sm">Loading…</div>
          ) : (
            <ScanTable jobs={jobs} onViewLogs={setLogsJob} />
          )}
        </div>

        <div className="flex items-center justify-center gap-3 mt-4">
          {cursors.length > 0 && (
            <button
              type="button"
              onClick={() => setCursors((prev) => prev.slice(0, -1))}
              className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200 border border-slate-800 rounded-lg transition-colors"
            >
              ← Previous
            </button>
          )}
          {data?.next_cursor && (
            <button
              type="button"
              onClick={() => setCursors((prev) => [...prev, data.next_cursor!])}
              className="px-3 py-1.5 text-xs text-slate-400 hover:text-slate-200 border border-slate-800 rounded-lg transition-colors"
            >
              Next →
            </button>
          )}
        </div>
      </div>

      {showTrigger && (
        <TriggerScanModal
          providers={providers ?? []}
          onClose={() => setShowTrigger(false)}
          onTriggered={invalidate}
        />
      )}

      {logsJob && <ScanLogsPanel job={logsJob} onClose={() => setLogsJob(null)} />}
    </div>
  )
}
