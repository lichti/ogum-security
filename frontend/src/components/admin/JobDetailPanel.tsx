'use client'
import { useQuery } from '@tanstack/react-query'
import { X } from 'lucide-react'
import { StatusBadge } from '@/components/admin/StatusBadge'
import { formatDuration, formatTaskName, type Job, type JobDetail } from '@/lib/jobFormat'

const API = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000'

interface JobDetailPanelProps {
  job: Job | null
  onClose: () => void
}

async function fetchJobDetail(jobId: string, tenantId: string): Promise<JobDetail> {
  const res = await fetch(
    `${API}/api/v1/admin/jobs/${jobId}?tenant_id=${encodeURIComponent(tenantId)}`
  )
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const body = await res.json()
  return body.data as JobDetail
}

export function JobDetailPanel({ job, onClose }: JobDetailPanelProps) {
  const { data: detail, isLoading, isError } = useQuery({
    queryKey: ['admin-job-detail', job?.job_id, job?.tenant_id],
    queryFn: () => fetchJobDetail(job!.job_id, job!.tenant_id),
    enabled: job !== null,
  })

  if (!job) return null

  const metadataRows: [string, React.ReactNode][] = [
    ['Tenant', job.tenant_id],
    ['Provider', detail?.provider ?? job.provider ?? '—'],
    ['Status', <StatusBadge key="status" status={job.status} />],
    ['Created', job.created_at ? new Date(job.created_at).toLocaleString() : '—'],
    ['Started', job.started_at ? new Date(job.started_at).toLocaleString() : '—'],
    ['Completed', detail?.completed_at ? new Date(detail.completed_at).toLocaleString() : '—'],
    ['Duration', formatDuration(job.started_at, detail?.completed_at ?? job.completed_at)],
    ['Worker', job.worker ?? '—'],
  ]

  if (detail && (detail.checks_total !== null || detail.findings_found !== null)) {
    metadataRows.push(
      ['Checks', `${detail.checks_completed ?? 0} / ${detail.checks_total ?? 0}`],
      ['Findings', `${detail.findings_found ?? 0} found, ${detail.findings_fail ?? 0} fail`]
    )
  }

  return (
    <div
      className="fixed top-0 right-0 h-full w-[480px] bg-slate-900 border-l border-slate-700 shadow-2xl z-50 overflow-y-auto"
      data-testid="job-detail-panel"
    >
      <div className="flex items-center justify-between p-4 border-b border-slate-700 sticky top-0 bg-slate-900">
        <div>
          <h2 className="text-slate-200 font-semibold">{formatTaskName(job.task_name)}</h2>
          <p className="text-slate-500 text-xs font-mono">{job.job_id}</p>
        </div>
        <button
          onClick={onClose}
          className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
          aria-label="Close panel"
        >
          <X className="w-4 h-4" />
        </button>
      </div>

      <div className="p-4 space-y-6">
        <section>
          <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">Details</h3>
          <dl className="space-y-2">
            {metadataRows.map(([label, value]) => (
              <div key={String(label)} className="flex gap-2">
                <dt className="text-slate-500 text-sm w-24 flex-shrink-0">{label}</dt>
                <dd className="text-slate-300 text-sm">{value}</dd>
              </div>
            ))}
          </dl>
        </section>

        {detail?.error_message && (
          <section>
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">Error</h3>
            <div className="p-2 bg-red-950 border border-red-800 rounded text-red-300 text-xs font-mono whitespace-pre-wrap break-words">
              {detail.error_message}
            </div>
          </section>
        )}

        <section>
          <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">Logs</h3>
          {isLoading && <p className="text-slate-600 text-sm">Loading logs…</p>}
          {isError && <p className="text-red-400 text-sm">Failed to load logs.</p>}
          {detail && detail.logs.length === 0 && (
            <p className="text-slate-600 text-sm">No logs available for this job.</p>
          )}
          {detail && detail.logs.length > 0 && (
            <pre
              data-testid="job-log-viewer"
              className="bg-slate-950 border border-slate-800 rounded p-3 text-xs text-slate-400 font-mono whitespace-pre-wrap break-words max-h-96 overflow-y-auto"
            >
              {detail.logs.join('\n')}
            </pre>
          )}
        </section>
      </div>
    </div>
  )
}
