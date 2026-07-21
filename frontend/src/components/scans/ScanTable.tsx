'use client'
import { FileText } from 'lucide-react'
import { StatusBadge } from '@/components/admin/StatusBadge'
import { formatDurationSeconds } from '@/lib/jobFormat'
import type { ScanJob } from '@/lib/types'

interface ScanTableProps {
  jobs: ScanJob[]
  onViewLogs: (job: ScanJob) => void
}

function FindingsSummary({ job }: { job: ScanJob }) {
  return (
    <div className="text-xs">
      <div className="text-slate-300">
        <span className="font-mono font-semibold">{job.findings_found}</span> total ·{' '}
        <span className="font-mono font-semibold text-red-400">{job.findings_fail}</span> fail
      </div>
      <div className="text-slate-500 mt-0.5">
        <span className="text-green-400">{job.findings_new} new</span>
        {' · '}
        <span className="text-yellow-400">{job.findings_updated} updated</span>
        {' · '}
        <span className="text-slate-400">{job.findings_removed} removed</span>
      </div>
    </div>
  )
}

function AssetsSummary({ job }: { job: ScanJob }) {
  return (
    <div className="text-xs">
      <div className="text-slate-300 font-mono font-semibold">{job.assets_total}</div>
      {job.assets_removed > 0 && <div className="text-slate-500 mt-0.5">{job.assets_removed} removed</div>}
    </div>
  )
}

const FINISHED_STATUSES = new Set(['completed', 'failed'])

export function ScanTable({ jobs, onViewLogs }: ScanTableProps) {
  if (jobs.length === 0) {
    return <p className="text-slate-600 text-sm px-4 py-8 text-center">No scans yet — trigger one above.</p>
  }

  return (
    <table id="scans-table" className="w-full text-left">
      <thead>
        <tr className="border-b border-slate-800 text-xs text-slate-500 uppercase tracking-wider">
          <th className="py-2 pl-4 pr-3 font-medium">Job</th>
          <th className="py-2 px-3 font-medium">Provider</th>
          <th className="py-2 px-3 font-medium">Status</th>
          <th className="py-2 px-3 font-medium">Started</th>
          <th className="py-2 px-3 font-medium">Duration</th>
          <th className="py-2 px-3 font-medium">Findings</th>
          <th className="py-2 px-3 font-medium">Assets</th>
          <th className="py-2 pl-3 pr-4 font-medium" />
        </tr>
      </thead>
      <tbody className="divide-y divide-slate-800/50">
        {jobs.map((job) => (
          <tr key={job.job_id} data-testid={`scan-row-${job.job_id}`} className="text-sm hover:bg-slate-900/40">
            <td className="py-3 pl-4 pr-3">
              <span className="text-slate-400 font-mono text-xs" title={job.job_id}>
                {job.job_id.slice(0, 8)}
              </span>
            </td>
            <td className="py-3 px-3">
              <div className="text-slate-300">{job.provider.toUpperCase()}</div>
              {job.frameworks.length > 0 && (
                <div className="text-slate-600 text-xs truncate max-w-[160px]">{job.frameworks.join(', ')}</div>
              )}
            </td>
            <td className="py-3 px-3">
              <StatusBadge status={job.status} />
              {job.status === 'failed' && job.error_message && (
                <div className="text-red-400 text-xs mt-1 max-w-[200px] truncate" title={job.error_message}>
                  {job.error_message}
                </div>
              )}
            </td>
            <td className="py-3 px-3 text-slate-400 text-xs">
              {job.started_at ? new Date(job.started_at).toLocaleString() : '—'}
            </td>
            <td className="py-3 px-3 text-slate-400 text-xs font-mono">{formatDurationSeconds(job.duration_seconds)}</td>
            <td className="py-3 px-3">
              <FindingsSummary job={job} />
            </td>
            <td className="py-3 px-3">
              <AssetsSummary job={job} />
            </td>
            <td className="py-3 pl-3 pr-4">
              {FINISHED_STATUSES.has(job.status) && (
                <button
                  type="button"
                  onClick={() => onViewLogs(job)}
                  className="flex items-center gap-1.5 text-xs text-orange-400 hover:text-orange-300 transition-colors whitespace-nowrap"
                >
                  <FileText className="w-3.5 h-3.5" />
                  View Logs
                </button>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}
