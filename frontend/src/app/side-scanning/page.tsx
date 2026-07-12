'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { sideScanApi } from '@/lib/api'
import type { SideScanJob, SideScanJobStatus, SideScanJobType } from '@/lib/types'
import { RefreshCw, Server, Box, Container, Image, RotateCcw } from 'lucide-react'

const STATUS_VARIANT: Record<SideScanJobStatus, string> = {
  queued: 'bg-slate-800 text-slate-400 border border-slate-700',
  running: 'bg-blue-950 text-blue-400 border border-blue-800',
  completed: 'bg-green-950 text-green-400 border border-green-800',
  failed: 'bg-red-950 text-red-400 border border-red-800',
}

const TYPE_LABEL: Record<SideScanJobType, string> = {
  ec2: 'EC2',
  lambda: 'Lambda',
  k8s_container: 'K8s Container',
  ecr: 'Registry Image',
  sbom_rescan: 'SBOM Rescan',
}

function TypeIcon({ type }: { type: SideScanJobType }) {
  const cls = 'w-4 h-4 shrink-0'
  if (type === 'ec2') return <Server className={cls} />
  if (type === 'lambda') return <Box className={cls} />
  if (type === 'k8s_container') return <Container className={cls} />
  if (type === 'ecr') return <Image className={cls} aria-label="Registry image" />
  return <RotateCcw className={cls} />
}

function StatusBadge({ status }: { status: SideScanJobStatus }) {
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium ${STATUS_VARIANT[status]}`}
    >
      {status === 'running' && (
        <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse" />
      )}
      {status}
    </span>
  )
}

function formatDuration(job: SideScanJob): string {
  if (!job.started_at) return '—'
  const end = job.completed_at ? new Date(job.completed_at) : new Date()
  const start = new Date(job.started_at)
  const secs = Math.round((end.getTime() - start.getTime()) / 1000)
  if (secs < 60) return `${secs}s`
  return `${Math.round(secs / 60)}m ${secs % 60}s`
}

function resourceLabel(job: SideScanJob): string {
  if (job.image_uri) return job.image_uri
  if (job.pod_name) return `${job.pod_namespace ?? 'default'}/${job.pod_name}`
  return job.resource_id ?? job._key
}

export default function SideScanning() {
  const [statusFilter, setStatusFilter] = useState<string>('')
  const [typeFilter, setTypeFilter] = useState<string>('')
  const queryClient = useQueryClient()

  const { data, isLoading } = useQuery({
    queryKey: ['side-scan-jobs', statusFilter, typeFilter],
    queryFn: () =>
      sideScanApi.listJobs({
        status: statusFilter || undefined,
        job_type: typeFilter || undefined,
        limit: 100,
        offset: 0,
      }),
    refetchInterval: 30_000,
  })

  const retryMutation = useMutation({
    mutationFn: (jobId: string) => sideScanApi.retryJob(jobId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['side-scan-jobs'] })
    },
  })

  const jobs: SideScanJob[] = data?.data.items ?? []
  const total: number = data?.data.total ?? 0

  // KPI counts derived from current page
  const kpi = jobs.reduce(
    (acc, j) => {
      acc[j.type] = (acc[j.type] ?? 0) + 1
      if (j.status === 'failed') acc.failed++
      if (j.findings_count) acc.findings += j.findings_count
      return acc
    },
    { ec2: 0, lambda: 0, k8s_container: 0, ecr: 0, sbom_rescan: 0, failed: 0, findings: 0 } as Record<string, number>,
  )

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200">
      <div className="max-w-screen-xl mx-auto px-6 py-8">
        {/* Header */}
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-slate-100">Side Scanning</h1>
          <p className="text-slate-500 text-sm mt-1">Agentless deep scanning of EC2, Lambda, containers and registry images</p>
        </div>

        {/* KPI cards */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-8">
          {(
            [
              { label: 'EC2 Jobs', value: kpi.ec2, sub: 'instances scanned' },
              { label: 'Lambda Jobs', value: kpi.lambda, sub: 'functions scanned' },
              { label: 'K8s Container Jobs', value: kpi.k8s_container, sub: 'containers scanned' },
              { label: 'Registry Jobs', value: kpi.ecr, sub: 'images scanned' },
            ] as const
          ).map(({ label, value, sub }) => (
            <div key={label} className="bg-slate-900 border border-slate-800 rounded-lg p-4">
              <p className="text-slate-500 text-xs">{label}</p>
              <p className="text-2xl font-bold text-slate-100 mt-1">{value}</p>
              <p className="text-slate-600 text-xs mt-0.5">{sub}</p>
            </div>
          ))}
        </div>

        {/* Filters */}
        <div className="flex gap-3 mb-4 flex-wrap">
          <select
            className="bg-slate-900 border border-slate-700 text-slate-300 text-sm rounded px-3 py-1.5"
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
          >
            <option value="">All statuses</option>
            <option value="queued">Queued</option>
            <option value="running">Running</option>
            <option value="completed">Completed</option>
            <option value="failed">Failed</option>
          </select>
          <select
            className="bg-slate-900 border border-slate-700 text-slate-300 text-sm rounded px-3 py-1.5"
            value={typeFilter}
            onChange={(e) => setTypeFilter(e.target.value)}
          >
            <option value="">All types</option>
            <option value="ec2">EC2</option>
            <option value="lambda">Lambda</option>
            <option value="k8s_container">K8s Container</option>
            <option value="ecr">Registry Image</option>
            <option value="sbom_rescan">SBOM Rescan</option>
          </select>
          <span className="text-slate-500 text-sm self-center ml-auto">
            {total} job{total !== 1 ? 's' : ''} total
          </span>
        </div>

        {/* Jobs table */}
        <div className="bg-slate-900 border border-slate-800 rounded-lg overflow-hidden">
          {isLoading ? (
            <div className="py-12 text-center text-slate-500 text-sm">Loading scan jobs…</div>
          ) : jobs.length === 0 ? (
            <div className="py-12 text-center text-slate-500 text-sm">
              No scan jobs found.{' '}
              {statusFilter || typeFilter ? 'Try clearing filters.' : 'Trigger a scan from a resource.'}
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-800 text-left text-xs text-slate-500 uppercase tracking-wide">
                  <th className="px-4 py-3">Type</th>
                  <th className="px-4 py-3">Resource</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Findings</th>
                  <th className="px-4 py-3">Duration</th>
                  <th className="px-4 py-3">Started</th>
                  <th className="px-4 py-3"></th>
                </tr>
              </thead>
              <tbody>
                {jobs.map((job) => (
                  <tr key={job._key} className="border-b border-slate-800 hover:bg-slate-800/40 transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2 text-slate-400">
                        <TypeIcon type={job.type} />
                        <span className="text-slate-300">{TYPE_LABEL[job.type]}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-slate-400 font-mono text-xs max-w-xs truncate">
                      {resourceLabel(job)}
                    </td>
                    <td className="px-4 py-3">
                      <StatusBadge status={job.status} />
                    </td>
                    <td className="px-4 py-3 text-slate-300">
                      {job.findings_count ?? '—'}
                    </td>
                    <td className="px-4 py-3 text-slate-400 font-mono text-xs">
                      {formatDuration(job)}
                    </td>
                    <td className="px-4 py-3 text-slate-500 text-xs">
                      {job.started_at ? new Date(job.started_at).toLocaleString() : '—'}
                    </td>
                    <td className="px-4 py-3">
                      {job.status === 'failed' && (
                        <button
                          onClick={() => retryMutation.mutate(job._key)}
                          disabled={retryMutation.isPending}
                          className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 disabled:opacity-50"
                        >
                          <RefreshCw className="w-3 h-3" />
                          Re-scan
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  )
}
