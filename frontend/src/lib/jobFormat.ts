export interface Job {
  job_id: string
  task_name: string
  tenant_id: string
  status: string
  provider: string | null
  created_at: string | null
  started_at: string | null
  completed_at: string | null
  worker: string | null
}

export interface JobDetail extends Job {
  retries: number
  provider_id: string | null
  logs: string[]
  error_message: string | null
  findings_found: number | null
  findings_fail: number | null
  checks_total: number | null
  checks_completed: number | null
}

const TASK_BASE_NAMES: Record<string, string> = {
  cspm_scan: 'CSPM Scan',
  discovery: 'Discovery',
  side_scan: 'Side-Scan',
  iac_scan: 'IaC Scan',
}

const TASK_SUFFIX_LABELS: Record<string, string> = {
  aws: 'AWS',
  azure: 'Azure',
  gcp: 'GCP',
  k8s: 'Kubernetes',
  kubernetes: 'Kubernetes',
  ec2: 'EC2',
  lambda: 'Lambda',
  iac: 'IaC',
  unknown: 'Unknown',
}

/** task_name is a stable machine identifier like "cspm_scan/aws" or
 * "side_scan/ec2" — this maps it to a human-readable label for display. */
export function formatTaskName(taskName: string): string {
  const [base, suffix] = taskName.split('/', 2)
  const baseLabel = TASK_BASE_NAMES[base] ?? base.replace(/_/g, ' ')
  if (!suffix || base === 'iac_scan') return baseLabel
  const suffixLabel = TASK_SUFFIX_LABELS[suffix] ?? suffix.toUpperCase()
  return `${baseLabel} (${suffixLabel})`
}

function formatSeconds(seconds: number): string {
  const whole = Math.max(0, Math.round(seconds))
  if (whole < 60) return `${whole}s`
  const minutes = Math.floor(whole / 60)
  const remSeconds = whole % 60
  if (minutes < 60) return `${minutes}m ${remSeconds}s`
  const hours = Math.floor(minutes / 60)
  const remMinutes = minutes % 60
  return `${hours}h ${remMinutes}m`
}

/** Elapsed time between start and completion — completion defaults to "now"
 * for a still-running job, so duration keeps ticking up until the page is
 * refreshed (this page has no live polling, matching its existing UX). */
export function formatDuration(startedAt: string | null, completedAt: string | null): string {
  if (!startedAt) return '—'
  const start = new Date(startedAt).getTime()
  const end = completedAt ? new Date(completedAt).getTime() : Date.now()
  return formatSeconds((end - start) / 1000)
}

/** Same mm:ss/h:mm formatting as `formatDuration`, but for a job that already
 * carries its own server-computed `duration_seconds` (the Scans page) instead
 * of two timestamps to diff client-side. */
export function formatDurationSeconds(seconds: number | null): string {
  if (seconds === null) return '—'
  return formatSeconds(seconds)
}
