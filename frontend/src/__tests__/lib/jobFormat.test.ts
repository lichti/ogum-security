import { formatDuration, formatTaskName } from '@/lib/jobFormat'

describe('formatTaskName', () => {
  it('formats a CSPM scan task name with provider', () => {
    expect(formatTaskName('cspm_scan/aws')).toBe('CSPM Scan (AWS)')
    expect(formatTaskName('cspm_scan/azure')).toBe('CSPM Scan (Azure)')
    expect(formatTaskName('cspm_scan/gcp')).toBe('CSPM Scan (GCP)')
  })

  it('formats a discovery task name with provider', () => {
    expect(formatTaskName('discovery/k8s')).toBe('Discovery (Kubernetes)')
    expect(formatTaskName('discovery/kubernetes')).toBe('Discovery (Kubernetes)')
  })

  it('formats a side-scan task name with resource type', () => {
    expect(formatTaskName('side_scan/ec2')).toBe('Side-Scan (EC2)')
    expect(formatTaskName('side_scan/lambda')).toBe('Side-Scan (Lambda)')
  })

  it('does not append a redundant suffix for iac_scan', () => {
    expect(formatTaskName('iac_scan/iac')).toBe('IaC Scan')
  })

  it('uppercases an unmapped suffix rather than dropping it', () => {
    expect(formatTaskName('cspm_scan/oci')).toBe('CSPM Scan (OCI)')
  })

  it('falls back to a de-slugged base name for an unmapped base', () => {
    expect(formatTaskName('some_new_task/aws')).toBe('some new task (AWS)')
  })

  it('handles a task name with no suffix', () => {
    expect(formatTaskName('cspm_scan')).toBe('CSPM Scan')
  })
})

describe('formatDuration', () => {
  it('returns an em dash when the job has not started', () => {
    expect(formatDuration(null, null)).toBe('—')
  })

  it('formats sub-minute durations in seconds', () => {
    expect(formatDuration('2026-01-01T00:00:00Z', '2026-01-01T00:00:45Z')).toBe('45s')
  })

  it('formats sub-hour durations in minutes and seconds', () => {
    expect(formatDuration('2026-01-01T00:00:00Z', '2026-01-01T00:02:05Z')).toBe('2m 5s')
  })

  it('formats hour-plus durations in hours and minutes', () => {
    expect(formatDuration('2026-01-01T00:00:00Z', '2026-01-01T01:30:00Z')).toBe('1h 30m')
  })

  it('computes elapsed time against now when the job is still running', () => {
    const startedAt = new Date(Date.now() - 5000).toISOString()
    expect(formatDuration(startedAt, null)).toMatch(/^\ds$/)
  })
})
