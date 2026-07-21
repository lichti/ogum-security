import '@testing-library/jest-dom'
import { render, screen, fireEvent } from '@testing-library/react'
import { ScanTable } from '@/components/scans/ScanTable'
import type { ScanJob } from '@/lib/types'

function makeJob(overrides: Partial<ScanJob> = {}): ScanJob {
  return {
    job_id: 'job-abc12345',
    tenant_id: 'dev-tenant',
    provider_id: 'aws-111111111111',
    provider: 'aws',
    task_name: 'cspm_scan/aws',
    frameworks: ['CIS-AWS-2.0'],
    regions: ['us-east-1'],
    status: 'completed',
    checks_total: 10,
    checks_completed: 10,
    findings_found: 10,
    findings_fail: 3,
    findings_new: 2,
    findings_updated: 7,
    findings_removed: 1,
    assets_total: 15,
    assets_removed: 0,
    duration_seconds: 95,
    started_at: '2026-07-16T10:00:00Z',
    completed_at: '2026-07-16T10:01:35Z',
    created_at: '2026-07-16T10:00:00Z',
    error_message: null,
    ...overrides,
  }
}

const noop = jest.fn()

describe('ScanTable', () => {
  beforeEach(() => jest.clearAllMocks())

  it('shows an empty state when there are no scans', () => {
    render(<ScanTable jobs={[]} onViewLogs={noop} />)
    expect(screen.getByText(/No scans yet/)).toBeInTheDocument()
  })

  it('renders a row with provider, status, findings, and assets summaries', () => {
    render(<ScanTable jobs={[makeJob()]} onViewLogs={noop} />)

    expect(screen.getByText('AWS')).toBeInTheDocument()
    expect(screen.getByText('completed')).toBeInTheDocument()
    expect(screen.getByText('CIS-AWS-2.0')).toBeInTheDocument()
    expect(screen.getByText(/10/)).toBeInTheDocument()
    expect(screen.getByText('2 new')).toBeInTheDocument()
    expect(screen.getByText('7 updated')).toBeInTheDocument()
    expect(screen.getByText('1 removed')).toBeInTheDocument()
    expect(screen.getByText('15')).toBeInTheDocument() // assets_total
  })

  it('shows the job id truncated, full id in the title attribute', () => {
    render(<ScanTable jobs={[makeJob({ job_id: 'a1b2c3d4-e5f6-7890' })]} onViewLogs={noop} />)
    const idEl = screen.getByText('a1b2c3d4')
    expect(idEl).toHaveAttribute('title', 'a1b2c3d4-e5f6-7890')
  })

  it('shows assets_removed only when greater than zero (unlike the findings breakdown, always shown)', () => {
    const { rerender } = render(<ScanTable jobs={[makeJob({ assets_removed: 0 })]} onViewLogs={noop} />)
    expect(screen.queryByText('4 removed')).not.toBeInTheDocument()

    rerender(<ScanTable jobs={[makeJob({ assets_removed: 4 })]} onViewLogs={noop} />)
    expect(screen.getByText('4 removed')).toBeInTheDocument()
  })

  it('shows a "View Logs" button for completed and failed scans, not for running/queued', () => {
    const { rerender } = render(<ScanTable jobs={[makeJob({ status: 'completed' })]} onViewLogs={noop} />)
    expect(screen.getByRole('button', { name: /View Logs/i })).toBeInTheDocument()

    rerender(<ScanTable jobs={[makeJob({ status: 'failed' })]} onViewLogs={noop} />)
    expect(screen.getByRole('button', { name: /View Logs/i })).toBeInTheDocument()

    rerender(<ScanTable jobs={[makeJob({ status: 'running' })]} onViewLogs={noop} />)
    expect(screen.queryByRole('button', { name: /View Logs/i })).not.toBeInTheDocument()

    rerender(<ScanTable jobs={[makeJob({ status: 'queued' })]} onViewLogs={noop} />)
    expect(screen.queryByRole('button', { name: /View Logs/i })).not.toBeInTheDocument()
  })

  it('calls onViewLogs with the job when "View Logs" is clicked', () => {
    const onViewLogs = jest.fn()
    const job = makeJob()
    render(<ScanTable jobs={[job]} onViewLogs={onViewLogs} />)

    fireEvent.click(screen.getByRole('button', { name: /View Logs/i }))
    expect(onViewLogs).toHaveBeenCalledWith(job)
  })

  it('shows the error message for a failed scan', () => {
    render(
      <ScanTable
        jobs={[makeJob({ status: 'failed', error_message: 'AssumeRole failed: access denied' })]}
        onViewLogs={noop}
      />,
    )
    expect(screen.getByText('AssumeRole failed: access denied')).toBeInTheDocument()
  })
})
