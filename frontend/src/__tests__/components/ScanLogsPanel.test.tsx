import '@testing-library/jest-dom'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { ScanLogsPanel } from '@/components/scans/ScanLogsPanel'
import { scansApi } from '@/lib/api'
import type { ScanJob } from '@/lib/types'

jest.mock('@/lib/api', () => ({
  scansApi: { logs: jest.fn() },
}))

const mockLogs = scansApi.logs as jest.Mock

function renderWithClient(ui: React.ReactElement) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
  return render(ui, { wrapper: Wrapper })
}

function makeJob(overrides: Partial<ScanJob> = {}): ScanJob {
  return {
    job_id: 'job-abc123',
    tenant_id: 'dev-tenant',
    provider_id: 'aws-111111111111',
    provider: 'aws',
    task_name: 'cspm_scan/aws',
    frameworks: [],
    regions: [],
    status: 'completed',
    checks_total: 0,
    checks_completed: 0,
    findings_found: 0,
    findings_fail: 0,
    findings_new: 0,
    findings_updated: 0,
    findings_removed: 0,
    assets_total: 0,
    assets_removed: 0,
    duration_seconds: 10,
    started_at: null,
    completed_at: null,
    created_at: '2026-07-16T10:00:00Z',
    error_message: null,
    ...overrides,
  }
}

beforeEach(() => jest.clearAllMocks())

describe('ScanLogsPanel', () => {
  it('fetches logs for the given job and renders each line', async () => {
    mockLogs.mockResolvedValue({ data: { data: { job_id: 'job-abc123', logs: ['line one', 'line two'] } } })
    renderWithClient(<ScanLogsPanel job={makeJob()} onClose={jest.fn()} />)

    expect(await screen.findByTestId('scan-log-viewer')).toHaveTextContent('line one')
    expect(screen.getByTestId('scan-log-viewer')).toHaveTextContent('line two')
    expect(screen.getByText('job-abc123')).toBeInTheDocument()
  })

  it('shows an empty state when there are no logs', async () => {
    mockLogs.mockResolvedValue({ data: { data: { job_id: 'job-abc123', logs: [] } } })
    renderWithClient(<ScanLogsPanel job={makeJob()} onClose={jest.fn()} />)

    expect(await screen.findByText('No logs available for this scan.')).toBeInTheDocument()
  })

  it('shows an error message when the fetch fails', async () => {
    mockLogs.mockRejectedValue(new Error('network error'))
    renderWithClient(<ScanLogsPanel job={makeJob()} onClose={jest.fn()} />)

    expect(await screen.findByText('Failed to load logs.')).toBeInTheDocument()
  })

  it('closes on Escape, backdrop click, and the close button', async () => {
    mockLogs.mockResolvedValue({ data: { data: { job_id: 'job-abc123', logs: [] } } })
    const onClose = jest.fn()
    renderWithClient(<ScanLogsPanel job={makeJob()} onClose={onClose} />)
    await screen.findByText('No logs available for this scan.')

    fireEvent.keyDown(window, { key: 'Escape' })
    expect(onClose).toHaveBeenCalledTimes(1)

    fireEvent.click(screen.getByLabelText('Close panel'))
    expect(onClose).toHaveBeenCalledTimes(2)

    fireEvent.click(document.querySelector('[aria-hidden="true"]') as HTMLElement)
    expect(onClose).toHaveBeenCalledTimes(3)
  })

  it('refetches when the job changes', async () => {
    mockLogs.mockResolvedValue({ data: { data: { job_id: 'job-abc123', logs: [] } } })
    const { rerender } = renderWithClient(<ScanLogsPanel job={makeJob()} onClose={jest.fn()} />)
    await waitFor(() => expect(mockLogs).toHaveBeenCalledWith('job-abc123'))

    rerender(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <ScanLogsPanel job={makeJob({ job_id: 'job-xyz789' })} onClose={jest.fn()} />
      </QueryClientProvider>,
    )
    await waitFor(() => expect(mockLogs).toHaveBeenCalledWith('job-xyz789'))
  })
})
