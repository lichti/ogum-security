import '@testing-library/jest-dom'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'

import { JobDetailPanel } from '@/components/admin/JobDetailPanel'
import type { Job, JobDetail } from '@/lib/jobFormat'

function wrapper({ children }: { children: ReactNode }) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
}

const mockJob: Job = {
  job_id: 'job-abc-123',
  task_name: 'cspm_scan/aws',
  tenant_id: 'dev-tenant',
  status: 'completed',
  provider: 'aws',
  created_at: '2026-01-01T00:00:00Z',
  started_at: '2026-01-01T00:00:00Z',
  completed_at: '2026-01-01T00:02:05Z',
  worker: 'celery@worker-1',
}

const mockDetail: JobDetail = {
  ...mockJob,
  retries: 0,
  provider_id: 'aws-123456789012',
  logs: ['2026-01-01 00:00:00 INFO app.workers.tasks.cspm_scan: scan started'],
  error_message: null,
  findings_found: 42,
  findings_fail: 10,
  checks_total: 42,
  checks_completed: 42,
}

function mockFetchOnce(data: JobDetail) {
  global.fetch = jest.fn().mockResolvedValue({
    ok: true,
    json: async () => ({ data }),
  }) as jest.Mock
}

describe('JobDetailPanel', () => {
  afterEach(() => {
    jest.restoreAllMocks()
  })

  it('renders nothing when job is null', () => {
    const { container } = render(<JobDetailPanel job={null} onClose={jest.fn()} />, { wrapper })
    expect(container).toBeEmptyDOMElement()
  })

  it('renders the panel with the formatted job name and job id', () => {
    mockFetchOnce(mockDetail)
    render(<JobDetailPanel job={mockJob} onClose={jest.fn()} />, { wrapper })
    expect(screen.getByTestId('job-detail-panel')).toBeInTheDocument()
    expect(screen.getByText('CSPM Scan (AWS)')).toBeInTheDocument()
    expect(screen.getByText('job-abc-123')).toBeInTheDocument()
  })

  it('renders duration computed from started/completed timestamps', () => {
    mockFetchOnce(mockDetail)
    render(<JobDetailPanel job={mockJob} onClose={jest.fn()} />, { wrapper })
    expect(screen.getByText('2m 5s')).toBeInTheDocument()
  })

  it('fetches and renders job logs', async () => {
    mockFetchOnce(mockDetail)
    render(<JobDetailPanel job={mockJob} onClose={jest.fn()} />, { wrapper })

    await waitFor(() => expect(screen.getByTestId('job-log-viewer')).toBeInTheDocument())
    expect(screen.getByText(/scan started/)).toBeInTheDocument()
    expect(global.fetch).toHaveBeenCalledWith(
      expect.stringContaining(`/api/v1/admin/jobs/${mockJob.job_id}?tenant_id=${mockJob.tenant_id}`)
    )
  })

  it('shows a message when there are no logs', async () => {
    mockFetchOnce({ ...mockDetail, logs: [] })
    render(<JobDetailPanel job={mockJob} onClose={jest.fn()} />, { wrapper })
    await waitFor(() => expect(screen.getByText('No logs available for this job.')).toBeInTheDocument())
  })

  it('renders findings and checks counts once detail loads', async () => {
    mockFetchOnce(mockDetail)
    render(<JobDetailPanel job={mockJob} onClose={jest.fn()} />, { wrapper })
    await waitFor(() => expect(screen.getByText('42 found, 10 fail')).toBeInTheDocument())
    expect(screen.getByText('42 / 42')).toBeInTheDocument()
  })

  it('renders the error message for a failed job', async () => {
    mockFetchOnce({ ...mockDetail, status: 'failed', error_message: 'AssumeRole denied' })
    render(<JobDetailPanel job={{ ...mockJob, status: 'failed' }} onClose={jest.fn()} />, { wrapper })
    await waitFor(() => expect(screen.getByText('AssumeRole denied')).toBeInTheDocument())
  })

  it('shows an error message when the detail fetch fails', async () => {
    global.fetch = jest.fn().mockResolvedValue({ ok: false, status: 500 }) as jest.Mock
    render(<JobDetailPanel job={mockJob} onClose={jest.fn()} />, { wrapper })
    await waitFor(() => expect(screen.getByText('Failed to load logs.')).toBeInTheDocument())
  })

  it('calls onClose when the close button is clicked', () => {
    mockFetchOnce(mockDetail)
    const onClose = jest.fn()
    render(<JobDetailPanel job={mockJob} onClose={onClose} />, { wrapper })
    fireEvent.click(screen.getByLabelText('Close panel'))
    expect(onClose).toHaveBeenCalledTimes(1)
  })
})
