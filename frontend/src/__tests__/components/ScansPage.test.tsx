import '@testing-library/jest-dom'
import { render, screen, fireEvent, waitFor, within } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import ScansPage from '@/app/scans/page'
import { providersApi, scansApi } from '@/lib/api'
import type { ProviderConfig, ScanJob } from '@/lib/types'

jest.mock('@/lib/api', () => ({
  scansApi: { list: jest.fn(), trigger: jest.fn(), logs: jest.fn() },
  providersApi: { list: jest.fn() },
}))

const mockList = scansApi.list as jest.Mock
const mockTrigger = scansApi.trigger as jest.Mock
const mockLogs = scansApi.logs as jest.Mock
const mockProvidersList = providersApi.list as jest.Mock

function renderWithClient() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
  return render(<ScansPage />, { wrapper: Wrapper })
}

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

function makeProvider(overrides: Partial<ProviderConfig> = {}): ProviderConfig {
  return {
    key: 'aws-111111111111',
    provider: 'aws',
    display_name: 'Production AWS',
    account_id: '111111111111',
    regions: ['us-east-1'],
    enabled: true,
    status: 'active',
    credential_type: 'role',
    created_at: '2026-07-01T00:00:00Z',
    ...overrides,
  }
}

beforeEach(() => {
  jest.clearAllMocks()
  mockProvidersList.mockResolvedValue({ data: { data: [makeProvider()] } })
  mockLogs.mockResolvedValue({ data: { data: { job_id: 'job-abc12345', logs: [] } } })
})

describe('ScansPage', () => {
  it('renders the scans returned by the API', async () => {
    mockList.mockResolvedValue({ data: { data: { items: [makeJob()], next_cursor: null } } })
    renderWithClient()

    const row = within(await screen.findByTestId('scan-row-job-abc12345'))
    expect(row.getByText('AWS')).toBeInTheDocument()
    expect(row.getByText('completed')).toBeInTheDocument()
  })

  it('shows an empty state when there are no scans', async () => {
    mockList.mockResolvedValue({ data: { data: { items: [], next_cursor: null } } })
    renderWithClient()
    expect(await screen.findByText(/No scans yet/)).toBeInTheDocument()
  })

  it('all 4 status filters start selected, and the request omits the status param', async () => {
    mockList.mockResolvedValue({ data: { data: { items: [], next_cursor: null } } })
    renderWithClient()

    await waitFor(() => expect(mockList).toHaveBeenCalledWith(expect.objectContaining({ status: undefined })))
    for (const label of ['queued', 'running', 'completed', 'failed']) {
      expect(screen.getByRole('button', { name: label })).toHaveAttribute('aria-pressed', 'true')
    }
  })

  it('deselecting a status filters the request to the remaining statuses', async () => {
    mockList.mockResolvedValue({ data: { data: { items: [], next_cursor: null } } })
    renderWithClient()
    await waitFor(() => expect(mockList).toHaveBeenCalled())
    mockList.mockClear()

    fireEvent.click(screen.getByRole('button', { name: 'failed' }))

    await waitFor(() =>
      expect(mockList).toHaveBeenCalledWith(expect.objectContaining({ status: ['queued', 'running', 'completed'] })),
    )
    expect(screen.getByRole('button', { name: 'failed' })).toHaveAttribute('aria-pressed', 'false')
  })

  it('opens the trigger modal, and a successful trigger refreshes the list', async () => {
    mockList.mockResolvedValue({ data: { data: { items: [], next_cursor: null } } })
    mockTrigger.mockResolvedValue({ data: { data: { job_id: 'job-new', status: 'queued' } } })
    renderWithClient()
    await screen.findByText(/No scans yet/)

    fireEvent.click(screen.getByRole('button', { name: /Trigger Scan/i }))
    expect(await screen.findByTestId('trigger-scan-modal')).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Start Scan' }))

    await waitFor(() => expect(mockTrigger).toHaveBeenCalledWith({ provider_id: 'aws-111111111111' }))
    await waitFor(() => expect(screen.queryByTestId('trigger-scan-modal')).not.toBeInTheDocument())
  })

  it('opens the logs panel for a finished scan', async () => {
    mockList.mockResolvedValue({ data: { data: { items: [makeJob()], next_cursor: null } } })
    renderWithClient()

    fireEvent.click(await screen.findByRole('button', { name: /View Logs/i }))

    expect(await screen.findByTestId('scan-logs-panel')).toBeInTheDocument()
    await waitFor(() => expect(mockLogs).toHaveBeenCalledWith('job-abc12345'))
  })

  it('shows a Next page button when a cursor is returned, and fetches the next page', async () => {
    mockList
      .mockResolvedValueOnce({ data: { data: { items: [makeJob({ job_id: 'job-1' })], next_cursor: 'cursor-1' } } })
      .mockResolvedValueOnce({ data: { data: { items: [makeJob({ job_id: 'job-2' })], next_cursor: null } } })
    renderWithClient()
    await screen.findByRole('button', { name: /Next/ })

    fireEvent.click(screen.getByRole('button', { name: /Next/ }))

    await waitFor(() => expect(mockList).toHaveBeenLastCalledWith(expect.objectContaining({ cursor: 'cursor-1' })))
    expect(screen.queryByRole('button', { name: /Next/ })).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Previous/ })).toBeInTheDocument()
  })
})
