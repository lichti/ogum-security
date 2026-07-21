import '@testing-library/jest-dom'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// Mock the sideScanApi so no HTTP calls are made. Response shape mirrors what
// apiClient.get<T>() actually returns — an Axios response, so the payload is
// one level deeper at `.data` — not the bare payload. A prior version of this
// mock skipped that wrapper, which meant every test here still passed even
// after page.tsx read `data.items` directly instead of `data.data.items`: the
// KPI/table code's `?? []` fallback made "wrong shape" and "genuinely empty"
// look identical, so the bug went uncaught until real job data existed.
jest.mock('@/lib/api', () => ({
  sideScanApi: {
    listJobs: jest.fn().mockResolvedValue({ data: { items: [], total: 0, limit: 100, offset: 0 } }),
    retryJob: jest.fn(),
    getJob: jest.fn(),
    imageSecurityStatus: jest.fn(),
  },
}))

import SideScanning from '@/app/side-scanning/page'

function wrapper({ children }: { children: React.ReactNode }) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
}

describe('SideScanning page', () => {
  it('renders the page root', () => {
    // Page title/subtitle live in the shared top-bar Header (not rendered by
    // this page in isolation) — see the "Page header" convention in CLAUDE.md.
    const { container } = render(<SideScanning />, { wrapper })
    expect(container.querySelector('#side-scanning-page')).toBeInTheDocument()
  })

  it('renders KPI cards', () => {
    render(<SideScanning />, { wrapper })
    expect(screen.getByText('EC2 Jobs')).toBeInTheDocument()
    expect(screen.getByText('Lambda Jobs')).toBeInTheDocument()
    expect(screen.getByText('K8s Container Jobs')).toBeInTheDocument()
    expect(screen.getByText('Registry Jobs')).toBeInTheDocument()
  })

  it('renders status filter dropdown', () => {
    render(<SideScanning />, { wrapper })
    expect(screen.getByText('All statuses')).toBeInTheDocument()
  })

  it('renders type filter dropdown', () => {
    render(<SideScanning />, { wrapper })
    expect(screen.getByText('All types')).toBeInTheDocument()
  })

  it('shows loading state while query is in flight', () => {
    const { sideScanApi } = jest.requireMock('@/lib/api') as { sideScanApi: { listJobs: jest.Mock } }
    // Return a promise that never resolves to keep the loading state
    sideScanApi.listJobs.mockReturnValueOnce(new Promise(() => {}))
    render(<SideScanning />, { wrapper })
    expect(screen.getByText('Loading scan jobs…')).toBeInTheDocument()
  })

  it('renders jobs from a real (non-empty) API response', async () => {
    const { sideScanApi } = jest.requireMock('@/lib/api') as { sideScanApi: { listJobs: jest.Mock } }
    sideScanApi.listJobs.mockResolvedValueOnce({
      data: {
        total: 1,
        limit: 100,
        offset: 0,
        items: [
          {
            _key: 'ec2_instance-abc-123',
            tenant_id: 'dev-tenant',
            type: 'ec2',
            status: 'completed',
            resource_id: 'i-0abc123',
            started_at: '2026-07-12T16:59:56.612151+00:00',
            completed_at: '2026-07-12T16:59:57.494711+00:00',
          },
        ],
      },
    })

    render(<SideScanning />, { wrapper })

    expect(await screen.findByText('i-0abc123')).toBeInTheDocument()
    expect(screen.getByText('1 job total')).toBeInTheDocument()
    expect(screen.getByText('completed')).toBeInTheDocument()
  })
})
