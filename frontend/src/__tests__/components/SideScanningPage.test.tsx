import '@testing-library/jest-dom'
import { render, screen } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// Mock the sideScanApi so no HTTP calls are made
jest.mock('@/lib/api', () => ({
  sideScanApi: {
    listJobs: jest.fn().mockResolvedValue({ items: [], total: 0, limit: 100, offset: 0 }),
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
  it('renders page title', () => {
    render(<SideScanning />, { wrapper })
    expect(screen.getByText('Side Scanning')).toBeInTheDocument()
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
    const { sideScanApi } = require('@/lib/api')
    // Return a promise that never resolves to keep the loading state
    sideScanApi.listJobs.mockReturnValueOnce(new Promise(() => {}))
    render(<SideScanning />, { wrapper })
    expect(screen.getByText('Loading scan jobs…')).toBeInTheDocument()
  })
})
