import '@testing-library/jest-dom'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { ScoreTrendChart } from '@/components/compliance/ScoreTrendChart'
import { complianceApi } from '@/lib/api'
import type { ComplianceScoreTrendPoint } from '@/lib/types'

jest.mock('@/lib/api', () => ({
  complianceApi: { trend: jest.fn() },
}))

const mockTrend = complianceApi.trend as jest.Mock

function renderWithClient(ui: React.ReactElement) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
  return render(ui, { wrapper: Wrapper })
}

function point(overrides: Partial<ComplianceScoreTrendPoint> = {}): ComplianceScoreTrendPoint {
  return {
    date: '2026-07-15',
    score_by_control: 70,
    score_by_asset: 80,
    pass_count: 7,
    fail_count: 3,
    unscored_count: 0,
    ...overrides,
  }
}

beforeEach(() => jest.clearAllMocks())

describe('ScoreTrendChart', () => {
  it('shows an empty state when there is no history yet', async () => {
    mockTrend.mockResolvedValue({ data: { data: [] } })
    renderWithClient(<ScoreTrendChart frameworkId="CIS-7.0" />)
    await waitFor(() => {
      expect(screen.getByText(/No history yet/)).toBeInTheDocument()
    })
  })

  it('fetches the default 7d period on mount', async () => {
    mockTrend.mockResolvedValue({ data: { data: [point()] } })
    renderWithClient(<ScoreTrendChart frameworkId="CIS-7.0" />)
    await waitFor(() => {
      expect(mockTrend).toHaveBeenCalledWith('CIS-7.0', '7d')
    })
  })

  it('refetches with the new period when the selector changes', async () => {
    const user = userEvent.setup()
    mockTrend.mockResolvedValue({ data: { data: [point()] } })
    renderWithClient(<ScoreTrendChart frameworkId="CIS-7.0" />)
    await waitFor(() => expect(mockTrend).toHaveBeenCalledWith('CIS-7.0', '7d'))

    await user.click(screen.getByRole('tab', { name: '1M' }))
    await waitFor(() => expect(mockTrend).toHaveBeenCalledWith('CIS-7.0', '1m'))
  })
})
