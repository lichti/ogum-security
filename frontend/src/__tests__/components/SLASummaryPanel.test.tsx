import '@testing-library/jest-dom'
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { SLASummaryPanel } from '@/components/findings/SLASummaryPanel'
import { findingsApi } from '@/lib/api'

jest.mock('@/lib/api', () => ({
  findingsApi: { slaSummary: jest.fn() },
}))

const mockSlaSummary = findingsApi.slaSummary as jest.Mock

function renderWithClient(ui: React.ReactElement) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
  return render(ui, { wrapper: Wrapper })
}

beforeEach(() => jest.clearAllMocks())

describe('SLASummaryPanel', () => {
  it('renders counts and percentages for each SLA state', async () => {
    mockSlaSummary.mockResolvedValue({ data: { data: { within_sla: 6, at_risk: 3, overdue: 1 } } })
    renderWithClient(<SLASummaryPanel />)
    await waitFor(() => {
      expect(screen.getByText('Within SLA')).toBeInTheDocument()
      expect(screen.getByText('At Risk')).toBeInTheDocument()
      expect(screen.getByText('Overdue')).toBeInTheDocument()
      expect(screen.getByTestId('sla-summary-panel').textContent).toContain('6')
    })
  })

  it('renders zeroed tiles before data loads', () => {
    mockSlaSummary.mockReturnValue(new Promise(() => {}))
    renderWithClient(<SLASummaryPanel />)
    expect(screen.getByTestId('sla-summary-panel')).toBeInTheDocument()
  })
})
