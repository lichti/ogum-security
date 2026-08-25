import '@testing-library/jest-dom'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { ScoreTrendChart, ScoreTrendTooltip } from '@/components/compliance/ScoreTrendChart'
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

  it('renders a score chart and a separate unscored-controls mini-chart, not a shared dual-axis chart', async () => {
    // recharts' ResponsiveContainer needs real layout to mount its children — jsdom
    // reports 0x0 for every element, so this only verifies the two chart containers
    // this component is structured around, not the rendered lines/legend themselves
    // (no test in this codebase exercises recharts' internal SVG output).
    mockTrend.mockResolvedValue({ data: { data: [point()] } })
    const { container } = renderWithClient(<ScoreTrendChart frameworkId="CIS-7.0" />)
    await waitFor(() => expect(mockTrend).toHaveBeenCalled())

    const containers = await screen.findAllByText('', { selector: '.recharts-responsive-container' })
    expect(containers).toHaveLength(2)
    expect(container.querySelector('.h-32')).toBeInTheDocument() // score % chart
    expect(container.querySelector('.h-16')).toBeInTheDocument() // unscored count mini-chart
  })
})

// jsdom can't simulate recharts' real mouse-driven hover (ResponsiveContainer reports
// 0x0 layout, see the comment above), so the combined tooltip — one box for both
// charts, fixing the "two tooltips at once" bug — is exercised directly here instead
// of through a simulated hover on ScoreTrendChart.
describe('ScoreTrendTooltip', () => {
  const points = [point({ date: '2026-07-15', score_by_control: 70, unscored_count: 4 })]

  it('renders nothing when inactive', () => {
    const { container } = render(<ScoreTrendTooltip active={false} label="2026-07-15" points={points} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('renders nothing when the label has no matching point', () => {
    const { container } = render(<ScoreTrendTooltip active label="2099-01-01" points={points} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('renders the score and unscored count in one box, the score suffixed and the count bare', () => {
    render(<ScoreTrendTooltip active label="2026-07-15" points={points} />)
    expect(screen.getByText('2026-07-15')).toBeInTheDocument()
    expect(screen.getByText('70%')).toBeInTheDocument()
    expect(screen.getByText('4')).toBeInTheDocument()
    expect(screen.queryByText('4%')).not.toBeInTheDocument()
  })
})
