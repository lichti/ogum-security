import '@testing-library/jest-dom'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import CompliancePage from '@/app/compliance/page'
import { complianceApi, findingsApi } from '@/lib/api'
import type { ComplianceFamily, ComplianceSummary } from '@/lib/types'

jest.mock('@/lib/api', () => ({
  complianceApi: { summary: jest.fn(), frameworkDetail: jest.fn(), trend: jest.fn() },
  findingsApi: { list: jest.fn() },
}))

jest.mock('next/navigation', () => ({
  useRouter: () => ({ push: jest.fn() }),
}))

const mockSummary = complianceApi.summary as jest.Mock
const mockFrameworkDetail = complianceApi.frameworkDetail as jest.Mock
const mockTrend = complianceApi.trend as jest.Mock
const mockFindingsList = findingsApi.list as jest.Mock

function renderWithClient() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
  return render(<CompliancePage />, { wrapper: Wrapper })
}

const family: ComplianceFamily = {
  family: 'cis-aws',
  label: 'CIS AWS Foundations Benchmark',
  target_by_control: null,
  versions: [{ id: 'CIS-7.0', version_label: '7.0', pass: 1, fail: 1, total: 2, score: 50, sections: [] }],
}

function summary(overrides: Partial<ComplianceSummary> = {}): ComplianceSummary {
  return {
    families: [family],
    threat_score: 80,
    top_failing: [],
    top_assets: [],
    ...overrides,
  }
}

beforeEach(() => {
  jest.clearAllMocks()
  mockFrameworkDetail.mockResolvedValue({ data: { data: null } })
  mockTrend.mockResolvedValue({ data: { data: [] } })
  mockFindingsList.mockResolvedValue({ data: { data: { items: [], next_cursor: null, count: 0 } } })
})

describe('CompliancePage', () => {
  it('renders the Framework and Global risk-list columns side by side, both at once', async () => {
    mockSummary.mockImplementation((framework?: string) =>
      Promise.resolve({
        data: {
          data: framework
            ? summary({ top_assets: [asset('scoped-res')] })
            : summary({ top_assets: [asset('global-res')] }),
        },
      }),
    )
    renderWithClient()

    // Both columns visible simultaneously — no toggle/click needed to see the other.
    expect(await screen.findByText('scoped-res')).toBeInTheDocument()
    expect(await screen.findByText('global-res')).toBeInTheDocument()
    expect(screen.getAllByText('CIS AWS Foundations Benchmark').length).toBeGreaterThanOrEqual(2) // framework column label
    expect(screen.getAllByText('Global').length).toBeGreaterThanOrEqual(2) // Findings + Assets columns
    // undefined severity = no filter, since all 5 toggles start selected.
    await waitFor(() => expect(mockSummary).toHaveBeenCalledWith('CIS-7.0', undefined))
  })

  it('all 5 severity toggles start selected and pressed', async () => {
    mockSummary.mockResolvedValue({ data: { data: summary() } })
    renderWithClient()
    await screen.findByRole('button', { name: 'Critical' })

    for (const label of ['Critical', 'High', 'Medium', 'Low', 'Info']) {
      expect(screen.getByRole('button', { name: label })).toHaveAttribute('aria-pressed', 'true')
    }
  })

  it('deselecting one severity refetches both scopes with the remaining severities', async () => {
    mockSummary.mockResolvedValue({ data: { data: summary() } })
    renderWithClient()
    await waitFor(() => expect(mockSummary).toHaveBeenCalledWith('CIS-7.0', undefined))
    mockSummary.mockClear()

    fireEvent.click(screen.getByRole('button', { name: 'Low' }))

    await waitFor(() => {
      expect(mockSummary).toHaveBeenCalledWith(undefined, ['CRITICAL', 'HIGH', 'MEDIUM', 'INFORMATIONAL'])
      expect(mockSummary).toHaveBeenCalledWith('CIS-7.0', ['CRITICAL', 'HIGH', 'MEDIUM', 'INFORMATIONAL'])
    })
    expect(screen.getByRole('button', { name: 'Low' })).toHaveAttribute('aria-pressed', 'false')
  })

  it('deselecting every severity sends a sentinel that matches nothing, not an empty filter', async () => {
    mockSummary.mockResolvedValue({ data: { data: summary() } })
    renderWithClient()
    await screen.findByRole('button', { name: 'Critical' })
    await waitFor(() => expect(mockSummary).toHaveBeenCalledWith('CIS-7.0', undefined))

    for (const label of ['Critical', 'High', 'Medium', 'Low', 'Info']) {
      fireEvent.click(screen.getByRole('button', { name: label }))
    }

    await waitFor(() => expect(mockSummary).toHaveBeenCalledWith('CIS-7.0', ['__none__']))
  })

  it('clicking a Framework-column Top 10 Findings row opens the drill-down scoped to that framework', async () => {
    mockSummary.mockResolvedValue({
      data: {
        data: summary({
          top_failing: [{ check_id: 's3_check', title: 'S3 bucket public', severity: 'HIGH', count: 4 }],
        }),
      },
    })
    renderWithClient()

    const rows = await screen.findAllByText('S3 bucket public')
    fireEvent.click(rows[0]) // Framework column is rendered first

    expect(await screen.findByTestId('compliance-drilldown-panel')).toBeInTheDocument()
    await waitFor(() =>
      expect(mockFindingsList).toHaveBeenCalledWith(
        expect.objectContaining({ check_id: 's3_check', resource_id: undefined, framework: ['CIS-7.0'] }),
      ),
    )
  })

  it('clicking a Global-column Top 10 Assets row opens the drill-down scoped to no framework', async () => {
    mockSummary.mockResolvedValue({ data: { data: summary({ top_assets: [asset('res-a')] }) } })
    renderWithClient()

    const rows = await screen.findAllByText('res-a')
    fireEvent.click(rows[rows.length - 1]) // Global column is rendered second

    expect(await screen.findByTestId('compliance-drilldown-panel')).toBeInTheDocument()
    await waitFor(() =>
      expect(mockFindingsList).toHaveBeenCalledWith(
        expect.objectContaining({ resource_id: 'res-a', check_id: undefined, framework: undefined }),
      ),
    )
  })

  it('closing the drill-down panel removes it', async () => {
    mockSummary.mockResolvedValue({ data: { data: summary({ top_assets: [asset('res-a')] }) } })
    renderWithClient()

    const rows = await screen.findAllByText('res-a')
    fireEvent.click(rows[0])
    await screen.findByTestId('compliance-drilldown-panel')

    fireEvent.click(screen.getByLabelText('Close panel'))
    expect(screen.queryByTestId('compliance-drilldown-panel')).not.toBeInTheDocument()
  })
})

function asset(resourceId: string) {
  return {
    resource_id: resourceId,
    resource_type: 's3_bucket',
    provider: 'aws',
    region: 'us-east-1',
    account_id: '111111111111',
    count: 3,
  }
}
