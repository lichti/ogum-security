import '@testing-library/jest-dom'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { FrameworkDetail } from '@/components/compliance/FrameworkDetail'
import { complianceApi } from '@/lib/api'
import type { ComplianceFamily, ComplianceFrameworkDetail } from '@/lib/types'

jest.mock('@/lib/api', () => ({
  complianceApi: { frameworkDetail: jest.fn(), trend: jest.fn() },
}))

jest.mock('next/navigation', () => ({
  useRouter: () => ({ push: jest.fn() }),
}))

const mockFrameworkDetail = complianceApi.frameworkDetail as jest.Mock
const mockTrend = complianceApi.trend as jest.Mock

function renderWithClient(ui: React.ReactElement) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
  return render(ui, { wrapper: Wrapper })
}

function mockDetail(overrides: Partial<ComplianceFrameworkDetail> = {}): ComplianceFrameworkDetail {
  return {
    id: 'NIST-800-53-Revision-5',
    family: 'nist-800-53',
    family_label: 'NIST 800-53',
    version_label: 'Revision 5',
    score_by_control: 66.7,
    score_by_asset: 66.7,
    control_pass_count: 10,
    control_fail_count: 5,
    control_unscored_count: 0,
    control_total: 15,
    finding_pass_count: 10,
    finding_fail_count: 5,
    finding_accepted_count: 0,
    finding_muted_count: 0,
    catalog_available: false,
    sections: [],
    ...overrides,
  }
}

const family: ComplianceFamily = {
  family: 'nist-800-53',
  label: 'NIST 800-53',
  versions: [
    {
      id: 'NIST-800-53-Revision-5',
      version_label: 'Revision 5',
      pass: 10,
      fail: 5,
      total: 15,
      score: 66.7,
      sections: [],
    },
    {
      id: 'NIST-800-53-Revision-4',
      version_label: 'Revision 4',
      pass: 2,
      fail: 2,
      total: 4,
      score: 50,
      sections: [],
    },
  ],
}

const onVersionChange = jest.fn()

beforeEach(() => {
  jest.clearAllMocks()
  mockFrameworkDetail.mockResolvedValue({ data: { data: mockDetail() } })
  mockTrend.mockResolvedValue({ data: { data: [] } })
})

describe('FrameworkDetail', () => {
  it('renders the family label and the selected version score', () => {
    renderWithClient(
      <FrameworkDetail family={family} selectedVersionId="NIST-800-53-Revision-5" onVersionChange={onVersionChange} />,
    )
    expect(screen.getByText('NIST 800-53')).toBeInTheDocument()
    expect(screen.getByText('66.7%')).toBeInTheDocument()
  })

  it('renders a tab per version when there is more than one', () => {
    renderWithClient(
      <FrameworkDetail family={family} selectedVersionId="NIST-800-53-Revision-5" onVersionChange={onVersionChange} />,
    )
    expect(screen.getByText('Revision 5')).toBeInTheDocument()
    expect(screen.getByText('Revision 4')).toBeInTheDocument()
  })

  it('calls onVersionChange when a different version tab is clicked', () => {
    renderWithClient(
      <FrameworkDetail family={family} selectedVersionId="NIST-800-53-Revision-5" onVersionChange={onVersionChange} />,
    )
    fireEvent.click(screen.getByText('Revision 4'))
    expect(onVersionChange).toHaveBeenCalledWith('NIST-800-53-Revision-4')
  })

  it('links "View findings" to the Findings page scoped by the selected version id', () => {
    renderWithClient(
      <FrameworkDetail family={family} selectedVersionId="NIST-800-53-Revision-5" onVersionChange={onVersionChange} />,
    )
    const link = screen.getByText('View findings').closest('a')
    expect(link).toHaveAttribute('href', '/findings?framework=NIST-800-53-Revision-5')
  })

  it('does not render version tabs for a single-version family', () => {
    const single: ComplianceFamily = {
      family: 'SOC2',
      label: 'SOC 2',
      versions: [{ id: 'SOC2', version_label: '', pass: 1, fail: 1, total: 2, score: 50, sections: [] }],
    }
    renderWithClient(<FrameworkDetail family={single} selectedVersionId="SOC2" onVersionChange={onVersionChange} />)
    // "tab" is reused by the version switcher and the trend period selector — neither
    // renders here: a single-version family skips VersionTabs, and the detail query
    // (mocked, unresolved at this point in the test) hasn't mounted ScoreTrendChart yet.
    expect(screen.queryByRole('tab')).not.toBeInTheDocument()
  })

  it('fetches and renders the framework detail: score duality, heatmap, and accordion', async () => {
    mockFrameworkDetail.mockResolvedValue({
      data: {
        data: mockDetail({
          score_by_control: 40,
          score_by_asset: 66.7,
          control_unscored_count: 3,
          catalog_available: true,
          sections: [
            {
              key: 'ac',
              label: 'AC — Access Control',
              control_pass_count: 6,
              control_fail_count: 1,
              control_unscored_count: 0,
              control_total: 7,
              score_by_control: 85.7,
              finding_pass_count: 6,
              finding_fail_count: 1,
              finding_accepted_count: 0,
              finding_muted_count: 0,
              score_by_asset: 85.7,
              subsections: [],
              requirements: [
                {
                  control_id: 'ac_2',
                  name: 'Account Management',
                  description: null,
                  status: 'FAIL',
                  finding_key: 'find-1',
                  pass_count: 0,
                  fail_count: 1,
                  accepted_count: 0,
                  muted_count: 0,
                },
              ],
            },
          ],
        }),
      },
    })

    renderWithClient(
      <FrameworkDetail family={family} selectedVersionId="NIST-800-53-Revision-5" onVersionChange={onVersionChange} />,
    )

    await waitFor(() => {
      expect(mockFrameworkDetail).toHaveBeenCalledWith('NIST-800-53-Revision-5')
    })

    // Score duality — both scores shown, distinct from each other.
    expect(await screen.findByText('40%')).toBeInTheDocument()
    expect(screen.getByText('By control')).toBeInTheDocument()
    expect(screen.getByText('By asset')).toBeInTheDocument()
    // Unscored count (3) appears twice: ScoreDuality's stat and the summary row's Unscored bucket.
    expect(screen.getAllByText('3').length).toBeGreaterThanOrEqual(2)

    // "AC — Access Control" appears twice: once in the heatmap cell, once as the
    // accordion's section header button.
    const sectionLabels = screen.getAllByText('AC — Access Control')
    expect(sectionLabels).toHaveLength(2)
    expect(screen.getByText('85.7%')).toBeInTheDocument()

    // Accordion — collapsed by default, requirement hidden until expanded.
    expect(screen.queryByText('Account Management')).not.toBeInTheDocument()
    const accordionHeader = sectionLabels.find((el) => el.closest('button'))
    fireEvent.click(accordionHeader!.closest('button')!)
    expect(await screen.findByText('Account Management')).toBeInTheDocument()
  })

  it('toggles the summary row between the Control and Findings breakdowns', async () => {
    mockFrameworkDetail.mockResolvedValue({
      data: {
        data: mockDetail({
          control_pass_count: 8,
          control_fail_count: 2,
          control_unscored_count: 5,
          control_total: 15,
          finding_pass_count: 20,
          finding_fail_count: 4,
          finding_accepted_count: 3,
          finding_muted_count: 1,
        }),
      },
    })

    renderWithClient(
      <FrameworkDetail family={family} selectedVersionId="NIST-800-53-Revision-5" onVersionChange={onVersionChange} />,
    )

    // Control view (default): Pass/Fail/Unscored/Total, no Accepted/Muted.
    expect(await screen.findByText('By Control')).toBeInTheDocument()
    expect(screen.getByText('8')).toBeInTheDocument()
    expect(screen.getByText('15')).toBeInTheDocument()
    expect(screen.queryByText('Accepted')).not.toBeInTheDocument()
    expect(screen.queryByText('Muted')).not.toBeInTheDocument()

    fireEvent.click(screen.getByText('By Findings'))

    expect(screen.getByText('Accepted')).toBeInTheDocument()
    expect(screen.getByText('Muted')).toBeInTheDocument()
    expect(screen.getByText('20')).toBeInTheDocument() // finding_pass_count
    expect(screen.getByText('3')).toBeInTheDocument() // finding_accepted_count
    // Total = 20+4+3+1+5 (control_unscored_count reused as context) = 33
    expect(screen.getByText('33')).toBeInTheDocument()
  })
})
