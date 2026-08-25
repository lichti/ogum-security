import '@testing-library/jest-dom'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { FrameworkDetail } from '@/components/compliance/FrameworkDetail'
import { complianceApi, findingsApi, settingsApi } from '@/lib/api'
import type { ComplianceFamily, ComplianceFrameworkDetail } from '@/lib/types'

jest.mock('@/lib/api', () => ({
  complianceApi: { frameworkDetail: jest.fn(), trend: jest.fn(), controlAssets: jest.fn() },
  settingsApi: { updateCompliance: jest.fn() },
  findingsApi: { list: jest.fn() },
}))

jest.mock('next/navigation', () => ({
  useRouter: () => ({ push: jest.fn() }),
}))

const mockFrameworkDetail = complianceApi.frameworkDetail as jest.Mock
const mockTrend = complianceApi.trend as jest.Mock
const mockControlAssets = complianceApi.controlAssets as jest.Mock
const mockUpdateCompliance = settingsApi.updateCompliance as jest.Mock
const mockFindingsList = findingsApi.list as jest.Mock

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
    target_by_control: null,
    control_pass_count: 10,
    control_fail_count: 5,
    control_unscored_count: 0,
    control_total: 15,
    catalog_available: false,
    sections: [],
    ...overrides,
  }
}

const family: ComplianceFamily = {
  family: 'nist-800-53',
  label: 'NIST 800-53',
  target_by_control: null,
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
  mockUpdateCompliance.mockResolvedValue({ data: { data: {} } })
  mockControlAssets.mockResolvedValue({ data: { data: [] } })
  mockFindingsList.mockResolvedValue({ data: { data: { items: [], next_cursor: null } } })
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
      target_by_control: null,
      versions: [{ id: 'SOC2', version_label: '', pass: 1, fail: 1, total: 2, score: 50, sections: [] }],
    }
    renderWithClient(<FrameworkDetail family={single} selectedVersionId="SOC2" onVersionChange={onVersionChange} />)
    // "tab" is reused by the version switcher and the trend period selector — neither
    // renders here: a single-version family skips VersionTabs, and the detail query
    // (mocked, unresolved at this point in the test) hasn't mounted ScoreTrendChart yet.
    expect(screen.queryByRole('tab')).not.toBeInTheDocument()
  })

  it('fetches and renders the framework detail: unscored count and expandable sections', async () => {
    mockFrameworkDetail.mockResolvedValue({
      data: {
        data: mockDetail({
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

    // Unscored count (3) appears twice: the header stat and the summary row's Unscored bucket.
    expect(await screen.findAllByText('3')).toHaveLength(2)

    // Sections merges the heatmap row and the accordion toggle into one — "AC —
    // Access Control" now renders exactly once, not once per representation.
    const sectionLabel = screen.getByText('AC — Access Control')
    expect(screen.getByText('85.7%')).toBeInTheDocument()

    // Collapsed by default, requirement hidden until the section row is clicked.
    expect(screen.queryByText('Account Management')).not.toBeInTheDocument()
    fireEvent.click(sectionLabel.closest('button')!)
    expect(await screen.findByText('Account Management')).toBeInTheDocument()
  })

  it('clicking a Fail/Pass requirement row opens the control drilldown panel', async () => {
    mockFrameworkDetail.mockResolvedValue({
      data: {
        data: mockDetail({
          sections: [
            {
              key: 'ac',
              label: 'AC — Access Control',
              control_pass_count: 6,
              control_fail_count: 1,
              control_unscored_count: 0,
              control_total: 7,
              score_by_control: 85.7,
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

    fireEvent.click(await screen.findByText('AC — Access Control'))
    fireEvent.click(await screen.findByText('Account Management'))

    expect(await screen.findByTestId('control-drilldown-panel')).toBeInTheDocument()
    expect(screen.getByText('ac_2')).toBeInTheDocument()
    await waitFor(() =>
      expect(mockFindingsList).toHaveBeenCalledWith(
        expect.objectContaining({ framework: ['NIST-800-53-Revision-5/ac_2'] }),
      ),
    )
  })

  it('renders Score Trend before Sections, and Sections with no collapse toggle', async () => {
    mockFrameworkDetail.mockResolvedValue({
      data: {
        data: mockDetail({
          sections: [
            {
              key: 'ac',
              label: 'AC — Access Control',
              control_pass_count: 6,
              control_fail_count: 1,
              control_unscored_count: 0,
              control_total: 7,
              score_by_control: 85.7,
              subsections: [],
              requirements: [],
            },
          ],
        }),
      },
    })

    const { container } = renderWithClient(
      <FrameworkDetail family={family} selectedVersionId="NIST-800-53-Revision-5" onVersionChange={onVersionChange} />,
    )

    await screen.findByText('AC — Access Control')

    const trend = container.querySelector('#compliance-score-trend-chart')
    const sections = container.querySelector('#compliance-sections')
    expect(trend).toBeInTheDocument()
    expect(sections).toBeInTheDocument()
    // DOCUMENT_POSITION_FOLLOWING (4) means `sections` comes after `trend` in the DOM.
    expect(trend!.compareDocumentPosition(sections!) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()

    // "Sections" is a plain heading now, not a collapsible toggle button.
    expect(screen.queryByRole('button', { name: /Sections/ })).not.toBeInTheDocument()
    expect(screen.getByText('Sections (1)')).toBeInTheDocument()
  })

  it('shows a vs-goal indicator when a Compliance Settings target is configured', async () => {
    mockFrameworkDetail.mockResolvedValue({
      data: {
        data: mockDetail({
          score_by_control: 40,
          target_by_control: 90, // below goal
        }),
      },
    })

    renderWithClient(
      <FrameworkDetail family={family} selectedVersionId="NIST-800-53-Revision-5" onVersionChange={onVersionChange} />,
    )

    expect(await screen.findByText('▾ Goal 90%')).toBeInTheDocument()
  })

  it('setting a goal inline calls settingsApi.updateCompliance for this family and refreshes the detail', async () => {
    renderWithClient(
      <FrameworkDetail family={family} selectedVersionId="NIST-800-53-Revision-5" onVersionChange={onVersionChange} />,
    )
    await waitFor(() => expect(mockFrameworkDetail).toHaveBeenCalledWith('NIST-800-53-Revision-5'))

    fireEvent.click(await screen.findByRole('button', { name: 'Set control goal' }))
    fireEvent.change(screen.getByLabelText('control goal percentage'), { target: { value: '80' } })
    fireEvent.click(screen.getByLabelText('Save goal'))

    await waitFor(() =>
      expect(mockUpdateCompliance).toHaveBeenCalledWith('nist-800-53', { target_by_control: 80 }),
    )
    // Saving a target re-fetches the framework detail so the new goal shows up immediately.
    await waitFor(() => expect(mockFrameworkDetail).toHaveBeenCalledTimes(2))
  })

  it('clearing an existing goal sends the clear flag, not a value', async () => {
    mockFrameworkDetail.mockResolvedValue({ data: { data: mockDetail({ target_by_control: 60 }) } })
    renderWithClient(
      <FrameworkDetail family={family} selectedVersionId="NIST-800-53-Revision-5" onVersionChange={onVersionChange} />,
    )

    fireEvent.click(await screen.findByRole('button', { name: 'Edit control goal' }))
    fireEvent.click(screen.getByRole('button', { name: 'Clear goal' }))

    await waitFor(() =>
      expect(mockUpdateCompliance).toHaveBeenCalledWith('nist-800-53', { clear_target_by_control: true }),
    )
  })

  it('shows the Pass/Fail/Unscored/Total summary row from the fetched detail', async () => {
    mockFrameworkDetail.mockResolvedValue({
      data: {
        data: mockDetail({
          control_pass_count: 8,
          control_fail_count: 2,
          control_unscored_count: 5,
          control_total: 15,
        }),
      },
    })

    renderWithClient(
      <FrameworkDetail family={family} selectedVersionId="NIST-800-53-Revision-5" onVersionChange={onVersionChange} />,
    )

    expect(await screen.findByText('8')).toBeInTheDocument()
    expect(screen.getByText('15')).toBeInTheDocument()
  })
})
