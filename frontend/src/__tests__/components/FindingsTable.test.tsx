import '@testing-library/jest-dom'
import { render, screen, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { FindingsTable } from '@/components/findings/FindingsTable'
import type { Finding } from '@/lib/types'

jest.mock('@/lib/api', () => ({
  settingsApi: {
    getSla: jest.fn(() =>
      Promise.resolve({ data: { data: { critical_days: 7, high_days: 30, medium_days: 90, low_days: 180 } } }),
    ),
  },
}))

function renderWithClient(ui: React.ReactElement) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
  return render(ui, { wrapper: Wrapper })
}

const makeFinding = (overrides: Partial<Finding> = {}): Finding => ({
  _key: 'finding-001',
  finding_id: 'f-001',
  tenant_id: 'tenant-test',
  check_id: 'check_s3_public',
  title: 'S3 Bucket Publicly Accessible',
  description: 'The bucket allows public access.',
  resource_id: 'my-bucket',
  resource_arn: 'arn:aws:s3:::my-bucket',
  resource_type: 's3_bucket',
  severity: 'CRITICAL',
  status: 'FAIL',
  provider: 'aws',
  region: 'us-east-1',
  account_id: '123456789012',
  framework_mapping: ['CIS-AWS-2.0'],
  remediation: 'Block public access.',
  remediation_code: null,
  source: 'cspm',
  detected_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
  mute_reason: null,
  scan_job_id: null,
  first_seen_scan_id: null,
  last_seen_scan_id: null,
  scan_count: 1,
  ...overrides,
})

const defaultProps = {
  findings: [
    makeFinding({ _key: 'f-001', title: 'S3 Bucket Publicly Accessible', severity: 'CRITICAL' }),
    makeFinding({ _key: 'f-002', title: 'Security Group Too Permissive', severity: 'HIGH', check_id: 'check_sg' }),
  ],
  loading: false,
  nextCursor: null,
  prevCursors: [],
  onNext: jest.fn(),
  onPrev: jest.fn(),
  onRowClick: jest.fn(),
}

beforeEach(() => jest.clearAllMocks())

describe('FindingsTable', () => {
  it('renders finding rows', () => {
    renderWithClient(<FindingsTable {...defaultProps} />)
    expect(screen.getByText('S3 Bucket Publicly Accessible')).toBeInTheDocument()
    expect(screen.getByText('Security Group Too Permissive')).toBeInTheDocument()
  })

  it('renders severity badges for each row', () => {
    renderWithClient(<FindingsTable {...defaultProps} />)
    expect(screen.getByText('CRITICAL')).toBeInTheDocument()
    expect(screen.getByText('HIGH')).toBeInTheDocument()
  })

  it('shows empty state when findings list is empty', () => {
    renderWithClient(<FindingsTable {...defaultProps} findings={[]} />)
    expect(screen.getByTestId('findings-empty')).toBeInTheDocument()
    expect(screen.getByText('No findings found')).toBeInTheDocument()
  })

  it('shows skeleton loading state', () => {
    renderWithClient(<FindingsTable {...defaultProps} loading={true} />)
    expect(screen.getByTestId('findings-skeleton')).toBeInTheDocument()
    expect(screen.queryByTestId('findings-table')).not.toBeInTheDocument()
  })

  it('calls onRowClick when a row is clicked', () => {
    renderWithClient(<FindingsTable {...defaultProps} />)
    const row = screen.getByText('S3 Bucket Publicly Accessible').closest('tr')!
    fireEvent.click(row)
    expect(defaultProps.onRowClick).toHaveBeenCalledTimes(1)
    expect(defaultProps.onRowClick).toHaveBeenCalledWith(
      expect.objectContaining({ _key: 'f-001' }),
    )
  })

  it('disables Prev button on first page', () => {
    renderWithClient(<FindingsTable {...defaultProps} prevCursors={[]} />)
    expect(screen.getByLabelText('Previous page')).toBeDisabled()
  })

  it('enables Prev button when prevCursors is non-empty', () => {
    renderWithClient(<FindingsTable {...defaultProps} prevCursors={['cursor-abc']} />)
    expect(screen.getByLabelText('Previous page')).not.toBeDisabled()
  })

  it('disables Next button when nextCursor is null', () => {
    renderWithClient(<FindingsTable {...defaultProps} nextCursor={null} />)
    expect(screen.getByLabelText('Next page')).toBeDisabled()
  })

  it('enables Next button when nextCursor is provided', () => {
    renderWithClient(<FindingsTable {...defaultProps} nextCursor="cursor-xyz" />)
    expect(screen.getByLabelText('Next page')).not.toBeDisabled()
  })

  it('calls onNext when Next button is clicked', () => {
    renderWithClient(<FindingsTable {...defaultProps} nextCursor="cursor-xyz" />)
    fireEvent.click(screen.getByLabelText('Next page'))
    expect(defaultProps.onNext).toHaveBeenCalledTimes(1)
  })

  it('renders FAIL status in red', () => {
    renderWithClient(<FindingsTable {...defaultProps} />)
    expect(screen.getAllByText('FAIL')[0]).toHaveClass('text-red-400')
  })

  it('renders MUTED status as badge', () => {
    renderWithClient(
      <FindingsTable
        {...defaultProps}
        findings={[makeFinding({ status: 'MUTED', mute_reason: 'false positive' })]}
      />,
    )
    expect(screen.getByText('MUTED')).toBeInTheDocument()
  })
})
