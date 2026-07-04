import '@testing-library/jest-dom'
import { render, screen, fireEvent } from '@testing-library/react'
import { FindingsTable } from '@/components/findings/FindingsTable'
import type { Finding } from '@/lib/types'

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
    render(<FindingsTable {...defaultProps} />)
    expect(screen.getByText('S3 Bucket Publicly Accessible')).toBeInTheDocument()
    expect(screen.getByText('Security Group Too Permissive')).toBeInTheDocument()
  })

  it('renders severity badges for each row', () => {
    render(<FindingsTable {...defaultProps} />)
    expect(screen.getByText('CRITICAL')).toBeInTheDocument()
    expect(screen.getByText('HIGH')).toBeInTheDocument()
  })

  it('shows empty state when findings list is empty', () => {
    render(<FindingsTable {...defaultProps} findings={[]} />)
    expect(screen.getByTestId('findings-empty')).toBeInTheDocument()
    expect(screen.getByText('No findings found')).toBeInTheDocument()
  })

  it('shows skeleton loading state', () => {
    render(<FindingsTable {...defaultProps} loading={true} />)
    expect(screen.getByTestId('findings-skeleton')).toBeInTheDocument()
    expect(screen.queryByTestId('findings-table')).not.toBeInTheDocument()
  })

  it('calls onRowClick when a row is clicked', () => {
    render(<FindingsTable {...defaultProps} />)
    const row = screen.getByText('S3 Bucket Publicly Accessible').closest('tr')!
    fireEvent.click(row)
    expect(defaultProps.onRowClick).toHaveBeenCalledTimes(1)
    expect(defaultProps.onRowClick).toHaveBeenCalledWith(
      expect.objectContaining({ _key: 'f-001' }),
    )
  })

  it('disables Prev button on first page', () => {
    render(<FindingsTable {...defaultProps} prevCursors={[]} />)
    expect(screen.getByLabelText('Previous page')).toBeDisabled()
  })

  it('enables Prev button when prevCursors is non-empty', () => {
    render(<FindingsTable {...defaultProps} prevCursors={['cursor-abc']} />)
    expect(screen.getByLabelText('Previous page')).not.toBeDisabled()
  })

  it('disables Next button when nextCursor is null', () => {
    render(<FindingsTable {...defaultProps} nextCursor={null} />)
    expect(screen.getByLabelText('Next page')).toBeDisabled()
  })

  it('enables Next button when nextCursor is provided', () => {
    render(<FindingsTable {...defaultProps} nextCursor="cursor-xyz" />)
    expect(screen.getByLabelText('Next page')).not.toBeDisabled()
  })

  it('calls onNext when Next button is clicked', () => {
    render(<FindingsTable {...defaultProps} nextCursor="cursor-xyz" />)
    fireEvent.click(screen.getByLabelText('Next page'))
    expect(defaultProps.onNext).toHaveBeenCalledTimes(1)
  })

  it('renders FAIL status in red', () => {
    render(<FindingsTable {...defaultProps} />)
    expect(screen.getAllByText('FAIL')[0]).toHaveClass('text-red-400')
  })

  it('renders MUTED status as badge', () => {
    render(
      <FindingsTable
        {...defaultProps}
        findings={[makeFinding({ status: 'MUTED', mute_reason: 'false positive' })]}
      />,
    )
    expect(screen.getByText('MUTED')).toBeInTheDocument()
  })
})
