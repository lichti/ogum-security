import '@testing-library/jest-dom'
import { render, screen, fireEvent } from '@testing-library/react'
import { AttackPathsTable } from '@/components/attack-paths/AttackPathsTable'
import type { AttackPath } from '@/lib/types'

const makePath = (overrides: Partial<AttackPath> = {}): AttackPath => ({
  _key: 'path-001',
  path_id: 'path-001',
  tenant_id: 'tenant-test',
  rule: 'internet_to_data',
  entry_point_id: 'resources/ec2-001',
  entry_point_type: 'aws_ec2_instance',
  entry_point_name: 'prod-bastion',
  target_id: 'data_assets/s3-001',
  target_type: 'aws_s3_bucket',
  target_name: 'prod-data-bucket',
  hops: 2,
  path_vertex_ids: ['resources/ec2-001', 'data_assets/s3-001'],
  risk_score: 90,
  severity: 'CRITICAL',
  is_toxic_combination: false,
  detected_at: '2026-01-01T00:00:00Z',
  status: 'active',
  ...overrides,
})

const defaultProps = {
  paths: [
    makePath({ _key: 'p-001', entry_point_name: 'bastion-01', severity: 'CRITICAL', risk_score: 90 }),
    makePath({ _key: 'p-002', entry_point_name: 'web-server', severity: 'HIGH', risk_score: 70 }),
  ],
  loading: false,
  nextCursor: null,
  prevCursors: [],
  onNext: jest.fn(),
  onPrev: jest.fn(),
  onRowClick: jest.fn(),
}

beforeEach(() => jest.clearAllMocks())

describe('AttackPathsTable', () => {
  it('renders path rows with entry point and target names', () => {
    render(<AttackPathsTable {...defaultProps} />)
    expect(screen.getByText('bastion-01')).toBeInTheDocument()
    expect(screen.getByText('web-server')).toBeInTheDocument()
    // both rows share the same target name "prod-data-bucket"
    expect(screen.getAllByText('prod-data-bucket').length).toBeGreaterThan(0)
  })

  it('renders severity badges', () => {
    render(<AttackPathsTable {...defaultProps} />)
    expect(screen.getByText('CRITICAL')).toBeInTheDocument()
    expect(screen.getByText('HIGH')).toBeInTheDocument()
  })

  it('renders risk score values', () => {
    render(<AttackPathsTable {...defaultProps} />)
    expect(screen.getByText('90')).toBeInTheDocument()
    expect(screen.getByText('70')).toBeInTheDocument()
  })

  it('renders hops count', () => {
    render(<AttackPathsTable {...defaultProps} />)
    expect(screen.getAllByText('2').length).toBeGreaterThan(0)
  })

  it('shows empty state when paths list is empty', () => {
    render(<AttackPathsTable {...defaultProps} paths={[]} />)
    expect(screen.getByText('No attack paths detected')).toBeInTheDocument()
  })

  it('renders Toxic badge for toxic combinations', () => {
    render(
      <AttackPathsTable
        {...defaultProps}
        paths={[makePath({ is_toxic_combination: true })]}
      />,
    )
    expect(screen.getByText('Toxic')).toBeInTheDocument()
  })

  it('does not render Toxic badge for non-toxic paths', () => {
    render(
      <AttackPathsTable
        {...defaultProps}
        paths={[makePath({ is_toxic_combination: false })]}
      />,
    )
    expect(screen.queryByText('Toxic')).not.toBeInTheDocument()
  })

  it('calls onRowClick when a row is clicked', () => {
    render(<AttackPathsTable {...defaultProps} />)
    const row = screen.getByText('bastion-01').closest('tr')!
    fireEvent.click(row)
    expect(defaultProps.onRowClick).toHaveBeenCalledWith(
      expect.objectContaining({ _key: 'p-001' }),
    )
  })

  it('disables Prev button on first page', () => {
    render(<AttackPathsTable {...defaultProps} prevCursors={[]} />)
    expect(screen.getByLabelText('Previous page')).toBeDisabled()
  })

  it('enables Prev button when prevCursors is non-empty', () => {
    render(<AttackPathsTable {...defaultProps} prevCursors={['cursor-abc']} />)
    expect(screen.getByLabelText('Previous page')).not.toBeDisabled()
  })

  it('disables Next button when nextCursor is null', () => {
    render(<AttackPathsTable {...defaultProps} nextCursor={null} />)
    expect(screen.getByLabelText('Next page')).toBeDisabled()
  })

  it('enables Next button when nextCursor is provided', () => {
    render(<AttackPathsTable {...defaultProps} nextCursor="cursor-xyz" />)
    expect(screen.getByLabelText('Next page')).not.toBeDisabled()
  })

  it('calls onNext when Next button is clicked', () => {
    render(<AttackPathsTable {...defaultProps} nextCursor="cursor-xyz" />)
    fireEvent.click(screen.getByLabelText('Next page'))
    expect(defaultProps.onNext).toHaveBeenCalledTimes(1)
  })

  it('shows skeleton rows when loading', () => {
    render(<AttackPathsTable {...defaultProps} loading={true} />)
    // loading renders skeleton cells — no path names visible
    expect(screen.queryByText('bastion-01')).not.toBeInTheDocument()
  })

  it('shows path count in footer', () => {
    render(<AttackPathsTable {...defaultProps} />)
    expect(screen.getByText('2 paths')).toBeInTheDocument()
  })
})
