import '@testing-library/jest-dom'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AttackPathList } from '@/components/graph/AttackPathList'
import type { AttackPath } from '@/lib/types'

const makePath = (overrides: Partial<AttackPath> = {}): AttackPath => ({
  _key: 'path-1',
  path_id: 'path-1',
  tenant_id: 'tenant-a',
  rule: 'INTERNET_EC2_S3',
  entry_point_id: 'resources/ep',
  entry_point_type: 'aws_ec2_instance',
  entry_point_name: 'web-server',
  target_id: 'data_assets/s3',
  target_type: 'aws_s3_bucket',
  target_name: 'prod-data',
  hops: 2,
  path_vertex_ids: ['resources/ep', 'data_assets/s3'],
  risk_score: 80,
  severity: 'HIGH',
  is_toxic_combination: false,
  detected_at: '2026-01-01T00:00:00Z',
  status: 'active',
  ...overrides,
})

const PATHS: AttackPath[] = [
  makePath({ _key: 'p1', severity: 'CRITICAL', risk_score: 95, is_toxic_combination: true, entry_point_name: 'bastion' }),
  makePath({ _key: 'p2', severity: 'HIGH', risk_score: 80 }),
  makePath({ _key: 'p3', severity: 'MEDIUM', risk_score: 55, hops: 3, entry_point_name: 'lambda-fn' }),
]

describe('AttackPathList', () => {
  const noop = () => {}

  it('renders severity group headers', () => {
    render(<AttackPathList paths={PATHS} selectedKey={null} onSelect={noop} />)
    expect(screen.getByText('Critical')).toBeInTheDocument()
    expect(screen.getByText('High')).toBeInTheDocument()
    expect(screen.getByText('Medium')).toBeInTheDocument()
    expect(screen.queryByText('Low')).not.toBeInTheDocument()
  })

  it('renders path items with score and route', () => {
    render(<AttackPathList paths={PATHS} selectedKey={null} onSelect={noop} />)
    expect(screen.getByText(/95/)).toBeInTheDocument()
    expect(screen.getByText(/bastion → prod-data/)).toBeInTheDocument()
  })

  it('shows Toxic badge on toxic combination path', () => {
    render(<AttackPathList paths={PATHS} selectedKey={null} onSelect={noop} />)
    expect(screen.getByText('Toxic')).toBeInTheDocument()
  })

  it('does not show Toxic badge on non-toxic paths', () => {
    const nonToxic = [makePath({ _key: 'nt', is_toxic_combination: false })]
    render(<AttackPathList paths={nonToxic} selectedKey={null} onSelect={noop} />)
    expect(screen.queryByText('Toxic')).not.toBeInTheDocument()
  })

  it('highlights the selected path', () => {
    render(<AttackPathList paths={PATHS} selectedKey="p2" onSelect={noop} />)
    const buttons = screen.getAllByRole('button')
    const selected = buttons.find((b) => b.classList.contains('border-orange-500/50'))
    expect(selected).toBeTruthy()
  })

  it('calls onSelect with the clicked path', async () => {
    const onSelect = jest.fn()
    render(<AttackPathList paths={PATHS} selectedKey={null} onSelect={onSelect} />)
    await userEvent.click(screen.getByText(/bastion → prod-data/).closest('button')!)
    expect(onSelect).toHaveBeenCalledTimes(1)
    expect(onSelect).toHaveBeenCalledWith(expect.objectContaining({ _key: 'p1' }))
  })

  it('shows empty state when paths is empty', () => {
    render(<AttackPathList paths={[]} selectedKey={null} onSelect={noop} />)
    expect(screen.getByText('No attack paths')).toBeInTheDocument()
  })

  it('shows skeleton loading state', () => {
    const { container } = render(
      <AttackPathList paths={[]} selectedKey={null} loading onSelect={noop} />,
    )
    const skeletons = container.querySelectorAll('.animate-pulse')
    expect(skeletons.length).toBeGreaterThanOrEqual(3)
  })

  it('groups paths correctly — MEDIUM path appears under Medium header', () => {
    render(<AttackPathList paths={PATHS} selectedKey={null} onSelect={noop} />)
    expect(screen.getByText(/lambda-fn → prod-data/)).toBeInTheDocument()
    expect(screen.getByText('Medium')).toBeInTheDocument()
  })

  it('shows hop count in each path item', () => {
    render(<AttackPathList paths={PATHS} selectedKey={null} onSelect={noop} />)
    expect(screen.getByText(/3 hops/)).toBeInTheDocument()
    expect(screen.getAllByText(/2 hops/).length).toBeGreaterThanOrEqual(1)
  })

  it('groups by target_asset_category as a second level in paths/assets view', () => {
    const paths = [
      makePath({ _key: 'a', severity: 'HIGH', target_asset_category: 'database' }),
      makePath({ _key: 'b', severity: 'HIGH', target_asset_category: 'compute' }),
    ]
    render(<AttackPathList paths={paths} selectedKey={null} viewMode="paths" onSelect={noop} />)
    expect(screen.getByText('Database')).toBeInTheDocument()
    expect(screen.getByText('Compute')).toBeInTheDocument()
  })

  it('groups by rule as a second level in alerts view', () => {
    const paths = [
      makePath({ _key: 'a', severity: 'HIGH', rule: 'TC-02' }),
      makePath({ _key: 'b', severity: 'HIGH', rule: 'privilege_escalation' }),
    ]
    render(<AttackPathList paths={paths} selectedKey={null} viewMode="alerts" onSelect={noop} />)
    expect(screen.getByText('TC-02')).toBeInTheDocument()
    expect(screen.getByText('Privilege Escalation')).toBeInTheDocument()
  })

  it('shows a count for the second-level subgroup', () => {
    const paths = [
      makePath({ _key: 'a', severity: 'HIGH', target_asset_category: 'database' }),
      makePath({ _key: 'b', severity: 'HIGH', target_asset_category: 'database' }),
    ]
    render(<AttackPathList paths={paths} selectedKey={null} viewMode="paths" onSelect={noop} />)
    const header = screen.getByText('Database').closest('button')!
    expect(header).toHaveTextContent('2')
  })

  it('collapses and re-expands the severity group on click', async () => {
    render(<AttackPathList paths={PATHS} selectedKey={null} onSelect={noop} />)
    const criticalHeader = screen.getByText('Critical').closest('button')!
    expect(screen.getByText(/bastion → prod-data/)).toBeInTheDocument()
    await userEvent.click(criticalHeader)
    expect(screen.queryByText(/bastion → prod-data/)).not.toBeInTheDocument()
    await userEvent.click(criticalHeader)
    expect(screen.getByText(/bastion → prod-data/)).toBeInTheDocument()
  })

  it('collapses and re-expands a second-level subgroup on click', async () => {
    render(<AttackPathList paths={PATHS} selectedKey={null} onSelect={noop} />)
    // All PATHS lack target_asset_category, so every severity group has a single
    // "Other" subgroup — the first one in DOM order belongs to the Critical group.
    const subgroupHeader = screen.getAllByText('Other')[0].closest('button')!
    expect(screen.getByText(/bastion → prod-data/)).toBeInTheDocument()
    await userEvent.click(subgroupHeader)
    expect(screen.queryByText(/bastion → prod-data/)).not.toBeInTheDocument()
  })
})
