import '@testing-library/jest-dom'
import { render, screen, fireEvent } from '@testing-library/react'
import { DataTable } from '@/components/inventory/DataTable'
import type { ResourceSummary } from '@/lib/types'

const mockResources: ResourceSummary[] = [
  {
    key: 'aws_ec2_instance_i-001',
    tenant_id: 'test',
    provider: 'aws',
    resource_type: 'ec2_instance',
    resource_id: 'i-001',
    name: 'web-server',
    region: 'us-east-1',
    account_id: '111111111111',
    status: 'active',
    is_public: true,
    tags: {},
    last_scanned_at: null,
    updated_at: null,
  },
  {
    key: 'aws_ec2_instance_i-002',
    tenant_id: 'test',
    provider: 'aws',
    resource_type: 'ec2_instance',
    resource_id: 'i-002',
    name: 'db-server',
    region: 'eu-west-1',
    account_id: '111111111111',
    status: 'active',
    is_public: false,
    tags: {},
    last_scanned_at: null,
    updated_at: null,
  },
]

const defaultProps = {
  resources: mockResources,
  total: 2,
  limit: 50,
  offset: 0,
  loading: false,
  onPageChange: jest.fn(),
  onRowClick: jest.fn(),
}

beforeEach(() => {
  jest.clearAllMocks()
})

describe('DataTable', () => {
  it('renders resource rows', () => {
    render(<DataTable {...defaultProps} />)
    expect(screen.getByText('web-server')).toBeInTheDocument()
    expect(screen.getByText('db-server')).toBeInTheDocument()
  })

  it('renders resource IDs below names', () => {
    render(<DataTable {...defaultProps} />)
    expect(screen.getByText('i-001')).toBeInTheDocument()
    expect(screen.getByText('i-002')).toBeInTheDocument()
  })

  it('shows empty state when no resources', () => {
    render(<DataTable {...defaultProps} resources={[]} total={0} />)
    expect(screen.getByText('No resources found')).toBeInTheDocument()
    expect(screen.queryByText('web-server')).not.toBeInTheDocument()
  })

  it('shows skeleton when loading', () => {
    render(<DataTable {...defaultProps} loading={true} />)
    expect(screen.queryByText('web-server')).not.toBeInTheDocument()
    expect(screen.queryByText('No resources found')).not.toBeInTheDocument()
  })

  it('calls onRowClick when a row is clicked', () => {
    render(<DataTable {...defaultProps} />)
    const row = screen.getByText('web-server').closest('tr')!
    fireEvent.click(row)
    expect(defaultProps.onRowClick).toHaveBeenCalledWith(mockResources[0])
  })

  it('does not render pagination for single page', () => {
    render(<DataTable {...defaultProps} total={2} limit={50} />)
    expect(screen.queryByText(/Page/)).not.toBeInTheDocument()
  })

  it('renders pagination when multiple pages', () => {
    render(<DataTable {...defaultProps} total={200} limit={50} offset={0} />)
    expect(screen.getByText(/Page 1 of 4/)).toBeInTheDocument()
  })

  it('calls onPageChange with correct offset on next page click', () => {
    render(<DataTable {...defaultProps} total={200} limit={50} offset={0} />)
    const buttons = screen.getAllByRole('button')
    const nextButton = buttons[buttons.length - 1]
    fireEvent.click(nextButton)
    expect(defaultProps.onPageChange).toHaveBeenCalledWith(50)
  })

  it('disables prev button on first page', () => {
    render(<DataTable {...defaultProps} total={200} limit={50} offset={0} />)
    const buttons = screen.getAllByRole('button')
    const prevButton = buttons[0]
    expect(prevButton).toBeDisabled()
  })

  it('disables next button on last page', () => {
    render(<DataTable {...defaultProps} total={100} limit={50} offset={50} />)
    const buttons = screen.getAllByRole('button')
    const nextButton = buttons[buttons.length - 1]
    expect(nextButton).toBeDisabled()
  })
})
