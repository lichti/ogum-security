import '@testing-library/jest-dom'
import { render, screen, fireEvent } from '@testing-library/react'
import { DetailPanel } from '@/components/inventory/DetailPanel'
import type { ResourceDetail } from '@/lib/types'

const mockResource: ResourceDetail = {
  key: 'aws_ec2_instance_i-001',
  tenant_id: 'test',
  provider: 'aws',
  resource_type: 'ec2_instance',
  resource_id: 'i-001',
  name: 'web-server',
  arn: 'arn:aws:ec2:us-east-1:111111111111:instance/i-001',
  region: 'us-east-1',
  account_id: '111111111111',
  status: 'active',
  is_public: true,
  tags: { env: 'prod', team: 'platform' },
  last_scanned_at: null,
  updated_at: null,
  raw_metadata: { instance_type: 't3.micro' },
  edges: [
    {
      edge_type: 'BELONGS_TO',
      direction: 'outbound',
      peer_key: 'aws_vpc_vpc-001',
      peer_collection: 'resources',
      peer_type: 'vpc',
    },
  ],
}

describe('DetailPanel', () => {
  it('renders nothing when resource is null', () => {
    const { container } = render(<DetailPanel resource={null} onClose={jest.fn()} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('renders the panel when resource is provided', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />)
    expect(screen.getByTestId('detail-panel')).toBeInTheDocument()
  })

  it('renders resource name and ID', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />)
    expect(screen.getByText('web-server')).toBeInTheDocument()
    expect(screen.getByText('i-001')).toBeInTheDocument()
  })

  it('renders ARN', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />)
    expect(screen.getByText('arn:aws:ec2:us-east-1:111111111111:instance/i-001')).toBeInTheDocument()
  })

  it('renders tags', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />)
    expect(screen.getByText('env: prod')).toBeInTheDocument()
    expect(screen.getByText('team: platform')).toBeInTheDocument()
  })

  it('renders edge type and peer key', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />)
    expect(screen.getByText('BELONGS_TO')).toBeInTheDocument()
    expect(screen.getByText('aws_vpc_vpc-001')).toBeInTheDocument()
    expect(screen.getByText('(vpc)')).toBeInTheDocument()
  })

  it('renders Relationships count', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />)
    expect(screen.getByText('Relationships (1)')).toBeInTheDocument()
  })

  it('renders findings placeholder', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />)
    expect(screen.getByText(/No findings yet/)).toBeInTheDocument()
  })

  it('calls onClose when close button is clicked', () => {
    const onClose = jest.fn()
    render(<DetailPanel resource={mockResource} onClose={onClose} />)
    fireEvent.click(screen.getByLabelText('Close panel'))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('renders empty edges message when no edges', () => {
    const noEdgesResource = { ...mockResource, edges: [] }
    render(<DetailPanel resource={noEdgesResource} onClose={jest.fn()} />)
    expect(screen.getByText('No edges found.')).toBeInTheDocument()
    expect(screen.getByText('Relationships (0)')).toBeInTheDocument()
  })

  it('renders console link for ec2 instance', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />)
    const link = screen.getByTitle('Open in console')
    expect(link).toHaveAttribute('href', expect.stringContaining('console.aws.amazon.com'))
    expect(link).toHaveAttribute('target', '_blank')
  })
})
