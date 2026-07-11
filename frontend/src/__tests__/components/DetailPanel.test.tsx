import '@testing-library/jest-dom'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'

jest.mock('@/lib/api', () => ({
  sideScanApi: {
    triggerScan: jest.fn(),
  },
}))

import { DetailPanel } from '@/components/inventory/DetailPanel'
import { sideScanApi } from '@/lib/api'
import type { ResourceDetail } from '@/lib/types'

const mockTriggerScan = sideScanApi.triggerScan as jest.Mock

function wrapper({ children }: { children: ReactNode }) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
}

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
  beforeEach(() => {
    mockTriggerScan.mockReset()
  })

  it('renders nothing when resource is null', () => {
    const { container } = render(<DetailPanel resource={null} onClose={jest.fn()} />, { wrapper })
    expect(container).toBeEmptyDOMElement()
  })

  it('renders the panel when resource is provided', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />, { wrapper })
    expect(screen.getByTestId('detail-panel')).toBeInTheDocument()
  })

  it('renders resource name and ID', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />, { wrapper })
    expect(screen.getByText('web-server')).toBeInTheDocument()
    expect(screen.getByText('i-001')).toBeInTheDocument()
  })

  it('renders ARN', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />, { wrapper })
    expect(screen.getByText('arn:aws:ec2:us-east-1:111111111111:instance/i-001')).toBeInTheDocument()
  })

  it('renders tags', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />, { wrapper })
    expect(screen.getByText('env: prod')).toBeInTheDocument()
    expect(screen.getByText('team: platform')).toBeInTheDocument()
  })

  it('renders edge type and peer key', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />, { wrapper })
    expect(screen.getByText('BELONGS_TO')).toBeInTheDocument()
    expect(screen.getByText('aws_vpc_vpc-001')).toBeInTheDocument()
    expect(screen.getByText('(vpc)')).toBeInTheDocument()
  })

  it('renders Relationships count', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />, { wrapper })
    expect(screen.getByText('Relationships (1)')).toBeInTheDocument()
  })

  it('renders findings placeholder', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />, { wrapper })
    expect(screen.getByText(/No findings yet/)).toBeInTheDocument()
  })

  it('calls onClose when close button is clicked', () => {
    const onClose = jest.fn()
    render(<DetailPanel resource={mockResource} onClose={onClose} />, { wrapper })
    fireEvent.click(screen.getByLabelText('Close panel'))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('renders empty edges message when no edges', () => {
    const noEdgesResource = { ...mockResource, edges: [] }
    render(<DetailPanel resource={noEdgesResource} onClose={jest.fn()} />, { wrapper })
    expect(screen.getByText('No edges found.')).toBeInTheDocument()
    expect(screen.getByText('Relationships (0)')).toBeInTheDocument()
  })

  it('renders console link for ec2 instance', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />, { wrapper })
    const link = screen.getByTitle('Open in console')
    expect(link).toHaveAttribute('href', expect.stringContaining('console.aws.amazon.com'))
    expect(link).toHaveAttribute('target', '_blank')
  })

  describe('Scan Now', () => {
    it('renders for an active ec2_instance resource', () => {
      render(<DetailPanel resource={mockResource} onClose={jest.fn()} />, { wrapper })
      expect(screen.getByText('Scan Now')).toBeInTheDocument()
    })

    it('renders for an active lambda_function resource', () => {
      const lambdaResource = { ...mockResource, resource_type: 'lambda_function' }
      render(<DetailPanel resource={lambdaResource} onClose={jest.fn()} />, { wrapper })
      expect(screen.getByText('Scan Now')).toBeInTheDocument()
    })

    it('does not render for a non-scannable resource type', () => {
      const s3Resource = { ...mockResource, resource_type: 's3_bucket' }
      render(<DetailPanel resource={s3Resource} onClose={jest.fn()} />, { wrapper })
      expect(screen.queryByText('Scan Now')).not.toBeInTheDocument()
    })

    it('does not render for a deleted resource', () => {
      const deletedResource = { ...mockResource, status: 'deleted' as const }
      render(<DetailPanel resource={deletedResource} onClose={jest.fn()} />, { wrapper })
      expect(screen.queryByText('Scan Now')).not.toBeInTheDocument()
    })

    it('triggers a scan and shows a success banner with the job id', async () => {
      mockTriggerScan.mockResolvedValue({ data: { job_id: 'job-abc-123', status: 'queued', resource_key: mockResource.key } })
      render(<DetailPanel resource={mockResource} onClose={jest.fn()} />, { wrapper })

      fireEvent.click(screen.getByText('Scan Now'))

      await waitFor(() => expect(screen.getByText(/Side-scan queued — job job-abc-123/)).toBeInTheDocument())
      expect(mockTriggerScan).toHaveBeenCalledWith(mockResource.key)
    })

    it('shows an error banner when the trigger call fails', async () => {
      mockTriggerScan.mockRejectedValue(new Error('network error'))
      render(<DetailPanel resource={mockResource} onClose={jest.fn()} />, { wrapper })

      fireEvent.click(screen.getByText('Scan Now'))

      await waitFor(() => expect(screen.getByText('Failed to trigger scan.')).toBeInTheDocument())
    })
  })
})
