import '@testing-library/jest-dom'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'

jest.mock('next/navigation', () => ({
  useRouter: jest.fn(),
  usePathname: jest.fn(),
  useSearchParams: jest.fn(),
}))

jest.mock('@/lib/api', () => ({
  sideScanApi: {
    triggerScan: jest.fn(),
  },
  inventoryApi: {
    summary: jest.fn(),
    blastRadius: jest.fn(),
  },
}))

jest.mock('@/components/graph/AttackPathCanvas', () => ({
  AttackPathCanvas: () => <div data-testid="mock-canvas" />,
}))

import { useRouter, usePathname, useSearchParams } from 'next/navigation'
import { DetailPanel } from '@/components/inventory/DetailPanel'
import { sideScanApi, inventoryApi } from '@/lib/api'
import type { ResourceDetail } from '@/lib/types'

const mockTriggerScan = sideScanApi.triggerScan as jest.Mock
const mockSummary = inventoryApi.summary as jest.Mock
const mockBlastRadius = inventoryApi.blastRadius as jest.Mock
const mockUseRouter = useRouter as jest.Mock
const mockUsePathname = usePathname as jest.Mock
const mockUseSearchParams = useSearchParams as jest.Mock
const mockReplace = jest.fn()

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
    mockReplace.mockReset()
    mockSummary.mockReset().mockResolvedValue({
      data: { data: { narrative: 'A summary.', deep_links: [], finding_counts: {}, attack_path_count: 0 } },
    })
    mockBlastRadius.mockReset().mockResolvedValue({
      data: { data: { nodes: [], edges: [], grouped_counts: {} } },
    })
    mockUseRouter.mockReturnValue({ replace: mockReplace })
    mockUsePathname.mockReturnValue('/inventory')
    mockUseSearchParams.mockReturnValue(new URLSearchParams())
  })

  it('renders nothing when resource is null', () => {
    const { container } = render(<DetailPanel resource={null} onClose={jest.fn()} />, { wrapper })
    expect(container).toBeEmptyDOMElement()
  })

  it('renders the panel when resource is provided', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />, { wrapper })
    expect(screen.getByTestId('detail-panel')).toBeInTheDocument()
  })

  it('renders the breadcrumb with account, region, and name', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />, { wrapper })
    expect(screen.getByText('111111111111', { exact: false })).toBeInTheDocument()
    expect(screen.getAllByText('web-server').length).toBeGreaterThan(0)
  })

  it('renders all 7 main tabs', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />, { wrapper })
    for (const label of ['Info', 'Risk', 'Network', 'IAM', 'Configurations', 'Software Inventory', 'Compliance']) {
      expect(screen.getByRole('tab', { name: label })).toBeInTheDocument()
    }
  })

  it('defaults to the Info tab with the Overview sub-tab active', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />, { wrapper })
    expect(screen.getByRole('tab', { name: 'Info' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tab', { name: 'Overview' })).toHaveAttribute('aria-selected', 'true')
  })

  it('switches tab and updates the URL on click', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />, { wrapper })
    fireEvent.click(screen.getByRole('tab', { name: 'Risk' }))
    expect(screen.getByRole('tab', { name: 'Risk' })).toHaveAttribute('aria-selected', 'true')
    expect(mockReplace).toHaveBeenCalledWith(expect.stringContaining('tab=risk'), { scroll: false })
  })

  it('navigates to Risk/Blast Radius via ArrowRight from Info', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />, { wrapper })
    fireEvent.keyDown(screen.getByRole('tablist', { name: 'Resource detail tabs' }), { key: 'ArrowRight' })
    expect(screen.getByRole('tab', { name: 'Risk' })).toHaveAttribute('aria-selected', 'true')
  })

  it('shows an empty-state message for tabs without content yet', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />, { wrapper })
    fireEvent.click(screen.getByRole('tab', { name: 'IAM' }))
    expect(screen.getByText(/available yet/)).toBeInTheDocument()
  })

  it('reads the initial tab from the URL search params', () => {
    mockUseSearchParams.mockReturnValue(new URLSearchParams('tab=risk&subtab=blast_radius'))
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />, { wrapper })
    expect(screen.getByRole('tab', { name: 'Risk' })).toHaveAttribute('aria-selected', 'true')
    expect(screen.getByRole('tab', { name: 'Blast Radius' })).toHaveAttribute('aria-selected', 'true')
  })

  it('renders tags', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />, { wrapper })
    expect(screen.getByText('env: prod')).toBeInTheDocument()
    expect(screen.getByText('team: platform')).toBeInTheDocument()
  })

  it('renders Relationships count and grouped rows', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />, { wrapper })
    expect(screen.getByText('Relationships (1)')).toBeInTheDocument()
    expect(screen.getByText('1 BELONGS TO')).toBeInTheDocument()
    expect(screen.getByText('aws_vpc_vpc-001')).toBeInTheDocument()
  })

  it('renders the narrative summary', async () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />, { wrapper })
    await waitFor(() => expect(screen.getByText('A summary.')).toBeInTheDocument())
  })

  it('calls onClose when close button is clicked', () => {
    const onClose = jest.fn()
    render(<DetailPanel resource={mockResource} onClose={onClose} />, { wrapper })
    fireEvent.click(screen.getByLabelText('Close panel'))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('renders "no relationships" message when there are no edges', () => {
    const noEdgesResource = { ...mockResource, edges: [] }
    render(<DetailPanel resource={noEdgesResource} onClose={jest.fn()} />, { wrapper })
    expect(screen.getByText('No relationships found.')).toBeInTheDocument()
    expect(screen.getByText('Relationships (0)')).toBeInTheDocument()
  })

  it('renders console link for ec2 instance', () => {
    render(<DetailPanel resource={mockResource} onClose={jest.fn()} />, { wrapper })
    const link = screen.getByText('Open in Console').closest('a')
    expect(link).toHaveAttribute('href', expect.stringContaining('console.aws.amazon.com'))
    expect(link).toHaveAttribute('target', '_blank')
  })

  describe('kebab menu', () => {
    it('opens and shows Copy ARN / Copy Resource ID actions', () => {
      render(<DetailPanel resource={mockResource} onClose={jest.fn()} />, { wrapper })
      fireEvent.click(screen.getByLabelText('More actions'))
      expect(screen.getByText('Copy ARN')).toBeInTheDocument()
      expect(screen.getByText('Copy Resource ID')).toBeInTheDocument()
    })
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
