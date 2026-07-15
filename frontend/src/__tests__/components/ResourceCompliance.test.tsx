import '@testing-library/jest-dom'
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { ResourceCompliance } from '@/components/inventory/ResourceCompliance'
import { inventoryApi } from '@/lib/api'
import type { ResourceComplianceResponse, ResourceDetail } from '@/lib/types'

jest.mock('@/lib/api', () => ({
  inventoryApi: { compliance: jest.fn() },
}))

jest.mock('next/navigation', () => ({
  useRouter: () => ({ push: jest.fn() }),
}))

const mockCompliance = inventoryApi.compliance as jest.Mock

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
  is_public: false,
  tags: {},
  last_scanned_at: null,
  updated_at: null,
  raw_metadata: {},
  edges: [],
}

function renderWithClient(ui: React.ReactElement) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
  return render(ui, { wrapper: Wrapper })
}

function mockData(overrides: Partial<ResourceComplianceResponse> = {}): ResourceComplianceResponse {
  return {
    resource_key: mockResource.key,
    available_frameworks: [],
    selected_framework: null,
    controls: [],
    ...overrides,
  }
}

beforeEach(() => jest.clearAllMocks())

describe('ResourceCompliance', () => {
  it('shows empty state when no frameworks are available', async () => {
    mockCompliance.mockResolvedValue({ data: { data: mockData() } })
    renderWithClient(<ResourceCompliance resource={mockResource} onFrameworkChange={jest.fn()} />)
    await waitFor(() => {
      expect(screen.getByText('No compliance data found for this resource.')).toBeInTheDocument()
    })
  })

  it('renders the framework selector and control rows', async () => {
    mockCompliance.mockResolvedValue({
      data: {
        data: mockData({
          available_frameworks: [{ id: 'CIS-2.0', label: 'CIS AWS Foundations Benchmark 2.0' }],
          selected_framework: 'CIS-2.0',
          controls: [
            {
              control_id: '1.1',
              status: 'FAIL',
              title: 'EC2 instance is publicly reachable',
              category: 'Section 1',
              severity: 'HIGH',
              finding_key: 'find-1',
            },
          ],
        }),
      },
    })
    renderWithClient(<ResourceCompliance resource={mockResource} onFrameworkChange={jest.fn()} />)
    await waitFor(() => {
      expect(screen.getByText('CIS AWS Foundations Benchmark 2.0')).toBeInTheDocument()
      expect(screen.getByText('EC2 instance is publicly reachable')).toBeInTheDocument()
      expect(screen.getByText('FAIL')).toBeInTheDocument()
      expect(screen.getByText('View finding →')).toBeInTheDocument()
    })
  })
})
