import '@testing-library/jest-dom'
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { SoftwareInventoryPanel } from '@/components/inventory/SoftwareInventoryPanel'
import { inventoryApi } from '@/lib/api'
import type { ResourceDetail, SoftwareInventoryResponse } from '@/lib/types'

jest.mock('@/lib/api', () => ({
  inventoryApi: { software: jest.fn() },
}))

const mockSoftware = inventoryApi.software as jest.Mock

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

function mockData(overrides: Partial<SoftwareInventoryResponse> = {}): SoftwareInventoryResponse {
  return {
    resource_key: mockResource.key,
    sbom_generated_at: '2026-07-01T00:00:00Z',
    installed_packages: [],
    licenses: [],
    applications_available: false,
    running_services_available: false,
    ...overrides,
  }
}

beforeEach(() => jest.clearAllMocks())

describe('SoftwareInventoryPanel', () => {
  it('shows not-available state for applications sub-tab', async () => {
    mockSoftware.mockResolvedValue({ data: { data: mockData() } })
    renderWithClient(<SoftwareInventoryPanel resource={mockResource} subtabKey="applications" />)
    await waitFor(() => {
      expect(screen.getByText("This section isn't available yet.")).toBeInTheDocument()
    })
  })

  it('shows not-available state for running_services sub-tab', async () => {
    mockSoftware.mockResolvedValue({ data: { data: mockData() } })
    renderWithClient(<SoftwareInventoryPanel resource={mockResource} subtabKey="running_services" />)
    await waitFor(() => {
      expect(screen.getByText("This section isn't available yet.")).toBeInTheDocument()
    })
  })

  it('shows empty state when no SBOM has been generated', async () => {
    mockSoftware.mockResolvedValue({ data: { data: mockData({ sbom_generated_at: null }) } })
    renderWithClient(<SoftwareInventoryPanel resource={mockResource} subtabKey="installed_packages" />)
    await waitFor(() => {
      expect(screen.getByText('No SBOM has been generated for this resource yet.')).toBeInTheDocument()
    })
  })

  it('renders installed packages with CVE badges', async () => {
    mockSoftware.mockResolvedValue({
      data: {
        data: mockData({
          installed_packages: [
            { name: 'requests', version: '2.31.0', cve_ids: ['CVE-2024-1234'], filesystem_path: '/usr/lib/requests' },
          ],
        }),
      },
    })
    renderWithClient(<SoftwareInventoryPanel resource={mockResource} subtabKey="installed_packages" />)
    await waitFor(() => {
      expect(screen.getByText('requests')).toBeInTheDocument()
      expect(screen.getByText('CVE-2024-1234')).toBeInTheDocument()
      expect(screen.getByText('/usr/lib/requests')).toBeInTheDocument()
    })
  })

  it('renders licenses with category and deprecated flag', async () => {
    mockSoftware.mockResolvedValue({
      data: {
        data: mockData({
          licenses: [{ license_id: 'GPL-2.0', category: 'copyleft', deprecated: true, package_count: 2 }],
        }),
      },
    })
    renderWithClient(<SoftwareInventoryPanel resource={mockResource} subtabKey="licenses" />)
    await waitFor(() => {
      expect(screen.getByText('GPL-2.0')).toBeInTheDocument()
      expect(screen.getByText('Copyleft')).toBeInTheDocument()
      // "Deprecated" appears both as the column header and the badge — assert the badge specifically.
      expect(screen.getAllByText('Deprecated')).toHaveLength(2)
    })
  })
})
