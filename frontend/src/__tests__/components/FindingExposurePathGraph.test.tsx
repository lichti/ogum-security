import '@testing-library/jest-dom'
import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { FindingExposurePathGraph } from '@/components/findings/FindingExposurePathGraph'
import { findingsApi } from '@/lib/api'
import type { FindingDetail } from '@/lib/types'

jest.mock('@/lib/api', () => ({
  findingsApi: { exposurePath: jest.fn() },
}))

jest.mock('@/components/graph/AttackPathCanvas', () => ({
  AttackPathCanvas: ({ emptyLabel, loading, miniGraph }: { emptyLabel?: string; loading?: boolean; miniGraph?: { nodes: unknown[] } }) => (
    <div data-testid="mock-canvas">
      {loading ? 'loading' : miniGraph && miniGraph.nodes.length > 0 ? 'graph' : emptyLabel}
    </div>
  ),
}))

const mockExposurePath = findingsApi.exposurePath as jest.Mock

const mockFinding: FindingDetail = {
  _key: 'find-1',
  finding_id: 'find-1',
  tenant_id: 'test',
  check_id: 'check_s3_public',
  title: 'S3 Bucket Publicly Accessible',
  description: '',
  resource_id: 'my-bucket',
  resource_arn: null,
  resource_type: 's3_bucket',
  severity: 'HIGH',
  status: 'FAIL',
  provider: 'aws',
  region: 'us-east-1',
  account_id: '123456789012',
  framework_mapping: [],
  remediation: null,
  remediation_code: null,
  source: 'cspm',
  detected_at: '2026-01-01T00:00:00Z',
  updated_at: '2026-01-01T00:00:00Z',
  mute_reason: null,
  scan_job_id: null,
  first_seen_scan_id: null,
  last_seen_scan_id: null,
  scan_count: 1,
  resource: null,
  attack_paths: [],
  cli_command: null,
}

function renderWithClient(ui: React.ReactElement) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
  return render(ui, { wrapper: Wrapper })
}

beforeEach(() => jest.clearAllMocks())

describe('FindingExposurePathGraph', () => {
  it('shows empty label when no exposure edges are found', async () => {
    mockExposurePath.mockResolvedValue({
      data: { data: { resource_key: 'bucket-key', nodes: [], edges: [], grouped_counts: {} } },
    })
    renderWithClient(<FindingExposurePathGraph finding={mockFinding} />)
    await waitFor(() => {
      expect(screen.getByTestId('mock-canvas')).toHaveTextContent('No exposure path detected for this finding')
    })
  })

  it('renders the graph when exposure edges are found', async () => {
    mockExposurePath.mockResolvedValue({
      data: {
        data: {
          resource_key: 'bucket-key',
          nodes: [{ id: 'resources/vpc-1', resource_type: 'vpc', name: 'main-vpc', hop: 1 }],
          edges: [{ source: 'resources/bucket-key', target: 'resources/vpc-1', edge_type: 'BELONGS_TO' }],
          grouped_counts: { vpc: 1 },
        },
      },
    })
    renderWithClient(<FindingExposurePathGraph finding={mockFinding} />)
    await waitFor(() => {
      expect(screen.getByTestId('mock-canvas')).toHaveTextContent('graph')
    })
  })
})
