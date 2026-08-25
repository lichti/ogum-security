import '@testing-library/jest-dom'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { FindingDetailPanel } from '@/components/findings/FindingDetailPanel'

const mockFinding = {
  _key: 'f-001',
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
  first_seen_scan_id: null,
  last_seen_scan_id: null,
  scan_count: 3,
  resource: null,
  attack_paths: [],
  cli_command: 'aws s3api put-public-access-block --bucket my-bucket',
}

// Mock findingsApi + settingsApi
jest.mock('@/lib/api', () => ({
  findingsApi: {
    get: jest.fn(() => Promise.resolve({ data: { data: mockFinding } })),
    mute: jest.fn(() =>
      Promise.resolve({ data: { data: { ...mockFinding, status: 'MUTED', mute_reason: 'test reason' } } }),
    ),
    exposurePath: jest.fn(() =>
      Promise.resolve({ data: { data: { resource_key: 'my-bucket', nodes: [], edges: [], grouped_counts: {} } } }),
    ),
  },
  settingsApi: {
    getSla: jest.fn(() =>
      Promise.resolve({ data: { data: { critical_days: 7, high_days: 30, medium_days: 90, low_days: 180 } } }),
    ),
  },
}))

jest.mock('@/components/graph/AttackPathCanvas', () => ({
  AttackPathCanvas: () => <div data-testid="mock-canvas" />,
}))

function renderWithClient(ui: React.ReactElement) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
  return render(ui, { wrapper: Wrapper })
}

describe('FindingDetailPanel', () => {
  it('renders nothing when findingKey is null', () => {
    const { container } = renderWithClient(
      <FindingDetailPanel findingKey={null} onClose={jest.fn()} />,
    )
    expect(container).toBeEmptyDOMElement()
  })

  it('fetches and displays finding detail when key is provided', async () => {
    renderWithClient(<FindingDetailPanel findingKey="f-001" onClose={jest.fn()} />)
    await waitFor(() => {
      expect(screen.getByText('S3 Bucket Publicly Accessible')).toBeInTheDocument()
    })
    expect(screen.getByText('check_s3_public')).toBeInTheDocument()
    expect(screen.getByText('CRITICAL')).toBeInTheDocument()
  })

  it('closes panel when Escape key is pressed', async () => {
    const onClose = jest.fn()
    renderWithClient(<FindingDetailPanel findingKey="f-001" onClose={onClose} />)
    await waitFor(() => screen.getByText('S3 Bucket Publicly Accessible'))
    fireEvent.keyDown(window, { key: 'Escape' })
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('closes panel when backdrop is clicked', async () => {
    const onClose = jest.fn()
    renderWithClient(<FindingDetailPanel findingKey="f-001" onClose={onClose} />)
    await waitFor(() => screen.getByText('S3 Bucket Publicly Accessible'))
    // Click the overlay backdrop (first fixed div)
    const backdrop = document.querySelector('[aria-hidden="true"]') as HTMLElement
    fireEvent.click(backdrop)
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('calls onClose when X button is clicked', async () => {
    const onClose = jest.fn()
    renderWithClient(<FindingDetailPanel findingKey="f-001" onClose={onClose} />)
    await waitFor(() => screen.getByText('S3 Bucket Publicly Accessible'))
    fireEvent.click(screen.getByLabelText('Close panel'))
    expect(onClose).toHaveBeenCalledTimes(1)
  })

  it('displays CLI command when available', async () => {
    renderWithClient(<FindingDetailPanel findingKey="f-001" onClose={jest.fn()} />)
    await waitFor(() => screen.getByText('S3 Bucket Publicly Accessible'))
    expect(
      screen.getByText('aws s3api put-public-access-block --bucket my-bucket'),
    ).toBeInTheDocument()
  })

  it('shows Mute Finding button for FAIL findings', async () => {
    renderWithClient(<FindingDetailPanel findingKey="f-001" onClose={jest.fn()} />)
    await waitFor(() => screen.getByText('Mute Finding'))
    expect(screen.getByText('Mute Finding')).toBeInTheDocument()
  })

  it('shows mute modal when Mute Finding is clicked', async () => {
    renderWithClient(<FindingDetailPanel findingKey="f-001" onClose={jest.fn()} />)
    await waitFor(() => screen.getByText('Mute Finding'))
    fireEvent.click(screen.getByText('Mute Finding'))
    expect(screen.getByTestId('mute-modal')).toBeInTheDocument()
  })

  it('shows timeline with first detected date and scan count', async () => {
    renderWithClient(<FindingDetailPanel findingKey="f-001" onClose={jest.fn()} />)
    await waitFor(() => screen.getByText('S3 Bucket Publicly Accessible'))
    expect(screen.getByText('3 scans')).toBeInTheDocument()
  })
})
