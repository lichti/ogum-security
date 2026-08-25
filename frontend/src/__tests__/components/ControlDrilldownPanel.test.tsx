import '@testing-library/jest-dom'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ControlDrilldownPanel } from '@/components/compliance/ControlDrilldownPanel'
import { complianceApi, findingsApi } from '@/lib/api'
import type { ComplianceControlAsset, Finding } from '@/lib/types'

jest.mock('@/lib/api', () => ({
  findingsApi: { list: jest.fn() },
  complianceApi: { controlAssets: jest.fn() },
}))

const mockList = findingsApi.list as jest.Mock
const mockControlAssets = complianceApi.controlAssets as jest.Mock

function finding(overrides: Partial<Finding> = {}): Finding {
  return {
    _key: 'f-001',
    finding_id: 'f-001',
    tenant_id: 'tenant-test',
    check_id: 'check_s3_public',
    title: 'S3 Bucket Publicly Accessible',
    description: 'desc',
    resource_id: 'my-bucket',
    resource_arn: 'arn:aws:s3:::my-bucket',
    resource_type: 's3_bucket',
    severity: 'CRITICAL',
    status: 'FAIL',
    provider: 'aws',
    region: 'us-east-1',
    account_id: '123456789012',
    framework_mapping: ['CIS-7.0/1.1'],
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
    ...overrides,
  }
}

function asset(overrides: Partial<ComplianceControlAsset> = {}): ComplianceControlAsset {
  return {
    resource_id: 'my-bucket',
    resource_type: 's3_bucket',
    provider: 'aws',
    region: 'us-east-1',
    account_id: '123456789012',
    pass_count: 0,
    fail_count: 1,
    ...overrides,
  }
}

beforeEach(() => {
  jest.clearAllMocks()
  mockList.mockResolvedValue({ data: { data: { items: [], next_cursor: null } } })
  mockControlAssets.mockResolvedValue({ data: { data: [] } })
})

describe('ControlDrilldownPanel', () => {
  it('opens on the Findings tab by default, scoped by framework + control_id', async () => {
    render(
      <ControlDrilldownPanel frameworkId="CIS-7.0" controlId="1.1" title="Root MFA enabled" onClose={jest.fn()} />,
    )

    expect(screen.getByText('Root MFA enabled')).toBeInTheDocument()
    expect(screen.getByText('1.1')).toBeInTheDocument()
    await waitFor(() =>
      expect(mockList).toHaveBeenCalledWith(
        expect.objectContaining({ framework: ['CIS-7.0/1.1'], status: undefined }),
      ),
    )
  })

  it('shows the associated asset (resource_id + region) under each finding row', async () => {
    mockList.mockResolvedValue({ data: { data: { items: [finding()], next_cursor: null } } })
    render(<ControlDrilldownPanel frameworkId="CIS-7.0" controlId="1.1" title="Root MFA" onClose={jest.fn()} />)

    expect(await screen.findByText('S3 Bucket Publicly Accessible')).toBeInTheDocument()
    expect(screen.getByText(/my-bucket/)).toBeInTheDocument()
    expect(screen.getByText(/us-east-1/)).toBeInTheDocument()
  })

  it('the All/Pass/Fail filter refetches with the right status list', async () => {
    const user = userEvent.setup()
    render(<ControlDrilldownPanel frameworkId="CIS-7.0" controlId="1.1" title="Root MFA" onClose={jest.fn()} />)
    await waitFor(() => expect(mockList).toHaveBeenCalledWith(expect.objectContaining({ status: undefined })))

    await user.click(screen.getByRole('button', { name: 'Pass' }))
    await waitFor(() =>
      expect(mockList).toHaveBeenLastCalledWith(expect.objectContaining({ status: ['PASS', 'ACCEPTED'] })),
    )

    await user.click(screen.getByRole('button', { name: 'Fail' }))
    await waitFor(() => expect(mockList).toHaveBeenLastCalledWith(expect.objectContaining({ status: ['FAIL'] })))

    await user.click(screen.getByRole('button', { name: 'All' }))
    await waitFor(() => expect(mockList).toHaveBeenLastCalledWith(expect.objectContaining({ status: undefined })))
  })

  it('shows an empty state when there are no matching findings', async () => {
    render(<ControlDrilldownPanel frameworkId="CIS-7.0" controlId="1.1" title="Root MFA" onClose={jest.fn()} />)
    expect(await screen.findByText('No matching findings.')).toBeInTheDocument()
  })

  it('switches to the Assets tab and shows each asset with its Pass/Fail tally', async () => {
    const user = userEvent.setup()
    mockControlAssets.mockResolvedValue({
      data: { data: [asset({ resource_id: 'bucket-a', pass_count: 3, fail_count: 1 })] },
    })
    render(<ControlDrilldownPanel frameworkId="CIS-7.0" controlId="1.1" title="Root MFA" onClose={jest.fn()} />)

    await user.click(screen.getByRole('tab', { name: 'assets' }))

    expect(mockControlAssets).toHaveBeenCalledWith('CIS-7.0', '1.1')
    expect(await screen.findByText('bucket-a')).toBeInTheDocument()
    expect(screen.getByText('3 pass')).toBeInTheDocument()
    expect(screen.getByText('1 fail')).toBeInTheDocument()
  })

  it('shows an empty state on the Assets tab when there are no matching assets', async () => {
    const user = userEvent.setup()
    render(<ControlDrilldownPanel frameworkId="CIS-7.0" controlId="1.1" title="Root MFA" onClose={jest.fn()} />)
    await user.click(screen.getByRole('tab', { name: 'assets' }))
    expect(await screen.findByText('No matching assets.')).toBeInTheDocument()
  })

  it('clicking an asset expands an inline sub-table of its findings, with its own status filter', async () => {
    const user = userEvent.setup()
    mockControlAssets.mockResolvedValue({ data: { data: [asset({ resource_id: 'bucket-a' })] } })
    mockList.mockResolvedValue({ data: { data: { items: [finding({ resource_id: 'bucket-a' })], next_cursor: null } } })

    render(<ControlDrilldownPanel frameworkId="CIS-7.0" controlId="1.1" title="Root MFA" onClose={jest.fn()} />)
    await user.click(screen.getByRole('tab', { name: 'assets' }))
    await screen.findByText('bucket-a')

    // Only the Findings tab's own (unscoped) fetch has happened so far — not one
    // scoped to this asset, which only fires once its row is expanded.
    expect(mockList).not.toHaveBeenCalledWith(expect.objectContaining({ resource_id: 'bucket-a' }))

    await user.click(screen.getByText('bucket-a'))

    await waitFor(() =>
      expect(mockList).toHaveBeenCalledWith(
        expect.objectContaining({ framework: ['CIS-7.0/1.1'], resource_id: 'bucket-a', status: undefined }),
      ),
    )
    expect(await screen.findByText('S3 Bucket Publicly Accessible')).toBeInTheDocument()

    // The sub-table has its own All/Pass/Fail filter, independent of the Findings tab's.
    await user.click(screen.getByRole('button', { name: 'Fail' }))
    await waitFor(() =>
      expect(mockList).toHaveBeenLastCalledWith(expect.objectContaining({ resource_id: 'bucket-a', status: ['FAIL'] })),
    )
  })

  it('closes on Escape, backdrop click, and the close button', async () => {
    const onClose = jest.fn()
    render(<ControlDrilldownPanel frameworkId="CIS-7.0" controlId="1.1" title="Root MFA" onClose={onClose} />)
    await screen.findByText('No matching findings.')

    fireEvent.keyDown(window, { key: 'Escape' })
    expect(onClose).toHaveBeenCalledTimes(1)

    fireEvent.click(screen.getByLabelText('Close panel'))
    expect(onClose).toHaveBeenCalledTimes(2)

    fireEvent.click(document.querySelector('[aria-hidden="true"]') as HTMLElement)
    expect(onClose).toHaveBeenCalledTimes(3)
  })
})
