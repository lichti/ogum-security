import '@testing-library/jest-dom'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { ComplianceDrilldownPanel } from '@/components/compliance/ComplianceDrilldownPanel'
import { findingsApi } from '@/lib/api'
import type { Finding } from '@/lib/types'

jest.mock('@/lib/api', () => ({
  findingsApi: { list: jest.fn() },
}))

const mockList = findingsApi.list as jest.Mock

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
    framework_mapping: ['CIS-7.0'],
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

beforeEach(() => jest.clearAllMocks())

describe('ComplianceDrilldownPanel', () => {
  it('mode "check": queries by check_id and shows the affected asset per row, not the finding title', async () => {
    mockList.mockResolvedValue({ data: { data: { items: [finding()], next_cursor: null, count: 1 } } })
    render(
      <ComplianceDrilldownPanel
        title="S3 Bucket Publicly Accessible"
        subtitle="check_s3_public"
        mode={{ kind: 'check', checkId: 'check_s3_public' }}
        framework="CIS-7.0"
        onClose={jest.fn()}
      />,
    )

    await waitFor(() =>
      expect(mockList).toHaveBeenCalledWith(
        expect.objectContaining({
          status: ['FAIL'],
          check_id: 'check_s3_public',
          resource_id: undefined,
          framework: ['CIS-7.0'],
        }),
      ),
    )
    expect(await screen.findByText('my-bucket')).toBeInTheDocument()
    expect(screen.getByText(/s3_bucket/)).toBeInTheDocument()
  })

  it('mode "resource": queries by resource_id and shows the finding title per row, not the resource id', async () => {
    mockList.mockResolvedValue({ data: { data: { items: [finding()], next_cursor: null, count: 1 } } })
    render(
      <ComplianceDrilldownPanel
        title="my-bucket"
        subtitle="s3_bucket"
        mode={{ kind: 'resource', resourceId: 'my-bucket' }}
        onClose={jest.fn()}
      />,
    )

    await waitFor(() =>
      expect(mockList).toHaveBeenCalledWith(
        expect.objectContaining({ status: ['FAIL'], resource_id: 'my-bucket', check_id: undefined, framework: undefined }),
      ),
    )
    expect(await screen.findByText('S3 Bucket Publicly Accessible')).toBeInTheDocument()
    expect(screen.getByText('check_s3_public')).toBeInTheDocument()
  })

  it('links each row to the finding detail deep link', async () => {
    mockList.mockResolvedValue({ data: { data: { items: [finding()], next_cursor: null, count: 1 } } })
    render(
      <ComplianceDrilldownPanel
        title="my-bucket"
        mode={{ kind: 'resource', resourceId: 'my-bucket' }}
        onClose={jest.fn()}
      />,
    )
    const link = (await screen.findByText('S3 Bucket Publicly Accessible')).closest('a')
    expect(link).toHaveAttribute('href', '/findings?finding=f-001')
  })

  it('shows an empty state when there are no matching findings', async () => {
    mockList.mockResolvedValue({ data: { data: { items: [], next_cursor: null, count: 0 } } })
    render(
      <ComplianceDrilldownPanel
        title="my-bucket"
        mode={{ kind: 'resource', resourceId: 'my-bucket' }}
        onClose={jest.fn()}
      />,
    )
    expect(await screen.findByText('No matching findings.')).toBeInTheDocument()
  })

  it('shows Load more when a next cursor exists, and appends the next page on click', async () => {
    mockList
      .mockResolvedValueOnce({
        data: { data: { items: [finding({ _key: 'f-001' })], next_cursor: 'cursor-1', count: 1 } },
      })
      .mockResolvedValueOnce({
        data: {
          data: {
            items: [finding({ _key: 'f-002', title: 'Second finding' })],
            next_cursor: null,
            count: 1,
          },
        },
      })

    render(
      <ComplianceDrilldownPanel
        title="my-bucket"
        mode={{ kind: 'resource', resourceId: 'my-bucket' }}
        onClose={jest.fn()}
      />,
    )
    await screen.findByText('S3 Bucket Publicly Accessible')

    fireEvent.click(screen.getByRole('button', { name: /Load more/i }))

    expect(await screen.findByText('Second finding')).toBeInTheDocument()
    expect(screen.getByText('S3 Bucket Publicly Accessible')).toBeInTheDocument() // first page still there
    await waitFor(() => expect(mockList).toHaveBeenLastCalledWith(expect.objectContaining({ cursor: 'cursor-1' })))
    expect(screen.queryByRole('button', { name: /Load more/i })).not.toBeInTheDocument()
  })

  it('closes on Escape, backdrop click, and the close button', async () => {
    mockList.mockResolvedValue({ data: { data: { items: [], next_cursor: null, count: 0 } } })
    const onClose = jest.fn()
    render(
      <ComplianceDrilldownPanel
        title="my-bucket"
        mode={{ kind: 'resource', resourceId: 'my-bucket' }}
        onClose={onClose}
      />,
    )
    await screen.findByText('No matching findings.')

    fireEvent.keyDown(window, { key: 'Escape' })
    expect(onClose).toHaveBeenCalledTimes(1)

    fireEvent.click(screen.getByLabelText('Close panel'))
    expect(onClose).toHaveBeenCalledTimes(2)

    fireEvent.click(document.querySelector('[aria-hidden="true"]') as HTMLElement)
    expect(onClose).toHaveBeenCalledTimes(3)
  })
})
