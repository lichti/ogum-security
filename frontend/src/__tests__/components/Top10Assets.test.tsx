import '@testing-library/jest-dom'
import { render, screen, fireEvent } from '@testing-library/react'
import { Top10Assets } from '@/components/compliance/Top10Assets'
import type { ComplianceTopAsset } from '@/lib/types'

const items: ComplianceTopAsset[] = [
  {
    resource_id: 'res-a',
    resource_type: 's3_bucket',
    provider: 'aws',
    region: 'us-east-1',
    account_id: '111111111111',
    count: 5,
  },
]

const onSelect = jest.fn()
beforeEach(() => jest.clearAllMocks())

describe('Top10Assets', () => {
  it('shows an empty message (not a blank column) when there are no items', () => {
    render(<Top10Assets items={[]} scopeLabel="Global" onSelect={onSelect} />)
    expect(screen.getByText('No failing findings.')).toBeInTheDocument()
    expect(screen.getByText('Global')).toBeInTheDocument()
  })

  it('renders one row per asset with provider, type, region, account and count', () => {
    render(<Top10Assets items={items} scopeLabel="Framework" onSelect={onSelect} />)
    expect(screen.getByText('res-a')).toBeInTheDocument()
    expect(screen.getByText('AWS')).toBeInTheDocument()
    expect(screen.getByText(/s3_bucket/)).toBeInTheDocument()
    expect(screen.getByText(/us-east-1/)).toBeInTheDocument()
    expect(screen.getByText(/111111111111/)).toBeInTheDocument()
    expect(screen.getByText('5 findings')).toBeInTheDocument()
  })

  it('omits the region segment when the resource has none', () => {
    render(<Top10Assets items={[{ ...items[0], region: null }]} scopeLabel="Framework" onSelect={onSelect} />)
    expect(screen.getByText('s3_bucket · 111111111111')).toBeInTheDocument()
  })

  it('shows the scope label as its own column header', () => {
    render(<Top10Assets items={items} scopeLabel="GDPR" onSelect={onSelect} />)
    expect(screen.getByText('GDPR')).toBeInTheDocument()
  })

  it('calls onSelect with the clicked asset when a row is clicked', () => {
    render(<Top10Assets items={items} scopeLabel="Global" onSelect={onSelect} />)
    fireEvent.click(screen.getByText('res-a'))
    expect(onSelect).toHaveBeenCalledWith(items[0])
  })
})
