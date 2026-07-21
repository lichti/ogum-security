import '@testing-library/jest-dom'
import { render, screen, fireEvent } from '@testing-library/react'
import { Top10Findings } from '@/components/compliance/Top10Findings'
import type { ComplianceTopCheck } from '@/lib/types'

const items: ComplianceTopCheck[] = [
  { check_id: 's3_check', title: 'S3 bucket versioning', severity: 'HIGH', count: 7 },
]

const onSelect = jest.fn()
beforeEach(() => jest.clearAllMocks())

describe('Top10Findings', () => {
  it('shows an empty message (not a blank column) when there are no items', () => {
    render(<Top10Findings items={[]} scopeLabel="Global" onSelect={onSelect} />)
    expect(screen.getByText('No failing findings.')).toBeInTheDocument()
  })

  it('renders one row per check with severity, title, check_id and the count suffix', () => {
    render(<Top10Findings items={items} scopeLabel="Global" onSelect={onSelect} />)
    expect(screen.getByText('S3 bucket versioning')).toBeInTheDocument()
    expect(screen.getByText('s3_check')).toBeInTheDocument()
    expect(screen.getByText('7×')).toBeInTheDocument()
  })

  it('shows the scope label as its own column header', () => {
    render(<Top10Findings items={items} scopeLabel="CIS AWS Foundations Benchmark" onSelect={onSelect} />)
    expect(screen.getByText('CIS AWS Foundations Benchmark')).toBeInTheDocument()
  })

  it('calls onSelect with the clicked check when a row is clicked', () => {
    render(<Top10Findings items={items} scopeLabel="Global" onSelect={onSelect} />)
    fireEvent.click(screen.getByText('S3 bucket versioning'))
    expect(onSelect).toHaveBeenCalledWith(items[0])
  })
})
