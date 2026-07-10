import '@testing-library/jest-dom'
import { render, screen } from '@testing-library/react'
import { TopFailingControls } from '@/components/compliance/TopFailingControls'
import type { ComplianceSummary } from '@/lib/types'

const items: ComplianceSummary['top_failing'] = [
  { check_id: 'check_a', title: 'Check A', severity: 'CRITICAL', count: 12 },
  { check_id: 'check_b', title: 'Check B', severity: 'HIGH', count: 7 },
]

describe('TopFailingControls', () => {
  it('renders each item with its title, check id, and count', () => {
    render(<TopFailingControls items={items} scopeLabel={null} />)
    expect(screen.getByText('Check A')).toBeInTheDocument()
    expect(screen.getByText('check_a')).toBeInTheDocument()
    expect(screen.getByText('12×')).toBeInTheDocument()
  })

  it('shows the scope label when one is provided', () => {
    render(<TopFailingControls items={items} scopeLabel="CIS AWS Foundations Benchmark" />)
    expect(screen.getByText('— CIS AWS Foundations Benchmark', { exact: false })).toBeInTheDocument()
  })

  it('renders nothing when there are no failing controls', () => {
    const { container } = render(<TopFailingControls items={[]} scopeLabel={null} />)
    expect(container).toBeEmptyDOMElement()
  })
})
