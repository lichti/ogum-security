import { render, screen } from '@testing-library/react'
import { SLABadge, classifySLA } from '@/components/ui/SLABadge'

describe('SLABadge', () => {
  it('renders the Within SLA label', () => {
    render(<SLABadge status="within_sla" />)
    expect(screen.getByText('Within SLA')).toBeInTheDocument()
  })

  it('renders the At Risk label', () => {
    render(<SLABadge status="at_risk" />)
    expect(screen.getByText('At Risk')).toBeInTheDocument()
  })

  it('renders the Overdue label', () => {
    render(<SLABadge status="overdue" />)
    expect(screen.getByText('Overdue')).toBeInTheDocument()
  })

  it('applies green styling for Within SLA', () => {
    render(<SLABadge status="within_sla" />)
    expect(screen.getByText('Within SLA').className).toMatch(/green/)
  })

  it('applies red styling for Overdue', () => {
    render(<SLABadge status="overdue" />)
    expect(screen.getByText('Overdue').className).toMatch(/red/)
  })
})

describe('classifySLA', () => {
  const detectedAt = new Date('2026-01-01T00:00:00Z')

  it('classifies as within_sla well before the deadline', () => {
    const now = new Date('2026-01-02T00:00:00Z') // 1 of 7 days elapsed
    expect(classifySLA(detectedAt, 7, now)).toBe('within_sla')
  })

  it('classifies as at_risk within the last 20% of the window', () => {
    const now = new Date('2026-01-07T00:00:00Z') // 24h left of a 7-day (168h) window — under the 33.6h threshold
    expect(classifySLA(detectedAt, 7, now)).toBe('at_risk')
  })

  it('classifies as overdue past the deadline', () => {
    const now = new Date('2026-01-09T00:00:00Z') // 8 of 7 days elapsed
    expect(classifySLA(detectedAt, 7, now)).toBe('overdue')
  })

  it('classifies exactly at the deadline as overdue', () => {
    const now = new Date('2026-01-08T00:00:00Z') // exactly 7 days
    expect(classifySLA(detectedAt, 7, now)).toBe('overdue')
  })
})
