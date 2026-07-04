import '@testing-library/jest-dom'
import { render, screen } from '@testing-library/react'
import { SeverityBadge } from '@/components/ui/SeverityBadge'

describe('SeverityBadge', () => {
  it('renders CRITICAL with correct label and color', () => {
    const { container } = render(<SeverityBadge severity="CRITICAL" />)
    expect(screen.getByText('CRITICAL')).toBeInTheDocument()
    expect(container.firstChild).toHaveClass('text-red-400')
  })

  it('renders HIGH with correct label and color', () => {
    const { container } = render(<SeverityBadge severity="HIGH" />)
    expect(screen.getByText('HIGH')).toBeInTheDocument()
    expect(container.firstChild).toHaveClass('text-orange-400')
  })

  it('renders MEDIUM with correct label and color', () => {
    const { container } = render(<SeverityBadge severity="MEDIUM" />)
    expect(screen.getByText('MEDIUM')).toBeInTheDocument()
    expect(container.firstChild).toHaveClass('text-yellow-400')
  })

  it('renders LOW with correct label and color', () => {
    const { container } = render(<SeverityBadge severity="LOW" />)
    expect(screen.getByText('LOW')).toBeInTheDocument()
    expect(container.firstChild).toHaveClass('text-blue-400')
  })

  it('renders INFORMATIONAL with correct label', () => {
    render(<SeverityBadge severity="INFORMATIONAL" />)
    expect(screen.getByText('INFORMATIONAL')).toBeInTheDocument()
  })

  it('forwards additional className', () => {
    const { container } = render(
      <SeverityBadge severity="HIGH" className="extra-class" />,
    )
    expect(container.firstChild).toHaveClass('extra-class')
  })
})
