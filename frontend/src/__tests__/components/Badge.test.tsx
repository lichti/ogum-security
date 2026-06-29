import '@testing-library/jest-dom'
import { render, screen } from '@testing-library/react'
import { Badge } from '@/components/ui/Badge'

describe('Badge', () => {
  it('renders children', () => {
    render(<Badge>AWS</Badge>)
    expect(screen.getByText('AWS')).toBeInTheDocument()
  })

  it('applies provider-aws variant classes', () => {
    const { container } = render(<Badge variant="provider-aws">AWS</Badge>)
    expect(container.firstChild).toHaveClass('text-amber-400')
  })

  it('applies provider-azure variant classes', () => {
    const { container } = render(<Badge variant="provider-azure">Azure</Badge>)
    expect(container.firstChild).toHaveClass('text-blue-400')
  })

  it('applies severity-critical variant classes', () => {
    const { container } = render(<Badge variant="severity-critical">CRITICAL</Badge>)
    expect(container.firstChild).toHaveClass('text-red-400')
  })

  it('applies severity-high variant classes', () => {
    const { container } = render(<Badge variant="severity-high">HIGH</Badge>)
    expect(container.firstChild).toHaveClass('text-orange-400')
  })

  it('applies severity-medium variant classes', () => {
    const { container } = render(<Badge variant="severity-medium">MEDIUM</Badge>)
    expect(container.firstChild).toHaveClass('text-yellow-400')
  })

  it('applies severity-low variant classes', () => {
    const { container } = render(<Badge variant="severity-low">LOW</Badge>)
    expect(container.firstChild).toHaveClass('text-blue-400')
  })

  it('applies status-active variant', () => {
    const { container } = render(<Badge variant="status-active">active</Badge>)
    expect(container.firstChild).toHaveClass('text-green-400')
  })

  it('applies status-deleted variant', () => {
    const { container } = render(<Badge variant="status-deleted">deleted</Badge>)
    expect(container.firstChild).toHaveClass('text-slate-500')
  })

  it('applies default variant when no variant specified', () => {
    const { container } = render(<Badge>generic</Badge>)
    expect(container.firstChild).toHaveClass('text-slate-300')
  })

  it('accepts additional className', () => {
    const { container } = render(<Badge className="custom-class">test</Badge>)
    expect(container.firstChild).toHaveClass('custom-class')
  })
})
