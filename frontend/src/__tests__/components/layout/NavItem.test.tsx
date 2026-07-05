import '@testing-library/jest-dom'
import { render, screen } from '@testing-library/react'
import { NavItem } from '@/components/layout/NavItem'
import { Database } from 'lucide-react'

jest.mock('next/navigation', () => ({
  usePathname: jest.fn(),
}))

import { usePathname } from 'next/navigation'
const mockUsePathname = usePathname as jest.Mock

describe('NavItem', () => {
  beforeEach(() => {
    mockUsePathname.mockReturnValue('/other')
  })

  it('renders a link when enabled with href', () => {
    render(<NavItem icon={Database} label="Inventory" href="/inventory" />)
    expect(screen.getByRole('link', { name: /inventory/i })).toBeInTheDocument()
  })

  it('renders a span (not a link) when disabled', () => {
    render(<NavItem icon={Database} label="Attack Paths" disabled />)
    expect(screen.queryByRole('link')).not.toBeInTheDocument()
    expect(screen.getByText('Attack Paths').closest('span')).toBeInTheDocument()
  })

  it('shows badge when disabled with badge prop', () => {
    render(<NavItem icon={Database} label="Attack Paths" disabled badge="Soon" />)
    expect(screen.getByText('Soon')).toBeInTheDocument()
  })

  it('does not show badge when not provided', () => {
    render(<NavItem icon={Database} label="Inventory" href="/inventory" />)
    expect(screen.queryByText('Soon')).not.toBeInTheDocument()
  })

  it('applies active highlight classes when route matches', () => {
    mockUsePathname.mockReturnValue('/inventory')
    render(<NavItem icon={Database} label="Inventory" href="/inventory" />)
    const link = screen.getByRole('link', { name: /inventory/i })
    expect(link).toHaveClass('border-orange-500')
    expect(link).toHaveClass('bg-slate-800')
  })

  it('does not apply active classes when route does not match', () => {
    mockUsePathname.mockReturnValue('/findings')
    render(<NavItem icon={Database} label="Inventory" href="/inventory" />)
    const link = screen.getByRole('link', { name: /inventory/i })
    expect(link).not.toHaveClass('border-orange-500')
  })

  it('applies disabled styling when disabled', () => {
    render(<NavItem icon={Database} label="Attack Paths" disabled />)
    // parentElement is the outer <span> wrapping icon + label + badge
    const outerSpan = screen.getByText('Attack Paths').parentElement
    expect(outerSpan).toHaveClass('opacity-50')
    expect(outerSpan).toHaveClass('cursor-not-allowed')
  })

  it('sets aria-disabled on the span when disabled', () => {
    render(<NavItem icon={Database} label="Attack Paths" disabled />)
    const outerSpan = screen.getByText('Attack Paths').parentElement
    expect(outerSpan).toHaveAttribute('aria-disabled', 'true')
  })
})
