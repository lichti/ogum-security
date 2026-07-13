import '@testing-library/jest-dom'
import { render, screen } from '@testing-library/react'
import { StatusBadge } from '@/components/admin/StatusBadge'

describe('StatusBadge', () => {
  it('renders the status text', () => {
    render(<StatusBadge status="running" />)
    expect(screen.getByText('running')).toBeInTheDocument()
  })

  it('applies green classes for completed', () => {
    render(<StatusBadge status="completed" />)
    expect(screen.getByText('completed')).toHaveClass('bg-green-900', 'text-green-300')
  })

  it('applies red classes for failed', () => {
    render(<StatusBadge status="failed" />)
    expect(screen.getByText('failed')).toHaveClass('bg-red-900', 'text-red-300')
  })

  it('applies yellow classes for queued', () => {
    render(<StatusBadge status="queued" />)
    expect(screen.getByText('queued')).toHaveClass('bg-yellow-900', 'text-yellow-300')
  })

  it('matches status case-insensitively', () => {
    render(<StatusBadge status="COMPLETED" />)
    expect(screen.getByText('COMPLETED')).toHaveClass('bg-green-900')
  })

  it('falls back to a neutral style for an unknown status', () => {
    render(<StatusBadge status="mystery" />)
    expect(screen.getByText('mystery')).toHaveClass('bg-slate-700', 'text-slate-300')
  })
})
