import '@testing-library/jest-dom'
import { render, screen } from '@testing-library/react'
import { Sidebar } from '@/components/layout/Sidebar'

jest.mock('next/navigation', () => ({
  usePathname: jest.fn(() => '/'),
}))

describe('Sidebar', () => {
  it('renders the brand name', () => {
    render(<Sidebar />)
    expect(screen.getByText('Ogum Security')).toBeInTheDocument()
  })

  it('renders active links for implemented pages', () => {
    render(<Sidebar />)
    expect(screen.getByRole('link', { name: /dashboard/i })).toHaveAttribute('href', '/')
    expect(screen.getByRole('link', { name: /inventory/i })).toHaveAttribute('href', '/inventory')
    expect(screen.getByRole('link', { name: /findings/i })).toHaveAttribute('href', '/findings')
    expect(screen.getByRole('link', { name: /compliance/i })).toHaveAttribute('href', '/compliance')
    expect(screen.getByRole('link', { name: /cloud providers/i })).toHaveAttribute('href', '/providers')
  })

  it('renders disabled items without links for unimplemented pages', () => {
    render(<Sidebar />)
    const disabledLabels = ['Attack Paths', 'Side Scanning', 'Pulse (NRT)', 'CDR', 'AI Remediation', 'Integrations', 'Agent', 'Admin']
    const allLinks = screen.getAllByRole('link').map(l => l.textContent)
    disabledLabels.forEach(label => {
      expect(allLinks.join(' ')).not.toContain(label)
      expect(screen.getByText(label)).toBeInTheDocument()
    })
  })

  it('shows "Soon" badge on all disabled items', () => {
    render(<Sidebar />)
    const soonBadges = screen.getAllByText('Soon')
    expect(soonBadges.length).toBeGreaterThanOrEqual(8)
  })

  it('renders all navigation sections', () => {
    render(<Sidebar />)
    expect(screen.getByText('Overview')).toBeInTheDocument()
    expect(screen.getByText('Security Posture')).toBeInTheDocument()
    expect(screen.getByText('Threat Response')).toBeInTheDocument()
    expect(screen.getByText('Automation')).toBeInTheDocument()
    expect(screen.getByText('Configuration')).toBeInTheDocument()
    expect(screen.getByText('Platform')).toBeInTheDocument()
  })
})
