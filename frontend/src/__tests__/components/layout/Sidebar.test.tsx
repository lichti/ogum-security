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
    expect(screen.getByRole('link', { name: /^compliance$/i })).toHaveAttribute('href', '/compliance')
    expect(screen.getByRole('link', { name: /attack paths/i })).toHaveAttribute('href', '/attack-paths')
    expect(screen.getByRole('link', { name: /cloud providers/i })).toHaveAttribute('href', '/providers')
    expect(screen.getByRole('link', { name: /sla settings/i })).toHaveAttribute('href', '/settings/sla')
    expect(screen.getByRole('link', { name: /compliance settings/i })).toHaveAttribute('href', '/settings/compliance')
    expect(screen.getByRole('link', { name: /admin/i })).toHaveAttribute('href', '/admin/jobs')
  })

  it('renders disabled items without links for unimplemented pages', () => {
    render(<Sidebar />)
    const disabledLabels = ['Pulse (NRT)', 'CDR', 'AI Remediation', 'Integrations', 'Agent']
    const allLinks = screen.getAllByRole('link').map(l => l.textContent)
    disabledLabels.forEach(label => {
      expect(allLinks.join(' ')).not.toContain(label)
      expect(screen.getByText(label)).toBeInTheDocument()
    })
  })

  it('shows "Soon" badge on all disabled items', () => {
    render(<Sidebar />)
    const soonBadges = screen.getAllByText('Soon')
    expect(soonBadges.length).toBeGreaterThanOrEqual(5)
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
