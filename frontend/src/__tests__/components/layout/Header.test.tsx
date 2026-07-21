import '@testing-library/jest-dom'
import { render, screen } from '@testing-library/react'
import { Header } from '@/components/layout/Header'

jest.mock('next/navigation', () => ({
  usePathname: jest.fn(),
}))

import { usePathname } from 'next/navigation'
const mockUsePathname = usePathname as jest.Mock

describe('Header', () => {
  it('renders the mapped label for a known route', () => {
    mockUsePathname.mockReturnValue('/inventory')
    render(<Header />)
    expect(screen.getByText('Inventory')).toBeInTheDocument()
  })

  it('falls back to a formatted path for an unmapped route', () => {
    mockUsePathname.mockReturnValue('/some-unmapped-route')
    render(<Header />)
    expect(screen.getByText('some unmapped route')).toBeInTheDocument()
  })

  it('shows the Compliance subtitle next to the title on /compliance', () => {
    mockUsePathname.mockReturnValue('/compliance')
    render(<Header />)
    expect(screen.getByText('Compliance')).toBeInTheDocument()
    expect(screen.getByText('Framework scores and control status')).toBeInTheDocument()
  })

  it('renders no subtitle for routes without one configured', () => {
    mockUsePathname.mockReturnValue('/inventory')
    render(<Header />)
    expect(screen.queryByText('Framework scores and control status')).not.toBeInTheDocument()
  })

  it('uses a page-specific label where it differs from the sidebar nav label', () => {
    // '/' is "Dashboard" in the sidebar nav but "Security Overview" as the page's
    // own title — the two are allowed to differ (nav category vs. content title).
    mockUsePathname.mockReturnValue('/')
    render(<Header />)
    expect(screen.getByText('Security Overview')).toBeInTheDocument()
    expect(screen.getByText('Real-time posture across all connected accounts')).toBeInTheDocument()
  })

  it.each([
    ['/attack-paths', 'Attack Paths', 'Contextual risk graph — paths from internet exposure to sensitive data'],
    ['/side-scanning', 'Side Scanning', 'Agentless deep scanning of EC2, Lambda, containers and registry images'],
    ['/settings/compliance', 'Compliance Settings', undefined],
    ['/admin/jobs', 'Admin — Jobs', undefined],
  ])('resolves %s to label %s', (path, label, subtitle) => {
    mockUsePathname.mockReturnValue(path)
    render(<Header />)
    expect(screen.getByText(label)).toBeInTheDocument()
    if (subtitle) expect(screen.getByText(subtitle)).toBeInTheDocument()
  })
})
