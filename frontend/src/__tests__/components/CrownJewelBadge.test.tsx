import { render, screen } from '@testing-library/react'
import { CrownJewelBadge } from '@/components/ui/CrownJewelBadge'

describe('CrownJewelBadge', () => {
  it('renders the Crown Jewel label', () => {
    render(<CrownJewelBadge origin="auto" />)
    expect(screen.getByText('Crown Jewel')).toBeInTheDocument()
  })

  it('shows "auto-detected" subtitle for auto origin', () => {
    render(<CrownJewelBadge origin="auto" />)
    expect(screen.getByText('auto-detected')).toBeInTheDocument()
  })

  it('shows "manually marked" subtitle for manual origin', () => {
    render(<CrownJewelBadge origin="manual" />)
    expect(screen.getByText('manually marked')).toBeInTheDocument()
  })

  it('uses a dashed border for manually marked assets', () => {
    render(<CrownJewelBadge origin="manual" />)
    expect(screen.getByText('Crown Jewel').className).toMatch(/border-dashed/)
  })

  it('uses a solid border for auto-detected assets', () => {
    render(<CrownJewelBadge origin="auto" />)
    expect(screen.getByText('Crown Jewel').className).not.toMatch(/border-dashed/)
  })
})
