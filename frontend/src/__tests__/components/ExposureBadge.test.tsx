import { render, screen } from '@testing-library/react'
import { ExposureBadge } from '@/components/ui/ExposureBadge'

describe('ExposureBadge', () => {
  it('renders the Internet Facing label', () => {
    render(<ExposureBadge exposure="internet_facing" />)
    expect(screen.getByText('Internet Facing')).toBeInTheDocument()
  })

  it('renders the Public Facing label', () => {
    render(<ExposureBadge exposure="public_facing" />)
    expect(screen.getByText('Public Facing')).toBeInTheDocument()
  })

  it('renders the Trusted Access label', () => {
    render(<ExposureBadge exposure="trusted_access" />)
    expect(screen.getByText('Trusted Access')).toBeInTheDocument()
  })

  it('renders the None label', () => {
    render(<ExposureBadge exposure="none" />)
    expect(screen.getByText('None')).toBeInTheDocument()
  })

  it('always shows a tooltip icon explaining the exposure level', () => {
    render(<ExposureBadge exposure="internet_facing" />)
    expect(screen.getByLabelText('Internet Facing explanation')).toBeInTheDocument()
  })

  it('applies red styling for internet-facing exposure', () => {
    render(<ExposureBadge exposure="internet_facing" />)
    expect(screen.getByText('Internet Facing').closest('span')?.className).toMatch(/red/)
  })
})
