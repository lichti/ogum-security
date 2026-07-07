import { render, screen } from '@testing-library/react'
import { RiskBadge } from '@/components/ui/RiskBadge'

describe('RiskBadge', () => {
  it('renders score 0 as NONE tier', () => {
    render(<RiskBadge score={0} />)
    expect(screen.getByText('0')).toBeInTheDocument()
  })

  it('renders low score (1-24)', () => {
    render(<RiskBadge score={20} />)
    expect(screen.getByText('20')).toBeInTheDocument()
  })

  it('renders medium score (25-49)', () => {
    render(<RiskBadge score={40} />)
    expect(screen.getByText('40')).toBeInTheDocument()
  })

  it('renders high score (50-74)', () => {
    render(<RiskBadge score={60} />)
    expect(screen.getByText('60')).toBeInTheDocument()
  })

  it('renders critical score (75+)', () => {
    render(<RiskBadge score={80} />)
    expect(screen.getByText('80')).toBeInTheDocument()
  })

  it('renders dash for null score', () => {
    render(<RiskBadge score={null} />)
    expect(screen.getByText('—')).toBeInTheDocument()
  })

  it('renders dash for undefined score', () => {
    render(<RiskBadge score={undefined} />)
    expect(screen.getByText('—')).toBeInTheDocument()
  })

  it('applies title with score value', () => {
    render(<RiskBadge score={75} />)
    expect(screen.getByTitle('Risk score: 75')).toBeInTheDocument()
  })

  it('critical tier badge has red styling', () => {
    render(<RiskBadge score={90} />)
    const badge = screen.getByTitle('Risk score: 90')
    expect(badge.className).toMatch(/red/)
  })

  it('medium tier badge has yellow styling', () => {
    render(<RiskBadge score={35} />)
    const badge = screen.getByTitle('Risk score: 35')
    expect(badge.className).toMatch(/yellow/)
  })
})
