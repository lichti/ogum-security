import { render, screen } from '@testing-library/react'
import { RiskScoreBadge } from '@/components/ui/RiskScoreBadge'

describe('RiskScoreBadge', () => {
  it('renders the score with one decimal place', () => {
    render(<RiskScoreBadge score={9.8} />)
    expect(screen.getByText('9.8')).toBeInTheDocument()
  })

  it('applies red border for scores >= 9.0', () => {
    render(<RiskScoreBadge score={9.8} />)
    expect(screen.getByTitle('Score: 9.8').className).toMatch(/red/)
  })

  it('applies orange border for scores in 7.0-8.9', () => {
    render(<RiskScoreBadge score={7.5} />)
    expect(screen.getByTitle('Score: 7.5').className).toMatch(/orange/)
  })

  it('applies yellow border for scores in 4.0-6.9', () => {
    render(<RiskScoreBadge score={6.4} />)
    expect(screen.getByTitle('Score: 6.4').className).toMatch(/yellow/)
  })

  it('applies blue border for scores below 4.0', () => {
    render(<RiskScoreBadge score={2.1} />)
    expect(screen.getByTitle('Score: 2.1').className).toMatch(/blue/)
  })

  it('formats an integer score with a trailing .0', () => {
    render(<RiskScoreBadge score={5} />)
    expect(screen.getByText('5.0')).toBeInTheDocument()
  })
})
