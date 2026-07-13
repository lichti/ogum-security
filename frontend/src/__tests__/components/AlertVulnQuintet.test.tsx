import { render, screen } from '@testing-library/react'
import { AlertVulnQuintet } from '@/components/ui/AlertVulnQuintet'

describe('AlertVulnQuintet', () => {
  it('renders counts for each severity in order', () => {
    render(<AlertVulnQuintet counts={{ CRITICAL: 3, HIGH: 12, MEDIUM: 47, LOW: 8 }} />)
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.getByText('12')).toBeInTheDocument()
    expect(screen.getByText('47')).toBeInTheDocument()
    expect(screen.getByText('8')).toBeInTheDocument()
  })

  it('renders a dash for severities with zero count', () => {
    render(<AlertVulnQuintet counts={{ CRITICAL: 3 }} />)
    const dashes = screen.getAllByText('—')
    expect(dashes).toHaveLength(4)
  })

  it('renders all dashes when counts is empty', () => {
    render(<AlertVulnQuintet counts={{}} />)
    expect(screen.getAllByText('—')).toHaveLength(5)
  })

  it('exposes the full severity name via title for each cell', () => {
    render(<AlertVulnQuintet counts={{ CRITICAL: 3, HIGH: 12, MEDIUM: 47, LOW: 8, INFORMATIONAL: 0 }} />)
    expect(screen.getByTitle('CRITICAL')).toBeInTheDocument()
    expect(screen.getByTitle('HIGH')).toBeInTheDocument()
    expect(screen.getByTitle('MEDIUM')).toBeInTheDocument()
    expect(screen.getByTitle('LOW')).toBeInTheDocument()
    expect(screen.getByTitle('INFORMATIONAL')).toBeInTheDocument()
  })
})
