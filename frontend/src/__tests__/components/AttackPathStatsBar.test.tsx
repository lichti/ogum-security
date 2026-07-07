import '@testing-library/jest-dom'
import { render, screen, fireEvent } from '@testing-library/react'
import { AttackPathStatsBar } from '@/components/attack-paths/AttackPathStatsBar'
import type { AttackPathStats } from '@/lib/types'

const makeStats = (overrides: Partial<AttackPathStats> = {}): AttackPathStats => ({
  total: 10,
  by_severity: { CRITICAL: 3, HIGH: 4, MEDIUM: 2, LOW: 1 },
  new_24h: 2,
  ...overrides,
})

const onSeverityClick = jest.fn()
beforeEach(() => jest.clearAllMocks())

describe('AttackPathStatsBar', () => {
  it('renders total count', () => {
    render(<AttackPathStatsBar stats={makeStats()} onSeverityClick={onSeverityClick} />)
    expect(screen.getByText('10')).toBeInTheDocument()
  })

  it('renders count for each severity', () => {
    render(<AttackPathStatsBar stats={makeStats({ new_24h: 0 })} onSeverityClick={onSeverityClick} />)
    expect(screen.getByText('3')).toBeInTheDocument()
    expect(screen.getByText('4')).toBeInTheDocument()
    // MEDIUM = 2, LOW = 1 — unique when new_24h is 0
    expect(screen.getByText('2')).toBeInTheDocument()
    expect(screen.getByText('1')).toBeInTheDocument()
  })

  it('renders new_24h indicator when non-zero', () => {
    render(<AttackPathStatsBar stats={makeStats({ new_24h: 5 })} onSeverityClick={onSeverityClick} />)
    expect(screen.getByText('5')).toBeInTheDocument()
    expect(screen.getByText('New (24h)')).toBeInTheDocument()
  })

  it('hides new_24h indicator when zero', () => {
    render(<AttackPathStatsBar stats={makeStats({ new_24h: 0 })} onSeverityClick={onSeverityClick} />)
    expect(screen.queryByText('New (24h)')).not.toBeInTheDocument()
  })

  it('calls onSeverityClick with correct severity when a chip is clicked', () => {
    render(<AttackPathStatsBar stats={makeStats()} onSeverityClick={onSeverityClick} />)
    fireEvent.click(screen.getByLabelText('Filter by CRITICAL'))
    expect(onSeverityClick).toHaveBeenCalledWith('CRITICAL')
  })
})
