import '@testing-library/jest-dom'
import { render, screen, fireEvent } from '@testing-library/react'
import { FrameworkSidebar } from '@/components/compliance/FrameworkSidebar'
import type { ComplianceFamily } from '@/lib/types'

const families: ComplianceFamily[] = [
  {
    family: 'cis-aws',
    label: 'CIS AWS Foundations Benchmark',
    target_by_control: null,
    versions: [
      { id: 'CIS-7.0', version_label: '7.0', pass: 8, fail: 2, total: 10, score: 80, sections: [] },
      { id: 'CIS-1.4', version_label: '1.4', pass: 5, fail: 5, total: 10, score: 50, sections: [] },
    ],
  },
  {
    family: 'SOC2',
    label: 'SOC 2',
    target_by_control: null,
    versions: [{ id: 'SOC2', version_label: '', pass: 3, fail: 1, total: 4, score: 75, sections: [] }],
  },
]

const onSelect = jest.fn()
beforeEach(() => jest.clearAllMocks())

describe('FrameworkSidebar', () => {
  it('renders one card per family, not one per raw framework/control slug', () => {
    render(<FrameworkSidebar families={families} selectedFamily={null} onSelect={onSelect} />)
    expect(screen.getByText('CIS AWS Foundations Benchmark')).toBeInTheDocument()
    expect(screen.getByText('SOC 2')).toBeInTheDocument()
    expect(screen.getByText('(2)')).toBeInTheDocument()
  })

  it('shows the latest version score as the headline for a multi-version family', () => {
    render(<FrameworkSidebar families={families} selectedFamily={null} onSelect={onSelect} />)
    expect(screen.getByText('80%')).toBeInTheDocument()
    expect(screen.getByText('2 versions')).toBeInTheDocument()
  })

  it('calls onSelect with the family key when a card is clicked', () => {
    render(<FrameworkSidebar families={families} selectedFamily={null} onSelect={onSelect} />)
    fireEvent.click(screen.getByText('SOC 2'))
    expect(onSelect).toHaveBeenCalledWith('SOC2')
  })

  it('filters the list by search query', () => {
    render(<FrameworkSidebar families={families} selectedFamily={null} onSelect={onSelect} />)
    fireEvent.change(screen.getByLabelText('Search frameworks'), { target: { value: 'soc' } })
    expect(screen.getByText('SOC 2')).toBeInTheDocument()
    expect(screen.queryByText('CIS AWS Foundations Benchmark')).not.toBeInTheDocument()
  })

  it('shows a message when no framework matches the search', () => {
    render(<FrameworkSidebar families={families} selectedFamily={null} onSelect={onSelect} />)
    fireEvent.change(screen.getByLabelText('Search frameworks'), { target: { value: 'nonexistent' } })
    expect(screen.getByText('No frameworks match your search.')).toBeInTheDocument()
  })

  it('shows a vs-goal indicator when a Compliance Settings target is configured', () => {
    const withGoal: ComplianceFamily[] = [
      { ...families[0], target_by_control: 90 }, // headline score is 80% — below goal
      { ...families[1], target_by_control: 70 }, // headline score is 75% — meets goal
    ]
    render(<FrameworkSidebar families={withGoal} selectedFamily={null} onSelect={onSelect} />)
    expect(screen.getByText('▾ 90%')).toBeInTheDocument()
    expect(screen.getByText('✓ 70%')).toBeInTheDocument()
  })

  it('omits the vs-goal indicator when no target is configured', () => {
    render(<FrameworkSidebar families={families} selectedFamily={null} onSelect={onSelect} />)
    expect(screen.queryByText(/^(✓|▾)/)).not.toBeInTheDocument()
  })
})
