import '@testing-library/jest-dom'
import { render, screen } from '@testing-library/react'
import { SectionHeatmap } from '@/components/compliance/SectionHeatmap'
import type { ComplianceSectionNode } from '@/lib/types'

function mockSection(overrides: Partial<ComplianceSectionNode> = {}): ComplianceSectionNode {
  return {
    key: 'sec-1',
    label: 'Section 1',
    pass_count: 4,
    fail_count: 0,
    unscored_count: 0,
    total: 4,
    score_by_control: 100,
    subsections: [],
    requirements: [],
    ...overrides,
  }
}

describe('SectionHeatmap', () => {
  it('shows an empty state when there are no sections', () => {
    render(<SectionHeatmap sections={[]} />)
    expect(screen.getByText('No sections to show yet.')).toBeInTheDocument()
  })

  it('renders one cell per section with score and pass/total', () => {
    const sections = [
      mockSection({ key: 'a', label: 'Access Control', score_by_control: 90, pass_count: 9, total: 10 }),
      mockSection({ key: 'b', label: 'Data Protection', score_by_control: 40, pass_count: 2, total: 5 }),
    ]
    render(<SectionHeatmap sections={sections} />)

    expect(screen.getByText('Access Control')).toBeInTheDocument()
    expect(screen.getByText('90%')).toBeInTheDocument()
    expect(screen.getByText('9/10')).toBeInTheDocument()

    expect(screen.getByText('Data Protection')).toBeInTheDocument()
    expect(screen.getByText('40%')).toBeInTheDocument()
  })

  it.each([
    [95, 'text-green-400'],
    [60, 'text-yellow-400'],
    [20, 'text-red-400'],
  ])('colors a %i%% section score as %s', (score, expectedClass) => {
    render(<SectionHeatmap sections={[mockSection({ score_by_control: score })]} />)
    const scoreEl = screen.getByText(`${score}%`)
    expect(scoreEl.className).toContain(expectedClass)
  })

  it('includes exact counts in the tooltip title', () => {
    const sections = [mockSection({ label: 'Section X', pass_count: 3, total: 5, unscored_count: 1 })]
    const { container } = render(<SectionHeatmap sections={sections} />)
    const cell = container.querySelector('[title*="Section X"]')
    expect(cell?.getAttribute('title')).toContain('3/5')
    expect(cell?.getAttribute('title')).toContain('1 unscored')
  })
})
