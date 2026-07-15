import '@testing-library/jest-dom'
import { render, screen } from '@testing-library/react'
import { SectionHeatmap } from '@/components/compliance/SectionHeatmap'
import type { ComplianceSectionNode } from '@/lib/types'

function mockSection(overrides: Partial<ComplianceSectionNode> = {}): ComplianceSectionNode {
  return {
    key: 'sec-1',
    label: 'Section 1',
    control_pass_count: 4,
    control_fail_count: 0,
    control_unscored_count: 0,
    control_total: 4,
    score_by_control: 100,
    finding_pass_count: 4,
    finding_fail_count: 0,
    finding_accepted_count: 0,
    finding_muted_count: 0,
    score_by_asset: 100,
    subsections: [],
    requirements: [],
    ...overrides,
  }
}

describe('SectionHeatmap', () => {
  it('shows an empty state when there are no sections', () => {
    render(<SectionHeatmap sections={[]} view="control" />)
    expect(screen.getByText('No sections to show yet.')).toBeInTheDocument()
  })

  it('renders one row per section with score and pass/total (control view)', () => {
    const sections = [
      mockSection({ key: 'a', label: 'Access Control', score_by_control: 90, control_pass_count: 9, control_total: 10 }),
      mockSection({ key: 'b', label: 'Data Protection', score_by_control: 40, control_pass_count: 2, control_total: 5 }),
    ]
    render(<SectionHeatmap sections={sections} view="control" />)

    expect(screen.getByText('Access Control')).toBeInTheDocument()
    expect(screen.getByText('90%')).toBeInTheDocument()
    expect(screen.getByText('9/10')).toBeInTheDocument()

    expect(screen.getByText('Data Protection')).toBeInTheDocument()
    expect(screen.getByText('40%')).toBeInTheDocument()
  })

  it('renders finding-based score and pass/(pass+fail) in findings view', () => {
    const sections = [
      mockSection({
        label: 'Access Control',
        score_by_asset: 75,
        finding_pass_count: 3,
        finding_fail_count: 1,
        finding_accepted_count: 2,
        finding_muted_count: 1,
      }),
    ]
    render(<SectionHeatmap sections={sections} view="findings" />)
    expect(screen.getByText('75%')).toBeInTheDocument()
    expect(screen.getByText('3/4')).toBeInTheDocument() // pass/(pass+fail), accepted/muted excluded
  })

  it.each([
    [95, 'text-green-400'],
    [60, 'text-yellow-400'],
    [20, 'text-red-400'],
  ])('colors a %i%% control score as %s', (score, expectedClass) => {
    render(<SectionHeatmap sections={[mockSection({ score_by_control: score })]} view="control" />)
    const scoreEl = screen.getByText(`${score}%`)
    expect(scoreEl.className).toContain(expectedClass)
  })

  it('includes exact counts in the tooltip title for the control view', () => {
    const sections = [mockSection({ label: 'Section X', control_pass_count: 3, control_total: 5, control_unscored_count: 1 })]
    const { container } = render(<SectionHeatmap sections={sections} view="control" />)
    const row = container.querySelector('[title*="Section X"]')
    expect(row?.getAttribute('title')).toContain('3/5')
    expect(row?.getAttribute('title')).toContain('1 unscored')
  })

  it('includes accepted/muted counts in the tooltip title for the findings view', () => {
    const sections = [
      mockSection({ label: 'Section X', finding_accepted_count: 2, finding_muted_count: 3, control_unscored_count: 1 }),
    ]
    const { container } = render(<SectionHeatmap sections={sections} view="findings" />)
    const row = container.querySelector('[title*="Section X"]')
    expect(row?.getAttribute('title')).toContain('2 accepted')
    expect(row?.getAttribute('title')).toContain('3 muted')
  })
})
