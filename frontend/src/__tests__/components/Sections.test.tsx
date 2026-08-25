import '@testing-library/jest-dom'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Sections } from '@/components/compliance/Sections'
import type { ComplianceRequirementNode, ComplianceSectionNode } from '@/lib/types'

function mockRequirement(overrides: Partial<ComplianceRequirementNode> = {}): ComplianceRequirementNode {
  return {
    control_id: '1.1',
    name: 'Root MFA enabled',
    description: null,
    status: 'FAIL',
    finding_key: 'find-1',
    pass_count: 0,
    fail_count: 1,
    accepted_count: 0,
    muted_count: 0,
    ...overrides,
  }
}

function mockSection(overrides: Partial<ComplianceSectionNode> = {}): ComplianceSectionNode {
  return {
    key: 'sec-1',
    label: 'Identity and Access Management',
    control_pass_count: 0,
    control_fail_count: 1,
    control_unscored_count: 0,
    control_total: 1,
    score_by_control: 0,
    subsections: [],
    requirements: [mockRequirement()],
    ...overrides,
  }
}

const onOpenControl = jest.fn()
beforeEach(() => jest.clearAllMocks())

describe('Sections', () => {
  it('shows an empty state when there are no sections', () => {
    render(<Sections sections={[]} onOpenControl={onOpenControl} />)
    expect(screen.getByText('No sections to show yet.')).toBeInTheDocument()
  })

  it('renders one row per section with score and pass/fail/unscored/total, always visible (no collapse toggle)', () => {
    const sections = [
      mockSection({
        key: 'a',
        label: 'Access Control',
        score_by_control: 90,
        control_pass_count: 9,
        control_fail_count: 1,
        control_unscored_count: 0,
        control_total: 10,
        requirements: [],
      }),
      mockSection({
        key: 'b',
        label: 'Data Protection',
        score_by_control: 40,
        control_pass_count: 2,
        control_fail_count: 2,
        control_unscored_count: 1,
        control_total: 5,
        requirements: [],
      }),
    ]
    render(<Sections sections={sections} onOpenControl={onOpenControl} />)

    expect(screen.getByText('Sections (2)')).toBeInTheDocument()
    expect(screen.getByText('Access Control')).toBeInTheDocument()
    expect(screen.getByText('90%')).toBeInTheDocument()
    expect(screen.getByText('9/1/0/10')).toBeInTheDocument()

    expect(screen.getByText('Data Protection')).toBeInTheDocument()
    expect(screen.getByText('40%')).toBeInTheDocument()
    expect(screen.getByText('2/2/1/5')).toBeInTheDocument()
  })

  it.each([
    [95, 'text-green-400'],
    [60, 'text-yellow-400'],
    [20, 'text-red-400'],
  ])('colors a %i%% score as %s', (score, expectedClass) => {
    render(<Sections sections={[mockSection({ score_by_control: score, requirements: [] })]} onOpenControl={onOpenControl} />)
    const scoreEl = screen.getByText(`${score}%`)
    expect(scoreEl.className).toContain(expectedClass)
  })

  it('includes exact counts in the row title', () => {
    const sections = [
      mockSection({ label: 'Section X', control_pass_count: 3, control_total: 5, control_unscored_count: 1, requirements: [] }),
    ]
    const { container } = render(<Sections sections={sections} onOpenControl={onOpenControl} />)
    const row = container.querySelector('[title*="Section X"]')
    expect(row?.getAttribute('title')).toContain('3/5')
    expect(row?.getAttribute('title')).toContain('1 unscored')
  })

  it('shows a legend explaining the count column', () => {
    render(<Sections sections={[mockSection({ requirements: [] })]} onOpenControl={onOpenControl} />)
    const legend = screen.getByText('P/F/U/T')
    expect(legend.closest('[title]')?.getAttribute('title')).toContain('Score = (Pass + Unscored) / Total')
  })

  it('requirements are hidden until the section row is clicked', async () => {
    const user = userEvent.setup()
    render(<Sections sections={[mockSection()]} onOpenControl={onOpenControl} />)

    expect(screen.queryByText('Root MFA enabled')).not.toBeInTheDocument()
    await user.click(screen.getByText('Identity and Access Management'))
    expect(screen.getByText('Root MFA enabled')).toBeInTheDocument()
  })

  it('a section row with no requirements or subsections is not clickable', () => {
    render(<Sections sections={[mockSection({ requirements: [] })]} onOpenControl={onOpenControl} />)
    const button = screen.getByText('Identity and Access Management').closest('button')
    expect(button).toBeDisabled()
  })

  it('recurses into subsections', async () => {
    const user = userEvent.setup()
    const sections = [
      mockSection({
        requirements: [],
        subsections: [
          mockSection({ key: 'sub-1', label: 'Account Management', requirements: [mockRequirement()] }),
        ],
      }),
    ]
    render(<Sections sections={sections} onOpenControl={onOpenControl} />)

    await user.click(screen.getByText('Identity and Access Management'))
    expect(screen.getByText('Account Management')).toBeInTheDocument()

    await user.click(screen.getByText('Account Management'))
    expect(screen.getByText('Root MFA enabled')).toBeInTheDocument()
  })

  it('a Fail or Pass requirement row is clickable and opens the control drilldown', async () => {
    const user = userEvent.setup()
    const requirement = mockRequirement({ status: 'FAIL' })
    render(<Sections sections={[mockSection({ requirements: [requirement] })]} onOpenControl={onOpenControl} />)
    await user.click(screen.getByText('Identity and Access Management'))

    await user.click(screen.getByText('Root MFA enabled'))
    expect(onOpenControl).toHaveBeenCalledWith(requirement)
  })

  it('an Unscored requirement row is not clickable', async () => {
    const user = userEvent.setup()
    const sections = [
      mockSection({
        requirements: [mockRequirement({ status: 'UNSCORED', finding_key: null, control_id: '1.2' })],
      }),
    ]
    render(<Sections sections={sections} onOpenControl={onOpenControl} />)
    await user.click(screen.getByText('Identity and Access Management'))

    expect(screen.getByText('UNSCORED')).toBeInTheDocument()
    const row = screen.getByText('UNSCORED').closest('[data-testid="compliance-requirement-row-1.2"]')
    expect(row?.tagName).toBe('DIV')
    await user.click(screen.getByText('UNSCORED'))
    expect(onOpenControl).not.toHaveBeenCalled()
  })

  it('a Pass requirement row is also clickable', async () => {
    const user = userEvent.setup()
    const requirement = mockRequirement({ status: 'PASS' })
    render(<Sections sections={[mockSection({ requirements: [requirement] })]} onOpenControl={onOpenControl} />)
    await user.click(screen.getByText('Identity and Access Management'))

    await user.click(screen.getByText('Root MFA enabled'))
    expect(onOpenControl).toHaveBeenCalledWith(requirement)
  })
})
