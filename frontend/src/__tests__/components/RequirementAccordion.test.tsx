import '@testing-library/jest-dom'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { RequirementAccordion } from '@/components/compliance/RequirementAccordion'
import type { ComplianceRequirementNode, ComplianceSectionNode } from '@/lib/types'

const pushMock = jest.fn()
jest.mock('next/navigation', () => ({
  useRouter: () => ({ push: pushMock }),
}))

function mockRequirement(overrides: Partial<ComplianceRequirementNode> = {}): ComplianceRequirementNode {
  return {
    control_id: '1.1',
    name: 'Root MFA enabled',
    description: null,
    status: 'FAIL',
    finding_key: 'find-1',
    pass_count: 0,
    fail_count: 1,
    ...overrides,
  }
}

function mockSection(overrides: Partial<ComplianceSectionNode> = {}): ComplianceSectionNode {
  return {
    key: 'sec-1',
    label: 'Identity and Access Management',
    pass_count: 0,
    fail_count: 1,
    unscored_count: 0,
    total: 1,
    score_by_control: 0,
    subsections: [],
    requirements: [mockRequirement()],
    ...overrides,
  }
}

beforeEach(() => jest.clearAllMocks())

describe('RequirementAccordion', () => {
  it('shows an empty state when there are no sections', () => {
    render(<RequirementAccordion sections={[]} />)
    expect(screen.getByText('No requirements to show yet.')).toBeInTheDocument()
  })

  it('renders without crashing for a flat, subsection-less tree', () => {
    render(<RequirementAccordion sections={[mockSection()]} />)
    expect(screen.getByText('Identity and Access Management')).toBeInTheDocument()
  })

  it('requirements are hidden until the section is expanded', async () => {
    const user = userEvent.setup()
    render(<RequirementAccordion sections={[mockSection()]} />)

    expect(screen.queryByText('Root MFA enabled')).not.toBeInTheDocument()
    await user.click(screen.getByText('Identity and Access Management'))
    expect(screen.getByText('Root MFA enabled')).toBeInTheDocument()
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
    render(<RequirementAccordion sections={sections} />)

    await user.click(screen.getByText('Identity and Access Management'))
    expect(screen.getByText('Account Management')).toBeInTheDocument()

    await user.click(screen.getByText('Account Management'))
    expect(screen.getByText('Root MFA enabled')).toBeInTheDocument()
  })

  it('only shows the finding link when finding_key is present', async () => {
    const user = userEvent.setup()
    const sections = [
      mockSection({
        requirements: [mockRequirement({ status: 'UNSCORED', finding_key: null, control_id: '1.2' })],
      }),
    ]
    render(<RequirementAccordion sections={sections} />)
    await user.click(screen.getByText('Identity and Access Management'))

    expect(screen.getByText('UNSCORED')).toBeInTheDocument()
    expect(screen.queryByText('View finding →')).not.toBeInTheDocument()
  })

  it('navigates to the finding when the link is clicked', async () => {
    const user = userEvent.setup()
    render(<RequirementAccordion sections={[mockSection()]} />)
    await user.click(screen.getByText('Identity and Access Management'))
    await user.click(screen.getByText('View finding →'))
    expect(pushMock).toHaveBeenCalledWith('/findings?finding=find-1')
  })
})
