import '@testing-library/jest-dom'
import { render, screen, fireEvent } from '@testing-library/react'
import { FrameworkDetail } from '@/components/compliance/FrameworkDetail'
import type { ComplianceFamily } from '@/lib/types'

const family: ComplianceFamily = {
  family: 'nist-800-53',
  label: 'NIST 800-53',
  versions: [
    {
      id: 'NIST-800-53-Revision-5',
      version_label: 'Revision 5',
      pass: 10,
      fail: 5,
      total: 15,
      score: 66.7,
      sections: [
        { key: 'ac', label: 'AC — Access Control', pass: 6, fail: 1, total: 7, score: 85.7 },
        { key: 'cm', label: 'CM — Configuration Management', pass: 4, fail: 4, total: 8, score: 50 },
      ],
    },
    {
      id: 'NIST-800-53-Revision-4',
      version_label: 'Revision 4',
      pass: 2,
      fail: 2,
      total: 4,
      score: 50,
      sections: [],
    },
  ],
}

const onVersionChange = jest.fn()
beforeEach(() => jest.clearAllMocks())

describe('FrameworkDetail', () => {
  it('renders the family label and the selected version score', () => {
    render(
      <FrameworkDetail family={family} selectedVersionId="NIST-800-53-Revision-5" onVersionChange={onVersionChange} />,
    )
    expect(screen.getByText('NIST 800-53')).toBeInTheDocument()
    expect(screen.getByText('66.7%')).toBeInTheDocument()
  })

  it('renders a tab per version when there is more than one', () => {
    render(
      <FrameworkDetail family={family} selectedVersionId="NIST-800-53-Revision-5" onVersionChange={onVersionChange} />,
    )
    expect(screen.getByText('Revision 5')).toBeInTheDocument()
    expect(screen.getByText('Revision 4')).toBeInTheDocument()
  })

  it('calls onVersionChange when a different version tab is clicked', () => {
    render(
      <FrameworkDetail family={family} selectedVersionId="NIST-800-53-Revision-5" onVersionChange={onVersionChange} />,
    )
    fireEvent.click(screen.getByText('Revision 4'))
    expect(onVersionChange).toHaveBeenCalledWith('NIST-800-53-Revision-4')
  })

  it('renders every section of the selected version with its own score', () => {
    render(
      <FrameworkDetail family={family} selectedVersionId="NIST-800-53-Revision-5" onVersionChange={onVersionChange} />,
    )
    expect(screen.getByText('AC — Access Control')).toBeInTheDocument()
    expect(screen.getByText('CM — Configuration Management')).toBeInTheDocument()
    expect(screen.getByText('85.7%')).toBeInTheDocument()
  })

  it('links "View findings" to the Findings page scoped by the selected version id', () => {
    render(
      <FrameworkDetail family={family} selectedVersionId="NIST-800-53-Revision-5" onVersionChange={onVersionChange} />,
    )
    const link = screen.getByText('View findings').closest('a')
    expect(link).toHaveAttribute('href', '/findings?framework=NIST-800-53-Revision-5')
  })

  it('does not render version tabs for a single-version family', () => {
    const single: ComplianceFamily = {
      family: 'SOC2',
      label: 'SOC 2',
      versions: [{ id: 'SOC2', version_label: '', pass: 1, fail: 1, total: 2, score: 50, sections: [] }],
    }
    render(<FrameworkDetail family={single} selectedVersionId="SOC2" onVersionChange={onVersionChange} />)
    expect(screen.queryByRole('tab')).not.toBeInTheDocument()
  })
})
