import '@testing-library/jest-dom'
import { render, screen, fireEvent } from '@testing-library/react'
import { CollapsibleSection } from '@/components/ui/CollapsibleSection'

describe('CollapsibleSection', () => {
  it('renders the title and children, open by default', () => {
    render(
      <CollapsibleSection title="Sections (12)">
        <p>body content</p>
      </CollapsibleSection>,
    )
    expect(screen.getByText('Sections (12)')).toBeInTheDocument()
    expect(screen.getByText('body content')).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /Sections \(12\)/ })).toHaveAttribute('aria-expanded', 'true')
  })

  it('hides children and flips aria-expanded when the header is clicked', () => {
    render(
      <CollapsibleSection title="Requirements">
        <p>body content</p>
      </CollapsibleSection>,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Requirements' }))
    expect(screen.queryByText('body content')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Requirements' })).toHaveAttribute('aria-expanded', 'false')
  })

  it('shows children again on a second click', () => {
    render(
      <CollapsibleSection title="Requirements">
        <p>body content</p>
      </CollapsibleSection>,
    )
    const header = screen.getByRole('button', { name: 'Requirements' })
    fireEvent.click(header)
    fireEvent.click(header)
    expect(screen.getByText('body content')).toBeInTheDocument()
    expect(header).toHaveAttribute('aria-expanded', 'true')
  })

  it('respects defaultOpen=false', () => {
    render(
      <CollapsibleSection title="Requirements" defaultOpen={false}>
        <p>body content</p>
      </CollapsibleSection>,
    )
    expect(screen.queryByText('body content')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Requirements' })).toHaveAttribute('aria-expanded', 'false')
  })

  it('keeps headerExtra visible and interactive regardless of open state', () => {
    const onExtraClick = jest.fn()
    render(
      <CollapsibleSection
        title="Top 10 Findings"
        headerExtra={
          <button type="button" onClick={onExtraClick}>
            Filter
          </button>
        }
      >
        <p>body content</p>
      </CollapsibleSection>,
    )
    fireEvent.click(screen.getByRole('button', { name: 'Top 10 Findings' }))
    expect(screen.queryByText('body content')).not.toBeInTheDocument()

    const extraButton = screen.getByRole('button', { name: 'Filter' })
    expect(extraButton).toBeInTheDocument()
    fireEvent.click(extraButton)
    expect(onExtraClick).toHaveBeenCalledTimes(1)
  })
})
