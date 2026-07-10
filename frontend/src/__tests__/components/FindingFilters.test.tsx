import '@testing-library/jest-dom'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { FindingFilters } from '@/components/findings/FindingFilters'
import type { FindingsFilter } from '@/lib/types'

const onChange = jest.fn()
beforeEach(() => jest.clearAllMocks())

describe('FindingFilters', () => {
  it('renders a multi-select for severity, status, provider, framework, and source', () => {
    render(<FindingFilters filters={{ limit: 50 }} onChange={onChange} />)
    expect(screen.getByText('All Severities')).toBeInTheDocument()
    expect(screen.getByText('All Statuses')).toBeInTheDocument()
    expect(screen.getByText('All Providers')).toBeInTheDocument()
    expect(screen.getByText('All Frameworks')).toBeInTheDocument()
    expect(screen.getByText('All Sources')).toBeInTheDocument()
  })

  it('reflects an already-selected severity in the button label', () => {
    render(<FindingFilters filters={{ limit: 50, severity: ['CRITICAL'] }} onChange={onChange} />)
    expect(screen.getByText('CRITICAL')).toBeInTheDocument()
  })

  it('selecting a severity option calls onChange with it added', () => {
    render(<FindingFilters filters={{ limit: 50 }} onChange={onChange} />)
    fireEvent.click(screen.getByText('All Severities'))
    fireEvent.click(screen.getByText('HIGH'))
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ severity: ['HIGH'], cursor: undefined }),
    )
  })

  it('selecting multiple providers accumulates the selection', () => {
    const filters: FindingsFilter = { limit: 50, provider: ['aws'] }
    render(<FindingFilters filters={filters} onChange={onChange} />)
    fireEvent.click(screen.getByText('AWS'))
    fireEvent.click(screen.getByText('AZURE'))
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({ provider: ['aws', 'azure'] }),
    )
  })

  it('debounces the search input before calling onChange', async () => {
    render(<FindingFilters filters={{ limit: 50 }} onChange={onChange} />)
    fireEvent.change(screen.getByLabelText('Search findings'), { target: { value: 'macie' } })
    expect(onChange).not.toHaveBeenCalled()
    await waitFor(() => expect(onChange).toHaveBeenCalledWith(expect.objectContaining({ q: 'macie' })), {
      timeout: 1000,
    })
  })

  it('shows "Clear filters" only when a filter is active, and clears everything on click', () => {
    render(
      <FindingFilters filters={{ limit: 50, severity: ['CRITICAL'], provider: ['aws'] }} onChange={onChange} />,
    )
    const clearBtn = screen.getByText('Clear filters')
    fireEvent.click(clearBtn)
    expect(onChange).toHaveBeenCalledWith(
      expect.objectContaining({
        severity: undefined,
        status: undefined,
        provider: undefined,
        framework: undefined,
        source: undefined,
        q: undefined,
      }),
    )
  })

  it('does not show "Clear filters" when no filter is active', () => {
    render(<FindingFilters filters={{ limit: 50 }} onChange={onChange} />)
    expect(screen.queryByText('Clear filters')).not.toBeInTheDocument()
  })
})
