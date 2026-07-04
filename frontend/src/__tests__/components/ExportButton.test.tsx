import '@testing-library/jest-dom'
import { render, screen, fireEvent } from '@testing-library/react'
import { ExportButton } from '@/components/findings/ExportButton'
import type { FindingsFilter } from '@/lib/types'

const defaultFilters: FindingsFilter = { limit: 50 }

describe('ExportButton', () => {
  it('renders export button', () => {
    render(<ExportButton filters={defaultFilters} />)
    expect(screen.getByLabelText('Export findings')).toBeInTheDocument()
  })

  it('opens dropdown when clicked', () => {
    render(<ExportButton filters={defaultFilters} />)
    fireEvent.click(screen.getByLabelText('Export findings'))
    expect(screen.getByText('CSV')).toBeInTheDocument()
    expect(screen.getByText('JSON (OCSF)')).toBeInTheDocument()
  })

  it('closes dropdown when backdrop is clicked', () => {
    render(<ExportButton filters={defaultFilters} />)
    fireEvent.click(screen.getByLabelText('Export findings'))
    expect(screen.getByText('CSV')).toBeInTheDocument()
    const backdrop = document.querySelector('[aria-hidden="true"]') as HTMLElement
    fireEvent.click(backdrop)
    expect(screen.queryByText('CSV')).not.toBeInTheDocument()
  })

  it('is not disabled by default', () => {
    render(<ExportButton filters={defaultFilters} />)
    expect(screen.getByLabelText('Export findings')).not.toBeDisabled()
  })
})
