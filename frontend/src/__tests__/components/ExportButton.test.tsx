import '@testing-library/jest-dom'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { ExportButton } from '@/components/findings/ExportButton'
import { apiClient } from '@/lib/api'
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

  it('appends each selected multi-value filter as a repeated query param', async () => {
    const getSpy = jest
      .spyOn(apiClient, 'get')
      .mockResolvedValue({ data: new Blob(), headers: {} })
    const filters: FindingsFilter = { limit: 50, severity: ['CRITICAL', 'HIGH'], provider: ['aws'] }

    render(<ExportButton filters={filters} />)
    fireEvent.click(screen.getByLabelText('Export findings'))
    fireEvent.click(screen.getByText('CSV'))

    await waitFor(() => expect(getSpy).toHaveBeenCalled())
    const calledUrl = getSpy.mock.calls[0][0] as string
    expect(calledUrl).toContain('severity=CRITICAL')
    expect(calledUrl).toContain('severity=HIGH')
    expect(calledUrl).toContain('provider=aws')

    getSpy.mockRestore()
  })
})
