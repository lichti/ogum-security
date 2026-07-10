import '@testing-library/jest-dom'
import { render, screen, fireEvent } from '@testing-library/react'
import { MultiSelectFilter } from '@/components/inventory/MultiSelectFilter'

const options = [
  { value: 'aws', label: 'AWS', count: 10 },
  { value: 'azure', label: 'Azure', count: 3 },
]

const onChange = jest.fn()
beforeEach(() => jest.clearAllMocks())

describe('MultiSelectFilter', () => {
  it('shows "All {label}" when nothing is selected', () => {
    render(<MultiSelectFilter label="Providers" options={options} selected={[]} onChange={onChange} />)
    expect(screen.getByText('All Providers')).toBeInTheDocument()
  })

  it('shows the option label when exactly one is selected', () => {
    render(<MultiSelectFilter label="Providers" options={options} selected={['aws']} onChange={onChange} />)
    expect(screen.getByText('AWS')).toBeInTheDocument()
  })

  it('shows a count summary when multiple are selected', () => {
    render(<MultiSelectFilter label="Providers" options={options} selected={['aws', 'azure']} onChange={onChange} />)
    expect(screen.getByText('2 Providers')).toBeInTheDocument()
  })

  it('opens the dropdown and lists all options with counts', () => {
    render(<MultiSelectFilter label="Providers" options={options} selected={[]} onChange={onChange} />)
    fireEvent.click(screen.getByText('All Providers'))
    expect(screen.getByRole('listbox')).toBeInTheDocument()
    expect(screen.getByText('10')).toBeInTheDocument()
    expect(screen.getByText('3')).toBeInTheDocument()
  })

  it('adds a value when an unselected option is checked', () => {
    render(<MultiSelectFilter label="Providers" options={options} selected={[]} onChange={onChange} />)
    fireEvent.click(screen.getByText('All Providers'))
    fireEvent.click(screen.getByText('AWS'))
    expect(onChange).toHaveBeenCalledWith(['aws'])
  })

  it('removes a value when a selected option is unchecked', () => {
    render(<MultiSelectFilter label="Providers" options={options} selected={['aws', 'azure']} onChange={onChange} />)
    fireEvent.click(screen.getByText('2 Providers'))
    fireEvent.click(screen.getByText('AWS'))
    expect(onChange).toHaveBeenCalledWith(['azure'])
  })

  it('clears the selection when "All" is clicked', () => {
    render(<MultiSelectFilter label="Providers" options={options} selected={['aws']} onChange={onChange} />)
    fireEvent.click(screen.getByText('AWS'))
    fireEvent.click(screen.getByText('All Providers'))
    expect(onChange).toHaveBeenCalledWith([])
  })

  it('renders "No options" when the list is empty', () => {
    render(<MultiSelectFilter label="Regions" options={[]} selected={[]} onChange={onChange} />)
    fireEvent.click(screen.getByText('All Regions'))
    expect(screen.getByText('No options')).toBeInTheDocument()
  })
})
