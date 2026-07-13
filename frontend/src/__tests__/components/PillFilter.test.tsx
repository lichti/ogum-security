import '@testing-library/jest-dom'
import { render, screen, fireEvent } from '@testing-library/react'
import { PillFilter } from '@/components/ui/PillFilter'

const options = [
  { value: 'ec2', label: 'EC2 Instance', count: 1204 },
  { value: 's3', label: 'S3 Bucket', count: 483 },
]

const onApply = jest.fn()
beforeEach(() => jest.clearAllMocks())

describe('PillFilter', () => {
  it('renders the label on the pill button', () => {
    render(<PillFilter label="Type or Category" options={options} selected={[]} onApply={onApply} />)
    expect(screen.getByText('Type or Category')).toBeInTheDocument()
  })

  it('opens the popover with search, options, and counts', () => {
    render(<PillFilter label="Type or Category" options={options} selected={[]} onApply={onApply} />)
    fireEvent.click(screen.getByText('Type or Category'))
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(screen.getByPlaceholderText('Search...')).toBeInTheDocument()
    expect(screen.getByText('EC2 Instance')).toBeInTheDocument()
    expect(screen.getByText('1,204')).toBeInTheDocument()
  })

  it('does not apply on checkbox click alone — only on Apply', () => {
    render(<PillFilter label="Type or Category" options={options} selected={[]} onApply={onApply} />)
    fireEvent.click(screen.getByText('Type or Category'))
    fireEvent.click(screen.getByText('EC2 Instance'))
    expect(onApply).not.toHaveBeenCalled()
  })

  it('applies the selected values and default operator when Apply is clicked', () => {
    render(<PillFilter label="Type or Category" options={options} selected={[]} onApply={onApply} />)
    fireEvent.click(screen.getByText('Type or Category'))
    fireEvent.click(screen.getByText('EC2 Instance'))
    fireEvent.click(screen.getByText('Apply'))
    expect(onApply).toHaveBeenCalledWith(['ec2'], 'is')
  })

  it('clears the selection immediately when Clear is clicked', () => {
    render(<PillFilter label="Type or Category" options={options} selected={['ec2']} onApply={onApply} />)
    fireEvent.click(screen.getByText('Type or Category'))
    fireEvent.click(screen.getByText('Clear'))
    expect(onApply).toHaveBeenCalledWith([], 'is')
  })

  it('filters options via the search box', () => {
    render(<PillFilter label="Type or Category" options={options} selected={[]} onApply={onApply} />)
    fireEvent.click(screen.getByText('Type or Category'))
    fireEvent.change(screen.getByPlaceholderText('Search...'), { target: { value: 'ec2' } })
    expect(screen.getByText('EC2 Instance')).toBeInTheDocument()
    expect(screen.queryByText('S3 Bucket')).not.toBeInTheDocument()
  })

  it('shows an operator dropdown when multiple operators are provided', () => {
    render(
      <PillFilter
        label="Crown Jewel"
        options={options}
        selected={[]}
        operators={['is', 'is_not']}
        onApply={onApply}
      />,
    )
    fireEvent.click(screen.getByText('Crown Jewel'))
    expect(screen.getByLabelText('Operator')).toBeInTheDocument()
  })

  it('hides the operator dropdown when only one operator is available', () => {
    render(<PillFilter label="Crown Jewel" options={options} selected={[]} onApply={onApply} />)
    fireEvent.click(screen.getByText('Crown Jewel'))
    expect(screen.queryByLabelText('Operator')).not.toBeInTheDocument()
  })

  it('applies orange active styling when a filter has selected values', () => {
    render(<PillFilter label="Type or Category" options={options} selected={['ec2']} onApply={onApply} />)
    expect(screen.getByText('Type or Category').closest('button')?.className).toMatch(/orange/)
  })

  it('selects all options when "Select All" is checked', () => {
    render(<PillFilter label="Type or Category" options={options} selected={[]} onApply={onApply} />)
    fireEvent.click(screen.getByText('Type or Category'))
    fireEvent.click(screen.getByText(/Select All/))
    fireEvent.click(screen.getByText('Apply'))
    expect(onApply).toHaveBeenCalledWith(['ec2', 's3'], 'is')
  })
})
