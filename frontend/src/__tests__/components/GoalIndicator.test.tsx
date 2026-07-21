import '@testing-library/jest-dom'
import { render, screen, fireEvent } from '@testing-library/react'
import { GoalIndicator } from '@/components/compliance/GoalIndicator'

const baseProps = {
  score: 70,
  target: null as number | null,
}

describe('GoalIndicator — read-only mode (no onSetTarget)', () => {
  it('renders nothing when no target is configured', () => {
    const { container } = render(<GoalIndicator {...baseProps} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('renders a static (non-interactive) goal marker when a target is configured', () => {
    render(<GoalIndicator {...baseProps} target={60} />)
    const marker = screen.getByText('✓ Goal 60%')
    expect(marker.tagName).toBe('DIV')
  })
})

describe('GoalIndicator — editable mode (onSetTarget provided)', () => {
  it('shows a visible "+ Set goal" affordance when no target is configured', () => {
    const onSetTarget = jest.fn()
    render(<GoalIndicator {...baseProps} onSetTarget={onSetTarget} />)
    expect(screen.getByRole('button', { name: 'Set control goal' })).toBeInTheDocument()
  })

  it('clicking "+ Set goal" opens an editor; saving calls onSetTarget with the parsed value', () => {
    const onSetTarget = jest.fn()
    render(<GoalIndicator {...baseProps} onSetTarget={onSetTarget} />)

    fireEvent.click(screen.getByRole('button', { name: 'Set control goal' }))
    const input = screen.getByLabelText('control goal percentage')
    fireEvent.change(input, { target: { value: '85' } })
    fireEvent.click(screen.getByLabelText('Save goal'))

    expect(onSetTarget).toHaveBeenCalledWith(85)
  })

  it('pressing Enter in the input saves the goal', () => {
    const onSetTarget = jest.fn()
    render(<GoalIndicator {...baseProps} onSetTarget={onSetTarget} />)

    fireEvent.click(screen.getByRole('button', { name: 'Set control goal' }))
    const input = screen.getByLabelText('control goal percentage')
    fireEvent.change(input, { target: { value: '75' } })
    fireEvent.keyDown(input, { key: 'Enter' })

    expect(onSetTarget).toHaveBeenCalledWith(75)
  })

  it('clamps out-of-range input to 0–100', () => {
    const onSetTarget = jest.fn()
    render(<GoalIndicator {...baseProps} onSetTarget={onSetTarget} />)

    fireEvent.click(screen.getByRole('button', { name: 'Set control goal' }))
    const input = screen.getByLabelText('control goal percentage')
    fireEvent.change(input, { target: { value: '150' } })
    fireEvent.click(screen.getByLabelText('Save goal'))

    expect(onSetTarget).toHaveBeenCalledWith(100)
  })

  it('pressing Escape cancels the edit without calling onSetTarget', () => {
    const onSetTarget = jest.fn()
    render(<GoalIndicator {...baseProps} onSetTarget={onSetTarget} />)

    fireEvent.click(screen.getByRole('button', { name: 'Set control goal' }))
    const input = screen.getByLabelText('control goal percentage')
    fireEvent.change(input, { target: { value: '85' } })
    fireEvent.keyDown(input, { key: 'Escape' })

    expect(onSetTarget).not.toHaveBeenCalled()
    expect(screen.queryByLabelText('control goal percentage')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Set control goal' })).toBeInTheDocument()
  })

  it('clicking an existing goal opens the editor pre-filled with the current value', () => {
    const onSetTarget = jest.fn()
    render(<GoalIndicator {...baseProps} target={60} onSetTarget={onSetTarget} />)

    fireEvent.click(screen.getByRole('button', { name: 'Edit control goal' }))
    expect(screen.getByLabelText('control goal percentage')).toHaveValue(60)
  })

  it('"clear" removes an existing goal by calling onSetTarget with null', () => {
    const onSetTarget = jest.fn()
    render(<GoalIndicator {...baseProps} target={60} onSetTarget={onSetTarget} />)

    fireEvent.click(screen.getByRole('button', { name: 'Edit control goal' }))
    fireEvent.click(screen.getByRole('button', { name: 'Clear goal' }))

    expect(onSetTarget).toHaveBeenCalledWith(null)
  })

  it('disables the input and buttons while saving', () => {
    const onSetTarget = jest.fn()
    render(<GoalIndicator {...baseProps} target={60} onSetTarget={onSetTarget} saving />)

    fireEvent.click(screen.getByRole('button', { name: 'Edit control goal' }))
    expect(screen.getByLabelText('control goal percentage')).toBeDisabled()
    expect(screen.getByLabelText('Save goal')).toBeDisabled()
  })
})
