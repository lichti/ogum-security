import '@testing-library/jest-dom'
import { render, screen, fireEvent } from '@testing-library/react'
import { SavedViewSelector } from '@/components/ui/SavedViewSelector'
import type { SavedView } from '@/lib/types'

function makeView(overrides: Partial<SavedView> = {}): SavedView {
  return {
    key: 'view-1',
    scope: 'inventory',
    name: 'Internet-Facing Critical Assets',
    filters: {},
    columns: null,
    owner: 'system',
    is_system: true,
    pinned: false,
    created_at: '2026-01-01T00:00:00Z',
    updated_at: '2026-01-01T00:00:00Z',
    ...overrides,
  }
}

const onSelect = jest.fn()
const onPinToggle = jest.fn()
const onSaveAsNew = jest.fn()
beforeEach(() => jest.clearAllMocks())

describe('SavedViewSelector', () => {
  it('does not show a pinned section when nothing is pinned', () => {
    render(
      <SavedViewSelector
        views={[makeView()]}
        onSelect={onSelect}
        onPinToggle={onPinToggle}
        onSaveAsNew={onSaveAsNew}
      />,
    )
    expect(screen.queryByText(/Pinned Views/)).not.toBeInTheDocument()
  })

  it('shows pinned views as quick-access buttons', () => {
    render(
      <SavedViewSelector
        views={[makeView({ key: 'view-2', name: 'My Pinned View', is_system: false, owner: 'user-1', pinned: true })]}
        onSelect={onSelect}
        onPinToggle={onPinToggle}
        onSaveAsNew={onSaveAsNew}
      />,
    )
    expect(screen.getByText('Pinned Views (1)')).toBeInTheDocument()
    expect(screen.getByText('My Pinned View')).toBeInTheDocument()
  })

  it('opens the All Views dropdown listing every view', () => {
    render(
      <SavedViewSelector
        views={[makeView()]}
        onSelect={onSelect}
        onPinToggle={onPinToggle}
        onSaveAsNew={onSaveAsNew}
      />,
    )
    fireEvent.click(screen.getByText('All Views'))
    expect(screen.getByRole('listbox')).toBeInTheDocument()
    expect(screen.getByText('Internet-Facing Critical Assets')).toBeInTheDocument()
  })

  it('calls onSelect when a view in the dropdown is clicked', () => {
    const view = makeView()
    render(
      <SavedViewSelector views={[view]} onSelect={onSelect} onPinToggle={onPinToggle} onSaveAsNew={onSaveAsNew} />,
    )
    fireEvent.click(screen.getByText('All Views'))
    fireEvent.click(screen.getByText('Internet-Facing Critical Assets'))
    expect(onSelect).toHaveBeenCalledWith(view)
  })

  it('does not show a pin toggle for system views', () => {
    render(
      <SavedViewSelector
        views={[makeView()]}
        onSelect={onSelect}
        onPinToggle={onPinToggle}
        onSaveAsNew={onSaveAsNew}
      />,
    )
    fireEvent.click(screen.getByText('All Views'))
    expect(screen.queryByLabelText(/Pin Internet-Facing Critical Assets/)).not.toBeInTheDocument()
  })

  it('shows a pin toggle for user views and calls onPinToggle', () => {
    const userView = makeView({ key: 'view-3', name: 'User View', is_system: false, owner: 'user-1' })
    render(
      <SavedViewSelector
        views={[userView]}
        onSelect={onSelect}
        onPinToggle={onPinToggle}
        onSaveAsNew={onSaveAsNew}
      />,
    )
    fireEvent.click(screen.getByText('All Views'))
    fireEvent.click(screen.getByLabelText('Pin User View'))
    expect(onPinToggle).toHaveBeenCalledWith(userView)
  })

  it('reveals a name input when "Save as New" is clicked, then calls onSaveAsNew', () => {
    render(
      <SavedViewSelector views={[]} onSelect={onSelect} onPinToggle={onPinToggle} onSaveAsNew={onSaveAsNew} />,
    )
    fireEvent.click(screen.getByText('Save as New'))
    fireEvent.change(screen.getByPlaceholderText('View name'), { target: { value: 'My New View' } })
    fireEvent.click(screen.getByText('Save'))
    expect(onSaveAsNew).toHaveBeenCalledWith('My New View')
  })

  it('does not call onSaveAsNew with an empty name', () => {
    render(
      <SavedViewSelector views={[]} onSelect={onSelect} onPinToggle={onPinToggle} onSaveAsNew={onSaveAsNew} />,
    )
    fireEvent.click(screen.getByText('Save as New'))
    fireEvent.click(screen.getByText('Save'))
    expect(onSaveAsNew).not.toHaveBeenCalled()
  })
})
