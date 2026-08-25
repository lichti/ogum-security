import '@testing-library/jest-dom'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import ComplianceSettingsPage from '@/app/settings/compliance/page'
import { settingsApi } from '@/lib/api'
import type { ComplianceFamilySettingsView } from '@/lib/types'

jest.mock('@/lib/api', () => ({
  settingsApi: { listCompliance: jest.fn(), updateCompliance: jest.fn() },
}))

const mockList = settingsApi.listCompliance as jest.Mock
const mockUpdate = settingsApi.updateCompliance as jest.Mock

function renderWithClient() {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
  return render(<ComplianceSettingsPage />, { wrapper: Wrapper })
}

function row(overrides: Partial<ComplianceFamilySettingsView> = {}): ComplianceFamilySettingsView {
  return {
    family_key: 'cis-aws',
    family_label: 'CIS AWS Foundations Benchmark',
    enabled: true,
    target_by_control: null,
    ...overrides,
  }
}

beforeEach(() => jest.clearAllMocks())

describe('ComplianceSettingsPage', () => {
  it('shows an empty state when no framework has been discovered yet', async () => {
    mockList.mockResolvedValue({ data: { data: [] } })
    renderWithClient()
    expect(await screen.findByText(/No frameworks discovered yet/)).toBeInTheDocument()
  })

  it('renders one row per framework with its label and current targets', async () => {
    mockList.mockResolvedValue({ data: { data: [row(), row({ family_key: 'gdpr', family_label: 'GDPR' })] } })
    renderWithClient()
    expect(await screen.findByText('CIS AWS Foundations Benchmark')).toBeInTheDocument()
    expect(screen.getByText('GDPR')).toBeInTheDocument()
  })

  it('toggles enabled immediately, without a Save click', async () => {
    mockList.mockResolvedValue({ data: { data: [row({ enabled: true })] } })
    mockUpdate.mockResolvedValue({ data: { data: row({ enabled: false }) } })
    renderWithClient()

    const checkbox = await screen.findByRole('checkbox')
    expect(checkbox).toBeChecked()

    fireEvent.click(checkbox)
    expect(checkbox).not.toBeChecked() // optimistic flip, before the mutation resolves
    await waitFor(() => expect(mockUpdate).toHaveBeenCalledWith('cis-aws', { enabled: false }))
  })

  it('rolls back the enabled toggle if the update fails', async () => {
    mockList.mockResolvedValue({ data: { data: [row({ enabled: true })] } })
    mockUpdate.mockRejectedValue(new Error('network error'))
    renderWithClient()

    const checkbox = await screen.findByRole('checkbox')
    fireEvent.click(checkbox)
    await waitFor(() => expect(checkbox).toBeChecked())
  })

  it('shows a Save button only after a target is edited, and sends the new value', async () => {
    mockList.mockResolvedValue({ data: { data: [row()] } })
    mockUpdate.mockResolvedValue({ data: { data: row({ target_by_control: 90 }) } })
    renderWithClient()

    await screen.findByText('CIS AWS Foundations Benchmark')
    expect(screen.queryByRole('button', { name: 'Save' })).not.toBeInTheDocument()

    const controlInput = screen.getByPlaceholderText('—')
    fireEvent.change(controlInput, { target: { value: '90' } })

    const saveButton = await screen.findByRole('button', { name: 'Save' })
    fireEvent.click(saveButton)

    await waitFor(() =>
      expect(mockUpdate).toHaveBeenCalledWith('cis-aws', {
        target_by_control: 90,
        clear_target_by_control: false,
      }),
    )
  })

  it('clearing a previously-set target sends the clear flag instead of a value', async () => {
    mockList.mockResolvedValue({ data: { data: [row({ target_by_control: 90 })] } })
    mockUpdate.mockResolvedValue({ data: { data: row({ target_by_control: null }) } })
    renderWithClient()

    const controlInput = await screen.findByDisplayValue('90')
    fireEvent.change(controlInput, { target: { value: '' } })

    fireEvent.click(await screen.findByRole('button', { name: 'Save' }))

    await waitFor(() =>
      expect(mockUpdate).toHaveBeenCalledWith(
        'cis-aws',
        expect.objectContaining({ target_by_control: undefined, clear_target_by_control: true }),
      ),
    )
  })
})
