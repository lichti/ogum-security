import '@testing-library/jest-dom'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { TriggerScanModal } from '@/components/scans/TriggerScanModal'
import { scansApi } from '@/lib/api'
import type { ProviderConfig } from '@/lib/types'

jest.mock('@/lib/api', () => ({
  scansApi: { trigger: jest.fn() },
}))

const mockTrigger = scansApi.trigger as jest.Mock

function renderWithClient(ui: React.ReactElement) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
  return render(ui, { wrapper: Wrapper })
}

function makeProvider(overrides: Partial<ProviderConfig> = {}): ProviderConfig {
  return {
    key: 'aws-111111111111',
    provider: 'aws',
    display_name: 'Production AWS',
    account_id: '111111111111',
    regions: ['us-east-1'],
    enabled: true,
    status: 'active',
    credential_type: 'role',
    created_at: '2026-07-01T00:00:00Z',
    ...overrides,
  }
}

beforeEach(() => jest.clearAllMocks())

describe('TriggerScanModal', () => {
  it('shows a message instead of the form when there are no connected providers', () => {
    renderWithClient(<TriggerScanModal providers={[]} onClose={jest.fn()} onTriggered={jest.fn()} />)
    expect(screen.getByText(/No cloud provider connected yet/)).toBeInTheDocument()
    expect(screen.queryByLabelText('Cloud provider')).not.toBeInTheDocument()
  })

  it('lists every connected provider in the picker, defaulting to the first', () => {
    const providers = [makeProvider(), makeProvider({ key: 'azure-1', provider: 'azure', display_name: 'Prod Azure' })]
    renderWithClient(<TriggerScanModal providers={providers} onClose={jest.fn()} onTriggered={jest.fn()} />)

    expect(screen.getByText('Production AWS (AWS)')).toBeInTheDocument()
    expect(screen.getByText('Prod Azure (AZURE)')).toBeInTheDocument()
    expect(screen.getByLabelText('Cloud provider')).toHaveValue('aws-111111111111')
  })

  it('triggers a scan for the selected provider and calls onTriggered + onClose', async () => {
    mockTrigger.mockResolvedValue({ data: { data: { job_id: 'job-new', status: 'queued' } } })
    const onTriggered = jest.fn()
    const onClose = jest.fn()
    renderWithClient(
      <TriggerScanModal providers={[makeProvider()]} onClose={onClose} onTriggered={onTriggered} />,
    )

    fireEvent.click(screen.getByRole('button', { name: 'Start Scan' }))

    await waitFor(() => expect(mockTrigger).toHaveBeenCalledWith({ provider_id: 'aws-111111111111' }))
    await waitFor(() => expect(onTriggered).toHaveBeenCalled())
    expect(onClose).toHaveBeenCalled()
  })

  it('shows an error message when triggering fails, without closing the modal', async () => {
    mockTrigger.mockRejectedValue(new Error('network error'))
    const onClose = jest.fn()
    renderWithClient(<TriggerScanModal providers={[makeProvider()]} onClose={onClose} onTriggered={jest.fn()} />)

    fireEvent.click(screen.getByRole('button', { name: 'Start Scan' }))

    expect(await screen.findByText(/Failed to trigger scan/)).toBeInTheDocument()
    expect(onClose).not.toHaveBeenCalled()
  })

  it('closes on Cancel and on backdrop click, without triggering a scan', () => {
    const onClose = jest.fn()
    renderWithClient(<TriggerScanModal providers={[makeProvider()]} onClose={onClose} onTriggered={jest.fn()} />)

    fireEvent.click(screen.getByRole('button', { name: 'Cancel' }))
    expect(onClose).toHaveBeenCalledTimes(1)

    fireEvent.click(document.querySelector('[aria-hidden="true"]') as HTMLElement)
    expect(onClose).toHaveBeenCalledTimes(2)
    expect(mockTrigger).not.toHaveBeenCalled()
  })

  it('clicking inside the modal does not close it', () => {
    const onClose = jest.fn()
    renderWithClient(<TriggerScanModal providers={[makeProvider()]} onClose={onClose} onTriggered={jest.fn()} />)

    fireEvent.click(screen.getByTestId('trigger-scan-modal'))
    expect(onClose).not.toHaveBeenCalled()
  })
})
