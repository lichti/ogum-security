import '@testing-library/jest-dom'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { ProvidersTable } from '@/components/providers/ProvidersTable'
import type { ProviderConfig } from '@/lib/types'

const makeProvider = (overrides: Partial<ProviderConfig> = {}): ProviderConfig => ({
  key: 'aws-111111111111',
  provider: 'aws',
  display_name: 'Production AWS',
  account_id: '111111111111',
  regions: ['us-east-1', 'eu-west-1'],
  enabled: true,
  status: 'active',
  credential_type: 'role',
  last_discovery_at: new Date(Date.now() - 30 * 60 * 1000).toISOString(),
  created_at: new Date().toISOString(),
  ...overrides,
})

const noop = jest.fn().mockResolvedValue(undefined)

describe('ProvidersTable', () => {
  beforeEach(() => jest.clearAllMocks())

  it('renders empty state when no providers', () => {
    render(<ProvidersTable providers={[]} onToggle={noop} onDiscover={noop} onDelete={noop} />)
    expect(screen.getByText(/no cloud accounts connected/i)).toBeInTheDocument()
  })

  it('renders provider row with all columns', () => {
    render(<ProvidersTable providers={[makeProvider()]} onToggle={noop} onDiscover={noop} onDelete={noop} />)
    expect(screen.getByText('Production AWS')).toBeInTheDocument()
    expect(screen.getByText('111111111111')).toBeInTheDocument()
    expect(screen.getByText('AWS')).toBeInTheDocument()
  })

  it('shows Active status badge for active provider', () => {
    render(<ProvidersTable providers={[makeProvider({ status: 'active' })]} onToggle={noop} onDiscover={noop} onDelete={noop} />)
    expect(screen.getByText('Active')).toBeInTheDocument()
  })

  it('shows Disabled status badge for disabled provider', () => {
    render(<ProvidersTable providers={[makeProvider({ status: 'disabled', enabled: false })]} onToggle={noop} onDiscover={noop} onDelete={noop} />)
    expect(screen.getByText('Disabled')).toBeInTheDocument()
  })

  it('shows Pending status badge for pending provider', () => {
    render(<ProvidersTable providers={[makeProvider({ status: 'pending' })]} onToggle={noop} onDiscover={noop} onDelete={noop} />)
    expect(screen.getByText('Pending')).toBeInTheDocument()
  })

  it('truncates regions and shows overflow count', () => {
    const provider = makeProvider({ regions: ['us-east-1', 'eu-west-1', 'ap-southeast-1'] })
    render(<ProvidersTable providers={[provider]} onToggle={noop} onDiscover={noop} onDelete={noop} />)
    expect(screen.getByText(/\+1/)).toBeInTheDocument()
  })

  it('calls onDiscover when refresh button is clicked', async () => {
    const onDiscover = jest.fn().mockResolvedValue(undefined)
    render(<ProvidersTable providers={[makeProvider()]} onToggle={noop} onDiscover={onDiscover} onDelete={noop} />)
    fireEvent.click(screen.getByTitle('Re-trigger discovery'))
    await waitFor(() => expect(onDiscover).toHaveBeenCalledWith('aws-111111111111'))
  })

  it('calls onDelete when delete button is clicked', async () => {
    const onDelete = jest.fn().mockResolvedValue(undefined)
    render(<ProvidersTable providers={[makeProvider()]} onToggle={noop} onDiscover={noop} onDelete={onDelete} />)
    fireEvent.click(screen.getByTitle('Delete provider'))
    await waitFor(() => expect(onDelete).toHaveBeenCalledWith('aws-111111111111'))
  })

  it('calls onToggle with false when disable button clicked on enabled provider', async () => {
    const onToggle = jest.fn().mockResolvedValue(undefined)
    render(<ProvidersTable providers={[makeProvider({ enabled: true })]} onToggle={onToggle} onDiscover={noop} onDelete={noop} />)
    fireEvent.click(screen.getByTitle('Disable provider'))
    await waitFor(() => expect(onToggle).toHaveBeenCalledWith('aws-111111111111', false))
  })

  it('calls onToggle with true when enable button clicked on disabled provider', async () => {
    const onToggle = jest.fn().mockResolvedValue(undefined)
    render(<ProvidersTable providers={[makeProvider({ enabled: false, status: 'disabled' })]} onToggle={onToggle} onDiscover={noop} onDelete={noop} />)
    fireEvent.click(screen.getByTitle('Enable provider'))
    await waitFor(() => expect(onToggle).toHaveBeenCalledWith('aws-111111111111', true))
  })

  it('discover button is disabled when provider is disabled', () => {
    render(
      <ProvidersTable
        providers={[makeProvider({ enabled: false, status: 'disabled' })]}
        onToggle={noop}
        onDiscover={noop}
        onDelete={noop}
      />
    )
    expect(screen.getByTitle('Re-trigger discovery')).toBeDisabled()
  })

  it('renders multiple providers', () => {
    const providers = [
      makeProvider({ key: 'aws-111', provider: 'aws', display_name: 'AWS Prod' }),
      makeProvider({ key: 'azure-sub-aaa', provider: 'azure', display_name: 'Azure Dev', subscription_id: 'sub-aaa-bbb', account_id: null }),
    ]
    render(<ProvidersTable providers={providers} onToggle={noop} onDiscover={noop} onDelete={noop} />)
    expect(screen.getByText('AWS Prod')).toBeInTheDocument()
    expect(screen.getByText('Azure Dev')).toBeInTheDocument()
  })

  it('shows last discovery as relative time', () => {
    const provider = makeProvider({ last_discovery_at: new Date(Date.now() - 5 * 60 * 1000).toISOString() })
    render(<ProvidersTable providers={[provider]} onToggle={noop} onDiscover={noop} onDelete={noop} />)
    expect(screen.getByText('5m ago')).toBeInTheDocument()
  })

  it('shows — when last_discovery_at is null', () => {
    const provider = makeProvider({ last_discovery_at: null })
    render(<ProvidersTable providers={[provider]} onToggle={noop} onDiscover={noop} onDelete={noop} />)
    const cells = screen.getAllByText('—')
    expect(cells.length).toBeGreaterThan(0)
  })
})
