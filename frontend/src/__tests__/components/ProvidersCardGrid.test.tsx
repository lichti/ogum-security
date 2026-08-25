import '@testing-library/jest-dom'
import { render, screen, fireEvent, waitFor } from '@testing-library/react'
import { ProvidersCardGrid, HealthBadge } from '@/components/providers/ProvidersCardGrid'
import type { ProviderConfig, ProviderHealth } from '@/lib/types'

function makeProvider(overrides: Partial<ProviderConfig> = {}): ProviderConfig {
  return {
    key: 'aws-111111111111',
    provider: 'aws',
    display_name: 'Dev AWS Account',
    account_id: '111111111111',
    regions: ['us-east-1'],
    enabled: true,
    status: 'active',
    credential_type: 'role',
    last_discovery_at: new Date().toISOString(),
    created_at: new Date().toISOString(),
    ...overrides,
  }
}

const noop = () => Promise.resolve()

const testConnectionNoop = (): Promise<ProviderHealth> => Promise.resolve({} as ProviderHealth)

describe('ProvidersCardGrid', () => {
  it('shows empty state when no providers', () => {
    render(<ProvidersCardGrid providers={[]} onEdit={jest.fn()} onToggle={noop} onDiscover={noop} onScan={noop} onDelete={noop} onTestConnection={testConnectionNoop} />)
    expect(screen.getByTestId('providers-empty')).toBeInTheDocument()
  })

  it('groups providers by cloud with an account count', () => {
    const providers = [
      makeProvider({ key: 'aws-1' }),
      makeProvider({ key: 'aws-2' }),
      makeProvider({ key: 'azure-sub-1', provider: 'azure', subscription_id: 'sub-1' }),
    ]
    render(<ProvidersCardGrid providers={providers} onEdit={jest.fn()} onToggle={noop} onDiscover={noop} onScan={noop} onDelete={noop} onTestConnection={testConnectionNoop} />)

    expect(screen.getByTestId('provider-count-aws')).toHaveTextContent('(2 accounts)')
    expect(screen.getByTestId('provider-count-azure')).toHaveTextContent('(1 account)')
    expect(screen.queryByTestId('provider-count-gcp')).not.toBeInTheDocument()
    expect(screen.getByTestId('provider-card-aws-1')).toBeInTheDocument()
    expect(screen.getByTestId('provider-card-azure-sub-1')).toBeInTheDocument()
  })

  it('renders healthy badge for an active enabled provider before any test runs', () => {
    render(
      <ProvidersCardGrid
        providers={[makeProvider()]}
        onEdit={jest.fn()}
        onToggle={noop}
        onDiscover={noop}
        onScan={noop}
        onDelete={noop}
        onTestConnection={testConnectionNoop}
      />,
    )
    const badges = screen.getAllByTestId('health-badge-healthy')
    expect(badges.length).toBeGreaterThan(0)
  })

  it('renders failed badge when stored status is error', () => {
    render(
      <ProvidersCardGrid
        providers={[makeProvider({ status: 'error' })]}
        onEdit={jest.fn()}
        onToggle={noop}
        onDiscover={noop}
        onScan={noop}
        onDelete={noop}
        onTestConnection={testConnectionNoop}
      />,
    )
    expect(screen.getByTestId('health-badge-failed')).toBeInTheDocument()
  })

  it('calls onTestConnection and renders the live result', async () => {
    const result: ProviderHealth = {
      provider_id: 'aws-1',
      health: 'healthy',
      status: 'active',
      enabled: true,
      detail: 'AWS account 111111111111 reachable via sts:GetCallerIdentity',
      latency_ms: 240,
      live: true,
    }
    render(
      <ProvidersCardGrid
        providers={[makeProvider({ key: 'aws-1' })]}
        onEdit={jest.fn()}
        onToggle={noop}
        onDiscover={noop}
        onScan={noop}
        onDelete={noop}
        onTestConnection={() => Promise.resolve(result)}
      />,
    )

    fireEvent.click(screen.getByTestId('test-connection-aws-1'))
    await waitFor(() => {
      const el = screen.getByTestId('test-result-aws-1')
      expect(el).toHaveTextContent(/Connected/)
      expect(el).toHaveTextContent('240ms')
    })
  })

  it('renders the failure detail when the probe fails', async () => {
    const result: ProviderHealth = {
      provider_id: 'aws-2',
      health: 'failed',
      status: 'error',
      enabled: true,
      reason: 'connection test failed',
      detail: 'ClientError: ExpiredToken',
      live: true,
    }
    render(
      <ProvidersCardGrid
        providers={[makeProvider({ key: 'aws-2' })]}
        onEdit={jest.fn()}
        onToggle={noop}
        onDiscover={noop}
        onScan={noop}
        onDelete={noop}
        onTestConnection={() => Promise.resolve(result)}
      />,
    )

    fireEvent.click(screen.getByTestId('test-connection-aws-2'))
    await waitFor(() => {
      expect(screen.getByTestId('test-result-aws-2')).toHaveTextContent(/Connection failed/)
    })
  })
})

describe('HealthBadge', () => {
  it.each([
    ['healthy'],
    ['degraded'],
    ['failed'],
  ] as const)('renders the %s variant', (level) => {
    render(<HealthBadge health={level} />)
    expect(screen.getByTestId(`health-badge-${level}`)).toBeInTheDocument()
  })
})
