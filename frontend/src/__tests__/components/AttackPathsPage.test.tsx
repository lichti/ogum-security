import '@testing-library/jest-dom'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'

// React Flow needs ResizeObserver
global.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

jest.mock('@/lib/api', () => ({
  attackPathsApi: {
    stats: jest.fn().mockResolvedValue({
      data: {
        data: {
          total: 2,
          by_severity: { CRITICAL: 1, HIGH: 1, MEDIUM: 0, LOW: 0 },
          new_24h: 0,
          by_target_asset_category: {},
          by_target_crown_jewel_reason: {},
        },
      },
    }),
    list: jest.fn().mockResolvedValue({
      data: {
        data: {
          items: [
            {
              _key: 'p1',
              path_id: 'p1',
              tenant_id: 't1',
              rule: 'TC-02',
              entry_point_id: 'resources/ep1',
              entry_point_type: 'aws_s3_bucket',
              entry_point_name: 'public-bucket',
              target_id: 'data_assets/tgt1',
              target_type: 'aws_s3_bucket',
              target_name: 'public-bucket',
              hops: 0,
              path_vertex_ids: ['resources/ep1'],
              risk_score: 90,
              severity: 'CRITICAL',
              is_toxic_combination: true,
              detected_at: '2026-01-01T00:00:00Z',
              status: 'active',
              target_asset_category: 'storage',
            },
            {
              _key: 'p2',
              path_id: 'p2',
              tenant_id: 't1',
              rule: 'privilege_escalation',
              entry_point_id: 'identities/u1',
              entry_point_type: 'iam_user',
              entry_point_name: 'dev-user',
              target_id: 'identities/admin',
              target_type: 'iam_role',
              target_name: 'AdminRole',
              hops: 1,
              path_vertex_ids: ['identities/u1', 'identities/admin'],
              risk_score: 70,
              severity: 'HIGH',
              is_toxic_combination: false,
              detected_at: '2026-01-01T00:00:00Z',
              status: 'active',
              target_asset_category: 'security_identity',
            },
          ],
          next_cursor: null,
          count: 2,
        },
      },
    }),
    get: jest.fn().mockResolvedValue({
      data: { data: { path: {}, nodes: [], findings: [] } },
    }),
    getNarrative: jest.fn().mockResolvedValue({
      data: { data: { path_id: 'p1', steps: [], generated_by: 'template' } },
    }),
    getMitre: jest.fn(),
  },
}))

import AttackPathsPage from '@/app/attack-paths/page'

function wrapper({ children }: { children: React.ReactNode }) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
}

describe('AttackPathsPage — View Results By toggle', () => {
  it('defaults to Paths view and groups by target asset category', async () => {
    render(<AttackPathsPage />, { wrapper })
    await waitFor(() => expect(screen.getByText('Storage')).toBeInTheDocument())
    expect(screen.getByText('Security & Identity')).toBeInTheDocument()
  })

  it('switches to Alerts view and groups by rule', async () => {
    render(<AttackPathsPage />, { wrapper })
    await waitFor(() => expect(screen.getByText('Storage')).toBeInTheDocument())

    await userEvent.click(screen.getByRole('button', { name: 'Alerts' }))

    expect(screen.getByText('TC-02')).toBeInTheDocument()
    expect(screen.getByText('Privilege Escalation')).toBeInTheDocument()
    expect(screen.queryByText('Storage')).not.toBeInTheDocument()
  })

  it('marks the active view mode button as pressed', async () => {
    render(<AttackPathsPage />, { wrapper })
    await waitFor(() => expect(screen.getByRole('button', { name: 'Paths' })).toHaveAttribute('aria-pressed', 'true'))
    expect(screen.getByRole('button', { name: 'Alerts' })).toHaveAttribute('aria-pressed', 'false')
  })
})
