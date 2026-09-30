/**
 * US-06.01 — página /login.
 *
 * Tenant verificado → GET /auth/oidc/status → botão "Entrar com {IdP}" →
 * navega para o endpoint de login do backend. Sem IdP → mensagem e sem botão.
 * Token interim (US-06.09) continua disponível como fluxo secundário.
 */

import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useRouter, useSearchParams } from 'next/navigation'

import LoginPage from '@/app/login/page'
import { setApiToken } from '@/lib/api'

jest.mock('next/navigation', () => ({
  useRouter: jest.fn(),
  useSearchParams: jest.fn(),
}))

const mockApiGet = jest.fn()

jest.mock('@/lib/api', () => ({
  ...jest.requireActual('@/lib/api'),
  authApi: {
    status: (tenantId: string) => mockApiGet(tenantId),
  },
}))

describe('/login (US-06.01)', () => {
  beforeEach(() => {
    window.localStorage.clear()
    jest.clearAllMocks()
    ;(useSearchParams as jest.Mock).mockReturnValue(new URLSearchParams())
    ;(useRouter as jest.Mock).mockReturnValue({ push: jest.fn() })
  })

  function typeTenant(value: string) {
    return userEvent.type(screen.getByLabelText(/tenant/i, { selector: 'input' }), value)
  }

  it('shows the IdP button with the configured name after status lookup', async () => {
    mockApiGet.mockResolvedValueOnce({ data: { data: { enabled: true, idp_name: 'Corp Okta' } } })

    render(<LoginPage />)
    await typeTenant('acme')
    await userEvent.click(screen.getByRole('button', { name: /verificar/i }))

    expect(await screen.findByTestId('oidc-login-button')).toHaveTextContent('Entrar com Corp Okta')
    expect(mockApiGet).toHaveBeenCalledWith('acme')
  })

  it('shows an error and no SSO button when the tenant has no IdP', async () => {
    mockApiGet.mockRejectedValueOnce({
      isAxiosError: true,
      response: { data: { detail: 'No OIDC identity provider configured for tenant' } },
    })

    render(<LoginPage />)
    await typeTenant('acme')
    await userEvent.click(screen.getByRole('button', { name: /verificar/i }))

    expect(await screen.findByRole('alert')).toHaveTextContent(/No OIDC identity provider/i)
    expect(screen.queryByTestId('oidc-login-button')).not.toBeInTheDocument()
  })

  it('navigates to the backend OIDC login endpoint with the tenant id', async () => {
    mockApiGet.mockResolvedValueOnce({ data: { data: { enabled: true, idp_name: 'Google' } } })
    const assign = jest.fn()
    Object.defineProperty(window, 'location', {
      writable: true,
      value: { pathname: '/login', search: '', assign },
    })

    render(<LoginPage />)
    await typeTenant('acme')
    await userEvent.click(screen.getByRole('button', { name: /verificar/i }))
    await userEvent.click(await screen.findByTestId('oidc-login-button'))

    expect(assign).toHaveBeenCalledWith(
      expect.stringContaining('http://localhost:8000/api/v1/auth/oidc/login?tenant_id=acme'),
    )
  })

  it('saves the interim API token and navigates on', async () => {
    render(<LoginPage />)
    await userEvent.type(screen.getByPlaceholderText(/cole o token/i), 'token-abc')
    await userEvent.click(screen.getByRole('button', { name: /usar token/i }))

    expect(window.localStorage.getItem('ogum_api_token')).toBe('token-abc')
  })

  it('clears a stale interim token when saving empty is prevented (input required)', () => {
    render(<LoginPage />)
    setApiToken('velho')
    const button = screen.getByRole('button', { name: /usar token/i })
    expect(button).toBeDisabled() // sem token no input, botão desabilitado
  })
})
