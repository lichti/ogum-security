/**
 * US-06.01 — interceptor de refresh do apiClient.
 *
 * 401 → refresh único (single-flight) → retry; refresh falhou → evento
 * ogum:unauthorized + redirect para /login?next=<rota>. O refresh usa uma
 * instância axios nua — o adapter de teste só afeta o apiClient.
 */

import { AxiosError } from 'axios'

const { apiClient, authApi } = jest.requireActual('@/lib/api')

function make401(config: Record<string, unknown>) {
  const response = { data: { detail: 'Not authenticated' }, status: 401, statusText: 'Unauthorized', headers: {} }
  const err = new AxiosError('Request failed')
  err.response = response as never
  err.config = config as never
  return err
}

function install401Adapter(): jest.Mock {
  const adapter = jest.fn(async (config) => {
    const error = make401(config)
    throw error
  })
  apiClient.defaults.adapter = adapter
  return adapter
}

describe('401 → refresh → retry (US-06.01)', () => {
  const originalLocation = window.location

  beforeEach(() => {
    jest.clearAllMocks()
  })

  afterEach(() => {
    // jsdom não implementa navigation; devolve um stub controlável
    Object.defineProperty(window, 'location', { value: originalLocation, writable: true })
  })

  function stubLocation(pathname = '/findings') {
    Object.defineProperty(window, 'location', {
      writable: true,
      value: { pathname, search: '?severity=high', assign: jest.fn() },
    })
  }

  it('retries the original request once after a successful refresh', async () => {
    stubLocation()
    const refreshSpy = jest.spyOn(authApi, 'refresh').mockResolvedValueOnce({ status: 200 } as never)
    let calls = 0
    const adapter = jest.fn(async (config) => {
      calls += 1
      if (calls === 1) throw make401(config)
      return { data: { ok: true }, status: 200, statusText: 'OK', headers: {}, config }
    })
    apiClient.defaults.adapter = adapter

    const response = await apiClient.get('/api/v1/findings')
    expect(response.status).toBe(200)
    expect(refreshSpy).toHaveBeenCalledTimes(1)
    expect(adapter).toHaveBeenCalledTimes(2)
    refreshSpy.mockRestore()
  })

  it('redirects to /login preserving next when refresh fails', async () => {
    stubLocation('/findings')
    jest.spyOn(authApi, 'refresh').mockRejectedValueOnce(new AxiosError('expired'))
    install401Adapter()
    const listener = jest.fn()
    window.addEventListener('ogum:unauthorized', listener)

    await expect(apiClient.get('/api/v1/findings')).rejects.toMatchObject({ response: { status: 401 } })
    expect(listener).toHaveBeenCalledTimes(1)
    expect(window.location.assign).toHaveBeenCalledWith('/login?next=%2Ffindings%3Fseverity%3Dhigh')
    window.removeEventListener('ogum:unauthorized', listener)
  })

  it('does not redirect when already on /login', async () => {
    stubLocation('/login')
    jest.spyOn(authApi, 'refresh').mockRejectedValueOnce(new AxiosError('expired'))
    install401Adapter()

    await expect(apiClient.get('/api/v1/findings')).rejects.toMatchObject({ response: { status: 401 } })
    expect(window.location.assign).not.toHaveBeenCalled()
  })

  it('never attempts refresh for auth routes themselves (loop guard)', async () => {
    stubLocation()
    const refreshSpy = jest.spyOn(authApi, 'refresh')
    install401Adapter()

    await expect(apiClient.post('/api/v1/auth/refresh')).rejects.toMatchObject({ response: { status: 401 } })
    expect(refreshSpy).not.toHaveBeenCalled()
    refreshSpy.mockRestore()
  })
})

describe('authApi.status', () => {
  it('calls GET /auth/oidc/status with tenant_id', async () => {
    const spy = jest.spyOn(apiClient, 'get').mockResolvedValueOnce({
      data: { data: { enabled: true, idp_name: 'Corp Okta' } },
    })
    const result = await authApi.status('acme')
    expect(spy).toHaveBeenCalledWith('/api/v1/auth/oidc/status', { params: { tenant_id: 'acme' } })
    expect(result.data.data.idp_name).toBe('Corp Okta')
    spy.mockRestore()
  })
})
