import { AxiosError } from 'axios'

import { getApiToken, serializeParams, setApiToken } from '@/lib/api'

describe('interim API token (US-06.09)', () => {
  beforeEach(() => {
    window.localStorage.clear()
  })

  it('returns null when no token is configured', () => {
    expect(getApiToken()).toBeNull()
  })

  it('stores and retrieves the token via localStorage', () => {
    setApiToken('test-token-123')
    expect(getApiToken()).toBe('test-token-123')
  })

  it('clears the token when set to null', () => {
    setApiToken('test-token-123')
    setApiToken(null)
    expect(getApiToken()).toBeNull()
  })

  it('dispatches ogum:unauthorized on a 401 response', async () => {
    const listener = jest.fn()
    window.addEventListener('ogum:unauthorized', listener)

    const { apiClient } = await import('@/lib/api')
    // Rota inexistente contra um base URL sem servidor — o interceptor de
    // resposta só rejeita; para forçar 401 usamos um adapter direto.
    apiClient.defaults.adapter = async (config) => {
      const response = {
        data: { detail: 'Not authenticated' },
        status: 401,
        statusText: 'Unauthorized',
        headers: {},
        config,
      }
      const error = Object.assign(new AxiosError('Request failed'), { response, config })
      throw error
    }

    await expect(apiClient.get('/api/v1/inventory')).rejects.toMatchObject({
      response: { status: 401 },
    })
    expect(listener).toHaveBeenCalledTimes(1)
    window.removeEventListener('ogum:unauthorized', listener)
  })
})

describe('serializeParams', () => {
  it('serializes array values as repeated bare keys, not bracket notation', () => {
    const qs = serializeParams({ resource_type: ['vpc', 'subnet'] })
    expect(qs).toBe('resource_type=vpc&resource_type=subnet')
  })

  it('serializes scalar values as a single key=value pair', () => {
    expect(serializeParams({ search: 'macie' })).toBe('search=macie')
  })

  it('omits undefined and null values', () => {
    expect(serializeParams({ provider: undefined, region: null, limit: 50 })).toBe('limit=50')
  })

  it('omits empty arrays entirely (no key emitted)', () => {
    expect(serializeParams({ provider: [], limit: 50 })).toBe('limit=50')
  })

  it('combines multiple filters into a single query string', () => {
    const qs = serializeParams({ provider: ['aws', 'azure'], region: 'us-east-1', limit: 50, offset: 0 })
    expect(qs).toBe('provider=aws&provider=azure&region=us-east-1&limit=50&offset=0')
  })
})
