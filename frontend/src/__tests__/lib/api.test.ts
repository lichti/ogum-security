import { serializeParams } from '@/lib/api'

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
