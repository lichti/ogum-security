import {
  aggregateByCategory,
  categoryOf,
  resourceTypesForCategories,
  CATEGORY_ORDER,
} from '@/lib/inventoryCategories'

describe('categoryOf', () => {
  it('maps known resource types to their category', () => {
    expect(categoryOf('ec2_instance')).toBe('compute')
    expect(categoryOf('rds_instance')).toBe('database')
    expect(categoryOf('vpc')).toBe('networking')
    expect(categoryOf('kms_key')).toBe('security_identity')
    expect(categoryOf('eks_cluster')).toBe('containers')
    expect(categoryOf('storage_account')).toBe('storage')
  })

  it('falls back to "other" for unmapped types', () => {
    expect(categoryOf('some_future_resource_type')).toBe('other')
  })
})

describe('aggregateByCategory', () => {
  it('sums counts per category and covers every category key', () => {
    const totals = aggregateByCategory({
      ec2_instance: 10,
      lambda_function: 5,
      rds_instance: 2,
      unknown_type: 1,
    })
    expect(totals.compute).toBe(15)
    expect(totals.database).toBe(2)
    expect(totals.other).toBe(1)
    expect(Object.keys(totals).sort()).toEqual([...CATEGORY_ORDER].sort())
  })

  it('returns all-zero totals for empty input', () => {
    const totals = aggregateByCategory({})
    for (const cat of CATEGORY_ORDER) {
      expect(totals[cat]).toBe(0)
    }
  })
})

describe('resourceTypesForCategories', () => {
  const byResourceType = { ec2_instance: 10, rds_instance: 2, vpc: 4, unknown_type: 1 }

  it('returns an empty list when no categories are selected', () => {
    expect(resourceTypesForCategories([], byResourceType)).toEqual([])
  })

  it('resolves a category to the concrete types present in the data', () => {
    expect(resourceTypesForCategories(['compute'], byResourceType)).toEqual(['ec2_instance'])
  })

  it('supports multiple categories and the "other" bucket', () => {
    const result = resourceTypesForCategories(['database', 'other'], byResourceType)
    expect(result.sort()).toEqual(['rds_instance', 'unknown_type'])
  })
})
