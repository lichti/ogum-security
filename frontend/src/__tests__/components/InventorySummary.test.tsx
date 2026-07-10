import '@testing-library/jest-dom'
import { render, screen, fireEvent } from '@testing-library/react'
import { InventorySummary } from '@/components/inventory/InventorySummary'
import { aggregateByCategory } from '@/lib/inventoryCategories'

const byProvider = { aws: 42, azure: 5, gcp: 0, k8s: 12 }
const byCategory = aggregateByCategory({ ec2_instance: 40, rds_instance: 2, s3_bucket_unmapped: 3 })

const onProviderClick = jest.fn()
const onCategoryClick = jest.fn()
beforeEach(() => jest.clearAllMocks())

describe('InventorySummary', () => {
  it('renders a card with count for every provider', () => {
    render(
      <InventorySummary
        byProvider={byProvider}
        byCategory={byCategory}
        selectedProviders={[]}
        selectedCategories={[]}
        onProviderClick={onProviderClick}
        onCategoryClick={onCategoryClick}
      />,
    )
    expect(screen.getByLabelText('Filter by AWS')).toBeInTheDocument()
    expect(screen.getByText('42')).toBeInTheDocument()
    expect(screen.getByLabelText('Filter by AZURE')).toBeInTheDocument()
    expect(screen.getByLabelText('Filter by GCP')).toBeInTheDocument()
    expect(screen.getByLabelText('Filter by K8S')).toBeInTheDocument()
  })

  it('renders a card for every category, including unmapped types under Other', () => {
    render(
      <InventorySummary
        byProvider={byProvider}
        byCategory={byCategory}
        selectedProviders={[]}
        selectedCategories={[]}
        onProviderClick={onProviderClick}
        onCategoryClick={onCategoryClick}
      />,
    )
    expect(screen.getByLabelText('Filter by Compute')).toBeInTheDocument()
    expect(screen.getByLabelText('Filter by Database')).toBeInTheDocument()
    const other = screen.getByLabelText('Filter by Other')
    expect(other).toHaveTextContent('3')
  })

  it('calls onProviderClick with the provider key when a provider card is clicked', () => {
    render(
      <InventorySummary
        byProvider={byProvider}
        byCategory={byCategory}
        selectedProviders={[]}
        selectedCategories={[]}
        onProviderClick={onProviderClick}
        onCategoryClick={onCategoryClick}
      />,
    )
    fireEvent.click(screen.getByLabelText('Filter by AWS'))
    expect(onProviderClick).toHaveBeenCalledWith('aws')
  })

  it('calls onCategoryClick with the category key when a category card is clicked', () => {
    render(
      <InventorySummary
        byProvider={byProvider}
        byCategory={byCategory}
        selectedProviders={[]}
        selectedCategories={[]}
        onProviderClick={onProviderClick}
        onCategoryClick={onCategoryClick}
      />,
    )
    fireEvent.click(screen.getByLabelText('Filter by Compute'))
    expect(onCategoryClick).toHaveBeenCalledWith('compute')
  })

  it('marks selected provider and category cards as pressed', () => {
    render(
      <InventorySummary
        byProvider={byProvider}
        byCategory={byCategory}
        selectedProviders={['aws']}
        selectedCategories={['compute']}
        onProviderClick={onProviderClick}
        onCategoryClick={onCategoryClick}
      />,
    )
    expect(screen.getByLabelText('Filter by AWS')).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByLabelText('Filter by AZURE')).toHaveAttribute('aria-pressed', 'false')
    expect(screen.getByLabelText('Filter by Compute')).toHaveAttribute('aria-pressed', 'true')
  })
})
