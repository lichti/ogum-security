import '@testing-library/jest-dom'
import { render, screen, fireEvent } from '@testing-library/react'
import { FindingsSummary } from '@/components/findings/FindingsSummary'

const bySeverity = { CRITICAL: 5, HIGH: 3, MEDIUM: 2, LOW: 1, INFORMATIONAL: 0 }
const byProvider = { aws: 8, azure: 2, gcp: 0, k8s: 1 }

const onSeverityClick = jest.fn()
const onProviderClick = jest.fn()
beforeEach(() => jest.clearAllMocks())

describe('FindingsSummary', () => {
  it('renders a card with count for every severity', () => {
    render(
      <FindingsSummary
        bySeverity={bySeverity}
        byProvider={byProvider}
        selectedSeverities={[]}
        selectedProviders={[]}
        onSeverityClick={onSeverityClick}
        onProviderClick={onProviderClick}
      />,
    )
    expect(screen.getByLabelText('Filter by CRITICAL')).toHaveTextContent('5')
    expect(screen.getByLabelText('Filter by HIGH')).toHaveTextContent('3')
    expect(screen.getByLabelText('Filter by INFORMATIONAL')).toHaveTextContent('0')
  })

  it('renders a card with count for every provider', () => {
    render(
      <FindingsSummary
        bySeverity={bySeverity}
        byProvider={byProvider}
        selectedSeverities={[]}
        selectedProviders={[]}
        onSeverityClick={onSeverityClick}
        onProviderClick={onProviderClick}
      />,
    )
    expect(screen.getByLabelText('Filter by AWS')).toHaveTextContent('8')
    expect(screen.getByLabelText('Filter by GCP')).toHaveTextContent('0')
  })

  it('calls onSeverityClick with the severity key when a card is clicked', () => {
    render(
      <FindingsSummary
        bySeverity={bySeverity}
        byProvider={byProvider}
        selectedSeverities={[]}
        selectedProviders={[]}
        onSeverityClick={onSeverityClick}
        onProviderClick={onProviderClick}
      />,
    )
    fireEvent.click(screen.getByLabelText('Filter by CRITICAL'))
    expect(onSeverityClick).toHaveBeenCalledWith('CRITICAL')
  })

  it('calls onProviderClick with the provider key when a card is clicked', () => {
    render(
      <FindingsSummary
        bySeverity={bySeverity}
        byProvider={byProvider}
        selectedSeverities={[]}
        selectedProviders={[]}
        onSeverityClick={onSeverityClick}
        onProviderClick={onProviderClick}
      />,
    )
    fireEvent.click(screen.getByLabelText('Filter by AWS'))
    expect(onProviderClick).toHaveBeenCalledWith('aws')
  })

  it('marks selected severity and provider cards as pressed', () => {
    render(
      <FindingsSummary
        bySeverity={bySeverity}
        byProvider={byProvider}
        selectedSeverities={['CRITICAL']}
        selectedProviders={['aws']}
        onSeverityClick={onSeverityClick}
        onProviderClick={onProviderClick}
      />,
    )
    expect(screen.getByLabelText('Filter by CRITICAL')).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByLabelText('Filter by HIGH')).toHaveAttribute('aria-pressed', 'false')
    expect(screen.getByLabelText('Filter by AWS')).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByLabelText('Filter by AZURE')).toHaveAttribute('aria-pressed', 'false')
  })
})
