import '@testing-library/jest-dom'
import { render, screen, fireEvent } from '@testing-library/react'
import { ConnectWizard } from '@/components/providers/ConnectWizard'

jest.mock('@/lib/api', () => ({
  providersApi: {
    register: jest.fn(),
  },
}))

describe('ConnectWizard', () => {
  const onComplete = jest.fn()
  const onCancel = jest.fn()

  beforeEach(() => {
    jest.clearAllMocks()
  })

  it('renders provider selection step', () => {
    render(<ConnectWizard onComplete={onComplete} onCancel={onCancel} />)
    expect(screen.getByText('Connect Cloud Account')).toBeInTheDocument()
    expect(screen.getByText('Amazon Web Services')).toBeInTheDocument()
    expect(screen.getByText('Microsoft Azure')).toBeInTheDocument()
    expect(screen.getByText('Google Cloud Platform')).toBeInTheDocument()
    expect(screen.getByText('Kubernetes')).toBeInTheDocument()
  })

  it('advances to configure step when AWS is selected', () => {
    render(<ConnectWizard onComplete={onComplete} onCancel={onCancel} />)
    fireEvent.click(screen.getByText('Amazon Web Services'))
    expect(screen.getByPlaceholderText('123456789012')).toBeInTheDocument()
    expect(screen.getByText('Connect & Start Discovery')).toBeInTheDocument()
  })

  it('shows Azure-specific field when Azure selected', () => {
    render(<ConnectWizard onComplete={onComplete} onCancel={onCancel} />)
    fireEvent.click(screen.getByText('Microsoft Azure'))
    expect(screen.getByPlaceholderText(/xxxxxxxx-xxxx/)).toBeInTheDocument()
  })

  it('shows GCP project field when GCP selected', () => {
    render(<ConnectWizard onComplete={onComplete} onCancel={onCancel} />)
    fireEvent.click(screen.getByText('Google Cloud Platform'))
    expect(screen.getByPlaceholderText('my-project-id')).toBeInTheDocument()
  })

  it('shows K8s cluster name field when K8s selected', () => {
    render(<ConnectWizard onComplete={onComplete} onCancel={onCancel} />)
    fireEvent.click(screen.getByText('Kubernetes'))
    expect(screen.getByPlaceholderText('prod-cluster')).toBeInTheDocument()
  })

  it('returns to provider selection when back is clicked', () => {
    render(<ConnectWizard onComplete={onComplete} onCancel={onCancel} />)
    fireEvent.click(screen.getByText('Amazon Web Services'))
    fireEvent.click(screen.getByText(/Back/))
    expect(screen.getByText('Amazon Web Services')).toBeInTheDocument()
  })

  it('calls onCancel when × is clicked', () => {
    render(<ConnectWizard onComplete={onComplete} onCancel={onCancel} />)
    fireEvent.click(screen.getByText('×'))
    expect(onCancel).toHaveBeenCalledTimes(1)
  })

  it('all four providers are selectable buttons', () => {
    render(<ConnectWizard onComplete={onComplete} onCancel={onCancel} />)
    const providers = ['Amazon Web Services', 'Microsoft Azure', 'Google Cloud Platform', 'Kubernetes']
    providers.forEach((name) => {
      expect(screen.getByText(name).closest('button')).toBeInTheDocument()
    })
  })
})
