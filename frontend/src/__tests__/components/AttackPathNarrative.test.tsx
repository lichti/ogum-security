import '@testing-library/jest-dom'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import type { ReactNode } from 'react'
import { AttackPathNarrative } from '@/components/attack-paths/AttackPathNarrative'
import { attackPathsApi } from '@/lib/api'

jest.mock('@/lib/api', () => ({
  attackPathsApi: { getNarrative: jest.fn() },
}))

const mockGetNarrative = attackPathsApi.getNarrative as jest.Mock

function renderWithClient(ui: React.ReactElement) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } })
  function Wrapper({ children }: { children: ReactNode }) {
    return <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  }
  return render(ui, { wrapper: Wrapper })
}

const STEPS = [
  { index: 1, total: 4, title: 'Entry Point', text: 'Starts at web-server.' },
  { index: 2, total: 4, title: 'Path & Pivot', text: 'Reaches target in 2 hops.' },
  { index: 3, total: 4, title: 'Target & Impact', text: 'Target is prod-data.' },
  { index: 4, total: 4, title: 'Findings & Evidence', text: '1 open finding.' },
]

beforeEach(() => jest.clearAllMocks())

describe('AttackPathNarrative', () => {
  it('shows loading state before data resolves', () => {
    mockGetNarrative.mockReturnValue(new Promise(() => {}))
    renderWithClient(<AttackPathNarrative pathKey="path-1" />)
    expect(screen.getByTestId('narrative-loading')).toBeInTheDocument()
  })

  it('renders the first step with pagination 1/4', async () => {
    mockGetNarrative.mockResolvedValue({ data: { data: { path_id: 'path-1', steps: STEPS, generated_by: 'template' } } })
    renderWithClient(<AttackPathNarrative pathKey="path-1" />)
    await waitFor(() => {
      expect(screen.getByText('Entry Point')).toBeInTheDocument()
      expect(screen.getByText('Starts at web-server.')).toBeInTheDocument()
      expect(screen.getByText('1/4')).toBeInTheDocument()
    })
  })

  it('advances to the next step on click', async () => {
    mockGetNarrative.mockResolvedValue({ data: { data: { path_id: 'path-1', steps: STEPS, generated_by: 'template' } } })
    renderWithClient(<AttackPathNarrative pathKey="path-1" />)
    await waitFor(() => expect(screen.getByText('1/4')).toBeInTheDocument())

    await userEvent.click(screen.getByLabelText('Next step'))

    expect(screen.getByText('Path & Pivot')).toBeInTheDocument()
    expect(screen.getByText('2/4')).toBeInTheDocument()
  })

  it('disables the previous button on the first step', async () => {
    mockGetNarrative.mockResolvedValue({ data: { data: { path_id: 'path-1', steps: STEPS, generated_by: 'template' } } })
    renderWithClient(<AttackPathNarrative pathKey="path-1" />)
    await waitFor(() => expect(screen.getByLabelText('Previous step')).toBeDisabled())
  })

  it('disables the next button on the last step', async () => {
    mockGetNarrative.mockResolvedValue({ data: { data: { path_id: 'path-1', steps: STEPS, generated_by: 'template' } } })
    renderWithClient(<AttackPathNarrative pathKey="path-1" />)
    await waitFor(() => screen.getByLabelText('Next step'))

    for (let i = 0; i < 3; i++) {
      await userEvent.click(screen.getByLabelText('Next step'))
    }

    expect(screen.getByText('4/4')).toBeInTheDocument()
    expect(screen.getByLabelText('Next step')).toBeDisabled()
  })

  it('renders nothing when there are no steps', async () => {
    mockGetNarrative.mockResolvedValue({ data: { data: { path_id: 'path-1', steps: [], generated_by: 'template' } } })
    const { container } = renderWithClient(<AttackPathNarrative pathKey="path-1" />)
    await waitFor(() => expect(screen.queryByTestId('narrative-loading')).not.toBeInTheDocument())
    expect(container).toBeEmptyDOMElement()
  })
})
