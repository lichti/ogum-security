import '@testing-library/jest-dom'
import { render, screen, fireEvent } from '@testing-library/react'
import { RelationshipGroups } from '@/components/inventory/RelationshipGroups'
import type { EdgeSummary } from '@/lib/types'

const edges: EdgeSummary[] = [
  { edge_type: 'BELONGS_TO', direction: 'outbound', peer_key: 'vpc-001', peer_collection: 'resources', peer_type: 'vpc' },
  { edge_type: 'ATTACHED_TO', direction: 'inbound', peer_key: 'sg-001', peer_collection: 'resources', peer_type: 'security_group' },
  { edge_type: 'ATTACHED_TO', direction: 'inbound', peer_key: 'sg-002', peer_collection: 'resources', peer_type: 'security_group' },
]

describe('RelationshipGroups', () => {
  it('renders a message when there are no edges', () => {
    render(<RelationshipGroups edges={[]} />)
    expect(screen.getByText('No relationships found.')).toBeInTheDocument()
  })

  it('groups edges by type with a count in the title', () => {
    render(<RelationshipGroups edges={edges} />)
    expect(screen.getByText('1 BELONGS TO')).toBeInTheDocument()
    expect(screen.getByText('2 ATTACHED TO')).toBeInTheDocument()
  })

  it('renders each peer resource within its group', () => {
    render(<RelationshipGroups edges={edges} />)
    expect(screen.getByText('vpc-001')).toBeInTheDocument()
    expect(screen.getByText('sg-001')).toBeInTheDocument()
    expect(screen.getByText('sg-002')).toBeInTheDocument()
  })

  it('sorts groups alphabetically by edge type', () => {
    render(<RelationshipGroups edges={edges} />)
    const headings = screen.getAllByRole('heading', { level: 4 }).map((h) => h.textContent)
    expect(headings).toEqual(['2 ATTACHED TO', '1 BELONGS TO'])
  })

  it('renders a "View in graph" link per group when onViewInGraph is provided', () => {
    const onViewInGraph = jest.fn()
    render(<RelationshipGroups edges={edges} onViewInGraph={onViewInGraph} />)
    const links = screen.getAllByText('View in graph →')
    expect(links).toHaveLength(2)
    fireEvent.click(links[0])
    expect(onViewInGraph).toHaveBeenCalledTimes(1)
  })

  it('does not render "View in graph" links when the callback is omitted', () => {
    render(<RelationshipGroups edges={edges} />)
    expect(screen.queryByText('View in graph →')).not.toBeInTheDocument()
  })
})
