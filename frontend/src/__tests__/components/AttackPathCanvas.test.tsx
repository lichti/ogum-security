import '@testing-library/jest-dom'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { AttackPathCanvas } from '@/components/graph/AttackPathCanvas'
import type { AttackPathDetail, AttackPath } from '@/lib/types'

// React Flow needs ResizeObserver
global.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

const BASE_PATH: AttackPath = {
  _key: 'path-1',
  path_id: 'path-1',
  tenant_id: 'tenant-a',
  rule: 'INTERNET_EC2_S3',
  entry_point_id: 'resources/ep-1',
  entry_point_type: 'aws_ec2_instance',
  entry_point_name: 'web-server',
  target_id: 'data_assets/target-1',
  target_type: 'aws_s3_bucket',
  target_name: 'prod-data',
  hops: 2,
  path_vertex_ids: ['resources/ep-1', 'data_assets/target-1'],
  risk_score: 90,
  severity: 'CRITICAL',
  is_toxic_combination: true,
  detected_at: '2026-01-01T00:00:00Z',
  status: 'active',
}

const makeDetail = (overrides: Partial<AttackPathDetail> = {}): AttackPathDetail => ({
  path: BASE_PATH,
  nodes: [
    { _id: 'resources/ep-1', _key: 'ep-1', name: 'web-server', resource_type: 'aws_ec2_instance' },
    { _id: 'data_assets/target-1', _key: 'target-1', name: 'prod-data', resource_type: 'aws_s3_bucket' },
  ],
  findings: [],
  ...overrides,
})

describe('AttackPathCanvas', () => {
  it('shows "select a path" placeholder when detail is null', () => {
    render(<AttackPathCanvas detail={null} />)
    expect(screen.getByText(/select a path/i)).toBeInTheDocument()
  })

  it('shows loading spinner when loading prop is true', () => {
    render(<AttackPathCanvas detail={null} loading />)
    expect(screen.getByText(/loading graph/i)).toBeInTheDocument()
  })

  it('shows no-data message when nodes array is empty', () => {
    render(<AttackPathCanvas detail={makeDetail({ nodes: [] })} />)
    expect(screen.getByText(/no graph data/i)).toBeInTheDocument()
  })

  it('renders the React Flow canvas when detail has nodes', () => {
    const { container } = render(<AttackPathCanvas detail={makeDetail()} />)
    // React Flow renders a div with class "react-flow"
    expect(container.querySelector('.react-flow')).toBeTruthy()
  })

  it('accepts onNodeClick prop without crashing', () => {
    const onNodeClick = jest.fn()
    const { container } = render(
      <AttackPathCanvas detail={makeDetail()} onNodeClick={onNodeClick} />,
    )
    // React Flow node click is handled internally by the library;
    // E2E tests cover the full interaction. Here we just verify no crash.
    expect(container.querySelector('.react-flow')).toBeTruthy()
  })

  it('attaches a risk-insight node for a finding linked to a path resource', () => {
    const { container } = render(
      <AttackPathCanvas
        detail={makeDetail({
          findings: [{ resource_id: 'resources/ep-1', title: 'Public EC2', severity: 'CRITICAL', status: 'FAIL' }],
        })}
      />,
    )
    expect(container.querySelector('.react-flow__node-riskInsight')).toBeTruthy()
  })

  it('does not attach a risk-insight node when there are no findings', () => {
    const { container } = render(<AttackPathCanvas detail={makeDetail({ findings: [] })} />)
    expect(container.querySelector('.react-flow__node-riskInsight')).toBeFalsy()
  })

  describe('mode="mini"', () => {
    it('shows an empty state when the mini graph has no nodes', () => {
      render(<AttackPathCanvas mode="mini" miniGraph={{ nodes: [], edges: [] }} emptyLabel="No exposure edges" />)
      expect(screen.getByText('No exposure edges')).toBeInTheDocument()
    })

    it('renders the canvas when the mini graph has nodes', () => {
      const { container } = render(
        <AttackPathCanvas
          mode="mini"
          miniGraph={{
            nodes: [{ id: 'resources/r1', type: 'center', data: { node: {} }, position: { x: 0, y: 0 } }],
            edges: [],
          }}
        />,
      )
      expect(container.querySelector('.react-flow')).toBeTruthy()
    })

    it('does not render a MiniMap in mini mode', () => {
      const { container } = render(
        <AttackPathCanvas
          mode="mini"
          miniGraph={{
            nodes: [{ id: 'resources/r1', type: 'center', data: { node: {} }, position: { x: 0, y: 0 } }],
            edges: [],
          }}
        />,
      )
      expect(container.querySelector('.react-flow__minimap')).toBeFalsy()
    })

    it('renders a "View full" link when onViewFull is provided', () => {
      const onViewFull = jest.fn()
      render(
        <AttackPathCanvas
          mode="mini"
          miniGraph={{
            nodes: [{ id: 'resources/r1', type: 'center', data: { node: {} }, position: { x: 0, y: 0 } }],
            edges: [],
          }}
          onViewFull={onViewFull}
        />,
      )
      expect(screen.getByText(/View full in Attack Paths/)).toBeInTheDocument()
    })
  })
})
