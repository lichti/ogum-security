import '@testing-library/jest-dom'
import { render, screen } from '@testing-library/react'
import { ReactFlowProvider } from '@xyflow/react'
import { RiskInsightNode } from '@/components/graph/nodes/RiskInsightNode'
import type { NodeProps } from '@xyflow/react'

// React Flow needs ResizeObserver
global.ResizeObserver = class ResizeObserver {
  observe() {}
  unobserve() {}
  disconnect() {}
}

function renderNode(finding: Record<string, unknown>) {
  const props = {
    id: 'risk-insight-1',
    data: { finding },
    selected: false,
    type: 'riskInsight',
    dragging: false,
    zIndex: 0,
    isConnectable: true,
    positionAbsoluteX: 0,
    positionAbsoluteY: 0,
  } as unknown as NodeProps

  return render(
    <ReactFlowProvider>
      <RiskInsightNode {...props} />
    </ReactFlowProvider>,
  )
}

describe('RiskInsightNode', () => {
  it('renders the finding title and severity', () => {
    renderNode({ title: 'Public S3 bucket', severity: 'CRITICAL', status: 'FAIL' })
    expect(screen.getByText('Public S3 bucket')).toBeInTheDocument()
    expect(screen.getByText('CRITICAL')).toBeInTheDocument()
  })

  it('falls back to check_id when title is missing', () => {
    renderNode({ check_id: 'ec2_public', severity: 'HIGH', status: 'FAIL' })
    expect(screen.getByText('ec2_public')).toBeInTheDocument()
  })

  it('shows the expandable badge for FAIL findings', () => {
    renderNode({ title: 'X', severity: 'HIGH', status: 'FAIL' })
    expect(screen.getByTitle('Expandable — active finding')).toBeInTheDocument()
  })

  it('shows the contained badge for MUTED findings', () => {
    renderNode({ title: 'X', severity: 'HIGH', status: 'MUTED' })
    expect(screen.getByTitle('Contained/restricted — muted or accepted')).toBeInTheDocument()
    expect(screen.queryByTitle('Expandable — active finding')).not.toBeInTheDocument()
  })

  it('shows the contained badge for ACCEPTED findings', () => {
    renderNode({ title: 'X', severity: 'HIGH', status: 'ACCEPTED' })
    expect(screen.getByTitle('Contained/restricted — muted or accepted')).toBeInTheDocument()
  })

  it('shows no badge for an unknown status', () => {
    renderNode({ title: 'X', severity: 'HIGH', status: 'PASS' })
    expect(screen.queryByTitle('Expandable — active finding')).not.toBeInTheDocument()
    expect(screen.queryByTitle('Contained/restricted — muted or accepted')).not.toBeInTheDocument()
  })
})
