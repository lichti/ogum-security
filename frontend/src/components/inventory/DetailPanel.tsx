'use client'
import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { CheckCircle2, ExternalLink, PlayCircle, X } from 'lucide-react'
import { Badge } from '@/components/ui/Badge'
import type { BadgeVariant } from '@/components/ui/Badge'
import { sideScanApi } from '@/lib/api'
import type { ResourceDetail } from '@/lib/types'

interface DetailPanelProps {
  resource: ResourceDetail | null
  onClose: () => void
}

const SCANNABLE_RESOURCE_TYPES = new Set(['ec2_instance', 'lambda_function'])

function consoleUrl(resource: ResourceDetail): string | null {
  if (resource.provider === 'aws' && resource.arn) {
    const region = resource.region ?? 'us-east-1'
    const base = `https://${region}.console.aws.amazon.com`
    if (resource.resource_type === 'ec2_instance')
      return `${base}/ec2/home?region=${region}#Instances:instanceId=${resource.resource_id}`
    if (resource.resource_type === 's3_bucket')
      return `https://s3.console.aws.amazon.com/s3/buckets/${resource.resource_id}`
  }
  return null
}

export function DetailPanel({ resource, onClose }: DetailPanelProps) {
  const [scanError, setScanError] = useState<string | null>(null)

  const scanMutation = useMutation({
    mutationFn: () => sideScanApi.triggerScan(resource?.key ?? ''),
    onSuccess: () => setScanError(null),
    onError: () => setScanError('Failed to trigger scan.'),
  })

  if (!resource) return null

  const url = consoleUrl(resource)
  const canScan = SCANNABLE_RESOURCE_TYPES.has(resource.resource_type) && resource.status === 'active'
  const scanSuccessJobId = scanMutation.isSuccess ? scanMutation.data.data.job_id : null
  const providerVariant: BadgeVariant = `provider-${resource.provider}` as BadgeVariant
  const statusVariant: BadgeVariant = resource.status === 'active' ? 'status-active' : 'status-deleted'

  const metadataRows: [string, React.ReactNode][] = [
    ['Provider', <Badge key="provider" variant={providerVariant}>{resource.provider.toUpperCase()}</Badge>],
    ['Type', resource.resource_type.replace(/_/g, ' ')],
    ['Region', resource.region ?? '—'],
    ['Account', resource.account_id ?? '—'],
    ['Status', <Badge key="status" variant={statusVariant}>{resource.status}</Badge>],
    ['ARN', resource.arn ? <span key="arn" className="font-mono text-xs break-all">{resource.arn}</span> : '—'],
    ['Last scanned', resource.last_scanned_at ? new Date(resource.last_scanned_at).toLocaleString() : '—'],
  ]

  return (
    <div
      className="fixed top-0 right-0 h-full w-[420px] bg-slate-900 border-l border-slate-700 shadow-2xl z-50 overflow-y-auto"
      data-testid="detail-panel"
    >
      <div className="flex items-center justify-between p-4 border-b border-slate-700 sticky top-0 bg-slate-900">
        <div>
          <h2 className="text-slate-200 font-semibold">{resource.name}</h2>
          <p className="text-slate-500 text-xs font-mono">{resource.resource_id}</p>
        </div>
        <div className="flex items-center gap-2">
          {url && (
            <a
              href={url}
              target="_blank"
              rel="noopener noreferrer"
              className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-orange-400 transition-colors"
              title="Open in console"
            >
              <ExternalLink className="w-4 h-4" />
            </a>
          )}
          <button
            onClick={onClose}
            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
            aria-label="Close panel"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>

      <div className="p-4 space-y-6">
        {canScan && (
          <section>
            <button
              onClick={() => scanMutation.mutate()}
              disabled={scanMutation.isPending}
              className="flex items-center gap-2 px-3 py-1.5 bg-orange-500 hover:bg-orange-600 disabled:opacity-50 text-white text-sm font-medium rounded-lg transition-colors"
            >
              <PlayCircle className="w-4 h-4" />
              {scanMutation.isPending ? 'Queuing scan...' : 'Scan Now'}
            </button>

            {scanSuccessJobId && (
              <div className="mt-2 p-2 bg-green-950 border border-green-800 rounded text-green-400 text-xs flex items-center gap-2">
                <CheckCircle2 className="w-3.5 h-3.5 flex-shrink-0" />
                Side-scan queued — job {scanSuccessJobId}
              </div>
            )}
            {scanError && (
              <div className="mt-2 p-2 bg-red-950 border border-red-800 rounded text-red-400 text-xs">
                {scanError}
              </div>
            )}
          </section>
        )}

        <section>
          <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">
            Metadata
          </h3>
          <dl className="space-y-2">
            {metadataRows.map(([label, value]) => (
              <div key={String(label)} className="flex gap-2">
                <dt className="text-slate-500 text-sm w-24 flex-shrink-0">{label}</dt>
                <dd className="text-slate-300 text-sm">{value}</dd>
              </div>
            ))}
          </dl>
        </section>

        {Object.keys(resource.tags).length > 0 && (
          <section>
            <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">
              Tags
            </h3>
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(resource.tags).map(([k, v]) => (
                <span
                  key={k}
                  className="px-2 py-0.5 bg-slate-800 border border-slate-700 rounded text-xs text-slate-300"
                >
                  {k}: {v}
                </span>
              ))}
            </div>
          </section>
        )}

        <section>
          <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">
            Relationships ({resource.edges.length})
          </h3>
          {resource.edges.length === 0 ? (
            <p className="text-slate-600 text-sm">No edges found.</p>
          ) : (
            <ul className="space-y-1.5">
              {resource.edges.map((e, i) => (
                <li key={i} className="flex items-center gap-2 text-sm">
                  <span className="text-slate-500 text-xs">{e.direction === 'outbound' ? '→' : '←'}</span>
                  <span className="text-orange-400 text-xs font-mono">{e.edge_type}</span>
                  <span className="text-slate-400 font-mono text-xs">{e.peer_key}</span>
                  {e.peer_type && (
                    <span className="text-slate-600 text-xs">({e.peer_type})</span>
                  )}
                </li>
              ))}
            </ul>
          )}
        </section>

        <section>
          <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">
            Findings
          </h3>
          <p className="text-slate-600 text-sm">
            No findings yet — run a CSPM scan to see findings.
          </p>
        </section>
      </div>
    </div>
  )
}
