'use client'
import { useState } from 'react'
import { RefreshCw, Trash2, Power, PowerOff, Pencil, ShieldCheck, HeartPulse } from 'lucide-react'
import type { ProviderConfig, ProviderHealth, ProviderHealthLevel, ProviderType } from '@/lib/types'

const PROVIDER_LABELS: Record<ProviderType, string> = {
  aws: 'Amazon Web Services',
  azure: 'Microsoft Azure',
  gcp: 'Google Cloud Platform',
  k8s: 'Kubernetes',
}

const PROVIDER_BADGE_COLORS: Record<ProviderType, string> = {
  aws: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  azure: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  gcp: 'bg-green-500/15 text-green-400 border-green-500/30',
  k8s: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
}

const HEALTH_BADGE: Record<ProviderHealthLevel, { label: string; icon: string; classes: string }> = {
  healthy: { label: 'Healthy', icon: '✓', classes: 'bg-green-500/15 text-green-400 border-green-500/30' },
  degraded: { label: 'Degraded', icon: '⚠', classes: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30' },
  failed: { label: 'Failed', icon: '✕', classes: 'bg-red-500/15 text-red-400 border-red-500/30' },
}

export function HealthBadge({ health }: { health: ProviderHealthLevel }) {
  const badge = HEALTH_BADGE[health]
  return (
    <span
      data-testid={`health-badge-${health}`}
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium border ${badge.classes}`}
    >
      <span aria-hidden>{badge.icon}</span>
      {badge.label}
    </span>
  )
}

function providerIdentifier(p: ProviderConfig): string {
  return p.account_id ?? p.subscription_id ?? p.project_id ?? p.cluster_name ?? '—'
}

function relativeTime(iso: string | null | undefined): string {
  if (!iso) return '—'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60_000)
  if (mins < 1) return 'just now'
  if (mins < 60) return `${mins}m ago`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}h ago`
  return `${Math.floor(hours / 24)}d ago`
}

interface ProviderCardProps {
  provider: ProviderConfig
  onEdit: (provider: ProviderConfig) => void
  onToggle: (id: string, enabled: boolean) => Promise<unknown>
  onDiscover: (id: string) => Promise<unknown>
  onScan: (id: string) => Promise<unknown>
  onDelete: (id: string) => Promise<unknown>
  onTestConnection: (id: string) => Promise<ProviderHealth>
}

function TestConnectionResult({ result }: { result: ProviderHealth }) {
  if (result.health === 'healthy') {
    return (
      <div data-testid={`test-result-${result.provider_id}`} className="mt-2 text-xs">
        <span className="text-green-400">✓ Connected</span>
        <span className="text-slate-500 ml-2">{result.detail}</span>
        {result.latency_ms !== null && result.latency_ms !== undefined && (
          <span className="text-slate-600 ml-1">({result.latency_ms}ms)</span>
        )}
      </div>
    )
  }
  return (
    <div data-testid={`test-result-${result.provider_id}`} className="mt-2 text-xs" title={result.detail ?? undefined}>
      <span className="text-red-400">✕ Connection failed</span>
      <span className="text-slate-500 ml-2 line-clamp-1">{result.detail || result.reason}</span>
    </div>
  )
}

function ProviderCard({ provider: p, onEdit, onToggle, onDiscover, onScan, onDelete, onTestConnection }: ProviderCardProps) {
  const [busy, setBusy] = useState(false)
  const [testing, setTesting] = useState(false)
  const [lastTest, setLastTest] = useState<ProviderHealth | null>(null)

  // Live test result takes precedence; before any test runs, fall back to the
  // stored last probe outcome (if one exists) rendered as a static hint.
  const storedHint =
    !lastTest && p.last_health_check_at ? (
      <div className="mt-2 text-xs text-slate-500" title={p.last_health_result ?? undefined}>
        Last check {relativeTime(p.last_health_check_at)}
        {p.last_health_result ? `: ${p.last_health_result}` : ''}
      </div>
    ) : null

  const withBusy = (fn: () => Promise<unknown>) => async (): Promise<void> => {
    setBusy(true)
    try {
      await fn()
    } finally {
      setBusy(false)
    }
  }

  const runTest = async (): Promise<void> => {
    setTesting(true)
    try {
      setLastTest(await onTestConnection(p.key))
    } finally {
      setTesting(false)
    }
  }

  return (
    <div data-testid={`provider-card-${p.key}`} className="bg-slate-900 border border-slate-700 rounded-xl p-4">
      <div className="flex items-start justify-between mb-3">
        <div>
          <span
            className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${PROVIDER_BADGE_COLORS[p.provider]} mb-2`}
          >
            {PROVIDER_LABELS[p.provider]}
          </span>
          <div className="text-slate-200 font-medium">{p.display_name}</div>
          <div className="text-slate-500 text-xs font-mono mt-0.5">{providerIdentifier(p)}</div>
        </div>
        <div className="flex flex-col items-end gap-1.5">
          {!p.enabled && (
            <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border bg-slate-500/15 text-slate-400 border-slate-500/30">
              Disabled
            </span>
          )}
          <HealthBadge health={lastTest?.health ?? (p.status === 'error' ? 'failed' : p.enabled ? 'healthy' : 'degraded')} />
        </div>
      </div>

      {p.regions.length > 0 && (
        <div className="text-slate-500 text-xs mb-3">Regions: {p.regions.slice(0, 4).join(', ')}</div>
      )}

      <div className="text-slate-500 text-xs mb-1">
        Last discovery: {relativeTime(p.last_discovery_at)} · Credential: {p.credential_type}
      </div>
      {storedHint}
      {lastTest && <TestConnectionResult result={lastTest} />}

      <div className="flex items-center gap-2 mt-4 flex-wrap">
        <button
          disabled={testing || !p.enabled}
          onClick={() => runTest()}
          data-testid={`test-connection-${p.key}`}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-cyan-500/10 hover:bg-cyan-500/20 text-cyan-400 rounded-lg border border-cyan-500/20 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          <HeartPulse className={`w-3 h-3 ${testing ? 'animate-pulse' : ''}`} />
          {testing ? 'Testing…' : 'Test Connection'}
        </button>
        <button
          onClick={() => onEdit(p)}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-slate-700/50 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-600 transition-colors"
        >
          <Pencil className="w-3 h-3" />
          Edit
        </button>
        <button
          disabled={busy || !p.enabled}
          onClick={withBusy(() => onDiscover(p.key))}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-orange-500/10 hover:bg-orange-500/20 text-orange-400 rounded-lg border border-orange-500/20 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          <RefreshCw className={`w-3 h-3 ${busy ? 'animate-spin' : ''}`} />
          Rediscover
        </button>
        <button
          disabled={busy || !p.enabled}
          onClick={withBusy(() => onScan(p.key))}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-green-500/10 hover:bg-green-500/20 text-green-400 rounded-lg border border-green-500/20 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          <ShieldCheck className="w-3 h-3" />
          Scan Now
        </button>
        <button
          disabled={busy}
          onClick={withBusy(() => onToggle(p.key, !p.enabled))}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-slate-700/50 hover:bg-slate-700 text-slate-300 rounded-lg border border-slate-600 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          {p.enabled ? <PowerOff className="w-3 h-3" /> : <Power className="w-3 h-3 text-green-400" />}
          {p.enabled ? 'Disable' : 'Enable'}
        </button>
        <button
          disabled={busy}
          onClick={withBusy(() => onDelete(p.key))}
          className="ml-auto p-1.5 text-slate-500 hover:text-red-400 hover:bg-slate-700 rounded disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          title="Delete"
        >
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  )
}

interface ProvidersCardGridProps extends Omit<ProviderCardProps, 'provider'> {
  providers: ProviderConfig[]
}

const PROVIDER_ORDER: ProviderType[] = ['aws', 'azure', 'gcp', 'k8s']

/** Account Center as grouped connection-health cards (US-14.20): one section per
 * cloud with an account count in the header, one card per connected account. */
export function ProvidersCardGrid({
  providers,
  onEdit,
  onToggle,
  onDiscover,
  onScan,
  onDelete,
  onTestConnection,
}: ProvidersCardGridProps) {
  if (providers.length === 0) {
    return (
      <div className="text-center py-16 text-slate-500" data-testid="providers-empty">
        <p className="text-sm">No cloud accounts connected yet.</p>
      </div>
    )
  }

  const groups = PROVIDER_ORDER.map((type) => ({
    type,
    items: providers.filter((p) => p.provider === type),
  })).filter((g) => g.items.length > 0)

  return (
    <div id="providers-card-grid" className="space-y-8">
      {groups.map(({ type, items }) => (
        <section key={type} aria-label={PROVIDER_LABELS[type]}>
          <h2 className="flex items-center gap-2 text-sm text-slate-300 mb-3">
            <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${PROVIDER_BADGE_COLORS[type]}`}>
              {type.toUpperCase()}
            </span>
            {PROVIDER_LABELS[type]}
            <span data-testid={`provider-count-${type}`} className="text-slate-500 text-xs">
              ({items.length} {items.length === 1 ? 'account' : 'accounts'})
            </span>
          </h2>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {items.map((p) => (
              <ProviderCard
                key={p.key}
                provider={p}
                onEdit={onEdit}
                onToggle={onToggle}
                onDiscover={onDiscover}
                onScan={onScan}
                onDelete={onDelete}
                onTestConnection={onTestConnection}
              />
            ))}
          </div>
        </section>
      ))}
    </div>
  )
}
