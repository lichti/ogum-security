'use client'
import { useState } from 'react'
import { RefreshCw, Trash2, Power, PowerOff, ChevronRight } from 'lucide-react'
import type { ProviderConfig, ProviderStatus } from '@/lib/types'

const PROVIDER_LABELS: Record<string, string> = {
  aws: 'Amazon Web Services',
  azure: 'Microsoft Azure',
  gcp: 'Google Cloud Platform',
  k8s: 'Kubernetes',
}

const PROVIDER_BADGE_COLORS: Record<string, string> = {
  aws: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  azure: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  gcp: 'bg-green-500/15 text-green-400 border-green-500/30',
  k8s: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
}

const STATUS_BADGE: Record<ProviderStatus, { label: string; classes: string }> = {
  active: { label: 'Active', classes: 'bg-green-500/15 text-green-400 border-green-500/30' },
  pending: { label: 'Pending', classes: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30' },
  error: { label: 'Error', classes: 'bg-red-500/15 text-red-400 border-red-500/30' },
  disabled: { label: 'Disabled', classes: 'bg-slate-500/15 text-slate-400 border-slate-500/30' },
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

interface ProvidersTableProps {
  providers: ProviderConfig[]
  onToggle: (id: string, enabled: boolean) => Promise<unknown>
  onDiscover: (id: string) => Promise<unknown>
  onDelete: (id: string) => Promise<unknown>
}

export function ProvidersTable({ providers, onToggle, onDiscover, onDelete }: ProvidersTableProps) {
  const [busy, setBusy] = useState<Record<string, boolean>>({})

  const withBusy = (id: string, fn: () => Promise<unknown>) => async (): Promise<void> => {
    setBusy((b) => ({ ...b, [id]: true }))
    try { await fn() } finally { setBusy((b) => ({ ...b, [id]: false })) }
  }

  if (providers.length === 0) {
    return (
      <div className="text-center py-16 text-slate-500">
        <p className="text-sm">No cloud accounts connected yet.</p>
      </div>
    )
  }

  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-slate-800">
            <th className="text-left py-3 px-4 text-slate-400 font-medium">Provider</th>
            <th className="text-left py-3 px-4 text-slate-400 font-medium">Display Name</th>
            <th className="text-left py-3 px-4 text-slate-400 font-medium">Account / ID</th>
            <th className="text-left py-3 px-4 text-slate-400 font-medium">Regions</th>
            <th className="text-left py-3 px-4 text-slate-400 font-medium">Status</th>
            <th className="text-left py-3 px-4 text-slate-400 font-medium">Last Discovery</th>
            <th className="text-right py-3 px-4 text-slate-400 font-medium">Actions</th>
          </tr>
        </thead>
        <tbody>
          {providers.map((p) => {
            const status = STATUS_BADGE[p.status ?? 'pending']
            const isBusy = busy[p.key]
            return (
              <tr key={p.key} className="border-b border-slate-800/60 hover:bg-slate-800/30 transition-colors">
                <td className="py-3 px-4">
                  <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${PROVIDER_BADGE_COLORS[p.provider]}`}>
                    {p.provider.toUpperCase()}
                  </span>
                </td>
                <td className="py-3 px-4 text-slate-200 font-medium">{p.display_name}</td>
                <td className="py-3 px-4 text-slate-400 font-mono text-xs">{providerIdentifier(p)}</td>
                <td className="py-3 px-4 text-slate-400 text-xs">
                  {p.regions.length > 0
                    ? p.regions.slice(0, 2).join(', ') + (p.regions.length > 2 ? ` +${p.regions.length - 2}` : '')
                    : '—'}
                </td>
                <td className="py-3 px-4">
                  <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${status.classes}`}>
                    {status.label}
                  </span>
                </td>
                <td className="py-3 px-4 text-slate-400 text-xs">{relativeTime(p.last_discovery_at)}</td>
                <td className="py-3 px-4">
                  <div className="flex items-center justify-end gap-1">
                    <button
                      title="Re-trigger discovery"
                      disabled={isBusy || !p.enabled}
                      onClick={withBusy(p.key, () => onDiscover(p.key))}
                      className="p-1.5 rounded text-slate-400 hover:text-orange-400 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                    >
                      <RefreshCw className={`w-3.5 h-3.5 ${isBusy ? 'animate-spin' : ''}`} />
                    </button>
                    <button
                      title={p.enabled ? 'Disable provider' : 'Enable provider'}
                      disabled={isBusy}
                      onClick={withBusy(p.key, () => onToggle(p.key, !p.enabled))}
                      className="p-1.5 rounded text-slate-400 hover:text-slate-200 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                    >
                      {p.enabled
                        ? <PowerOff className="w-3.5 h-3.5" />
                        : <Power className="w-3.5 h-3.5 text-green-400" />}
                    </button>
                    <button
                      title="Delete provider"
                      disabled={isBusy}
                      onClick={withBusy(p.key, () => onDelete(p.key))}
                      className="p-1.5 rounded text-slate-400 hover:text-red-400 hover:bg-slate-700 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

interface ProviderCardProps {
  provider: ProviderConfig
  onToggle: (id: string, enabled: boolean) => Promise<unknown>
  onDiscover: (id: string) => Promise<unknown>
  onDelete: (id: string) => Promise<unknown>
}

export function ProviderCard({ provider: p, onToggle, onDiscover, onDelete }: ProviderCardProps) {
  const [busy, setBusy] = useState(false)
  const status = STATUS_BADGE[p.status ?? 'pending']

  const withBusy = (fn: () => Promise<unknown>) => async (): Promise<void> => {
    setBusy(true)
    try { await fn() } finally { setBusy(false) }
  }

  return (
    <div className="bg-slate-900 border border-slate-700 rounded-xl p-4">
      <div className="flex items-start justify-between mb-3">
        <div>
          <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${PROVIDER_BADGE_COLORS[p.provider]} mb-2`}>
            {PROVIDER_LABELS[p.provider] ?? p.provider.toUpperCase()}
          </span>
          <div className="text-slate-200 font-medium">{p.display_name}</div>
          <div className="text-slate-500 text-xs font-mono mt-0.5">{providerIdentifier(p)}</div>
        </div>
        <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${status.classes}`}>
          {status.label}
        </span>
      </div>

      {p.regions.length > 0 && (
        <div className="text-slate-500 text-xs mb-3">
          Regions: {p.regions.join(', ')}
        </div>
      )}

      <div className="text-slate-500 text-xs mb-4">
        Last discovery: {relativeTime(p.last_discovery_at)}
      </div>

      <div className="flex items-center gap-2">
        <button
          disabled={busy || !p.enabled}
          onClick={withBusy(() => onDiscover(p.key))}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-orange-500/10 hover:bg-orange-500/20 text-orange-400 rounded-lg border border-orange-500/20 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          <RefreshCw className={`w-3 h-3 ${busy ? 'animate-spin' : ''}`} />
          Rediscover
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
