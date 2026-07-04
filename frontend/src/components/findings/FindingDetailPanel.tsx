'use client'
import { Check, Copy, X } from 'lucide-react'
import { useEffect, useState } from 'react'
import { Badge, type BadgeVariant } from '@/components/ui/Badge'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { MuteModal } from '@/components/findings/MuteModal'
import { findingsApi } from '@/lib/api'
import type { FindingDetail } from '@/lib/types'

interface FindingDetailPanelProps {
  findingKey: string | null
  onClose: () => void
  onMuted?: () => void
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }
  return (
    <button
      onClick={copy}
      className="p-1 rounded hover:bg-slate-700 text-slate-500 hover:text-slate-300 transition-colors"
      aria-label="Copy to clipboard"
    >
      {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
    </button>
  )
}

export function FindingDetailPanel({ findingKey, onClose, onMuted }: FindingDetailPanelProps) {
  const [finding, setFinding] = useState<FindingDetail | null>(null)
  const [loading, setLoading] = useState(false)
  const [showMuteModal, setShowMuteModal] = useState(false)
  const [mutingLoading, setMutingLoading] = useState(false)

  useEffect(() => {
    if (!findingKey) { setFinding(null); return }
    setLoading(true)
    findingsApi.get(findingKey)
      .then((r) => setFinding(r.data.data))
      .catch(() => setFinding(null))
      .finally(() => setLoading(false))
  }, [findingKey])

  useEffect(() => {
    const handler = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [onClose])

  if (!findingKey) return null

  const providerVariant: BadgeVariant = finding ? (`provider-${finding.provider}` as BadgeVariant) : 'default'
  const canMute = finding?.status === 'FAIL'

  const handleMute = async (reason: string) => {
    if (!findingKey) return
    setMutingLoading(true)
    try {
      const r = await findingsApi.mute(findingKey, reason)
      setFinding(r.data.data)
      setShowMuteModal(false)
      onMuted?.()
    } catch {
      /* ignore — UI stays open */
    } finally {
      setMutingLoading(false)
    }
  }

  return (
    <>
      <div
        className="fixed inset-0 z-40"
        onClick={onClose}
        aria-hidden="true"
      />
      <div
        className="fixed top-0 right-0 h-full w-[440px] bg-slate-900 border-l border-slate-700 shadow-2xl z-50 overflow-y-auto"
        data-testid="finding-detail-panel"
      >
        <div className="flex items-start justify-between p-4 border-b border-slate-700 sticky top-0 bg-slate-900">
          <div className="flex-1 min-w-0 pr-2">
            {loading ? (
              <div className="h-5 w-48 bg-slate-800 rounded animate-pulse" />
            ) : (
              <>
                <h2 className="text-slate-200 font-semibold text-sm leading-snug">{finding?.title}</h2>
                <p className="text-slate-500 text-xs font-mono mt-0.5">{finding?.check_id}</p>
              </>
            )}
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 flex-shrink-0"
            aria-label="Close panel"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {loading && (
          <div className="p-4 space-y-3">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="h-4 bg-slate-800 rounded animate-pulse" style={{ width: `${70 + i * 5}%` }} />
            ))}
          </div>
        )}

        {!loading && finding && (
          <div className="p-4 space-y-6">
            {/* Badges row */}
            <div className="flex flex-wrap gap-2">
              <SeverityBadge severity={finding.severity} />
              <Badge variant={providerVariant}>{finding.provider.toUpperCase()}</Badge>
              {finding.source === 'iac' && <Badge variant="default">IaC</Badge>}
              {finding.status === 'MUTED' && <Badge variant="status-deleted">MUTED</Badge>}
              {finding.status === 'ACCEPTED' && <Badge variant="default">ACCEPTED</Badge>}
            </div>

            {/* Resource */}
            <section>
              <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">Resource</h3>
              <dl className="space-y-2">
                {[
                  ['Type', finding.resource_type.replace(/_/g, ' ')],
                  ['ARN / ID', finding.resource_arn ?? finding.resource_id],
                  ['Region', finding.region ?? '—'],
                  ['Account', finding.account_id],
                ].map(([label, value]) => (
                  <div key={label} className="flex gap-2">
                    <dt className="text-slate-500 text-sm w-20 flex-shrink-0">{label}</dt>
                    <dd className="text-slate-300 text-sm font-mono text-xs break-all">{value}</dd>
                  </div>
                ))}
              </dl>
            </section>

            {/* Risk */}
            <section>
              <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">Risk</h3>
              <p className="text-slate-400 text-sm leading-relaxed">{finding.description}</p>
            </section>

            {/* Remediation */}
            {finding.remediation && (
              <section>
                <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">Remediation</h3>
                <p className="text-slate-400 text-sm leading-relaxed mb-3">{finding.remediation}</p>
                {finding.cli_command && (
                  <div className="bg-slate-950 border border-slate-800 rounded p-3 flex items-start gap-2">
                    <code className="text-green-400 text-xs font-mono flex-1 break-all">
                      {finding.cli_command}
                    </code>
                    <CopyButton text={finding.cli_command} />
                  </div>
                )}
              </section>
            )}

            {/* Frameworks */}
            {finding.framework_mapping.length > 0 && (
              <section>
                <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">Frameworks</h3>
                <div className="flex flex-wrap gap-1.5">
                  {finding.framework_mapping.map((fw) => (
                    <Badge key={fw} variant="default">{fw}</Badge>
                  ))}
                </div>
              </section>
            )}

            {/* Attack Paths */}
            <section>
              <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider mb-3">
                Attack Paths
              </h3>
              <p className="text-slate-600 text-sm">No attack paths detected — Ogum.Graph coming in Epic 02.</p>
            </section>

            {/* Actions */}
            <section className="border-t border-slate-800 pt-4 flex flex-wrap gap-2">
              {canMute && (
                <button
                  onClick={() => setShowMuteModal(true)}
                  className="px-3 py-1.5 text-sm border border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-500 rounded transition-colors"
                >
                  Mute Finding
                </button>
              )}
              {finding.mute_reason && (
                <p className="text-xs text-slate-600 w-full">Muted: {finding.mute_reason}</p>
              )}
              <button
                disabled
                className="px-3 py-1.5 text-sm border border-orange-500/30 text-orange-400/50 rounded cursor-not-allowed"
                title="Coming in Epic 05 — Ogum.AI"
              >
                Generate PR ✨
              </button>
            </section>
          </div>
        )}
      </div>

      {showMuteModal && finding && (
        <MuteModal
          findingTitle={finding.title}
          onConfirm={handleMute}
          onCancel={() => setShowMuteModal(false)}
          loading={mutingLoading}
        />
      )}
    </>
  )
}
