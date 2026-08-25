'use client'
import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, CheckCircle2 } from 'lucide-react'
import { providersApi, scansApi } from '@/lib/api'
import type { ProviderConfig } from '@/lib/types'
import { ProvidersTable } from '@/components/providers/ProvidersTable'
import { ConnectWizard } from '@/components/providers/ConnectWizard'
import { EditProviderModal } from '@/components/providers/EditProviderModal'

export default function ProvidersPage() {
  const router = useRouter()
  const queryClient = useQueryClient()
  const [showWizard, setShowWizard] = useState(false)
  const [editingProvider, setEditingProvider] = useState<ProviderConfig | null>(null)
  const [actionError, setActionError] = useState<string | null>(null)
  const [scanSuccess, setScanSuccess] = useState<string | null>(null)

  const { data, isLoading } = useQuery({
    queryKey: ['providers'],
    queryFn: () => providersApi.list().then((r) => r.data.data),
  })

  const invalidate = () => queryClient.invalidateQueries({ queryKey: ['providers'] })

  const toggleMutation = useMutation({
    mutationFn: ({ id, enabled }: { id: string; enabled: boolean }) =>
      providersApi.update(id, { enabled }),
    onSuccess: invalidate,
    onError: () => setActionError('Failed to update provider.'),
  })

  const discoverMutation = useMutation({
    mutationFn: (id: string) => providersApi.triggerDiscovery(id),
    onSuccess: invalidate,
    onError: () => setActionError('Failed to trigger discovery.'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => providersApi.delete(id),
    onSuccess: invalidate,
    onError: () => setActionError('Failed to delete provider.'),
  })

  const scanMutation = useMutation({
    mutationFn: (providerId: string) =>
      scansApi.trigger({ provider_id: providerId }),
    onSuccess: (res) => {
      const jobId = res.data.data.job_id
      setScanSuccess(`CSPM scan queued — job ${jobId}. Findings will appear shortly.`)
      setTimeout(() => setScanSuccess(null), 8000)
    },
    onError: () => setActionError('Failed to trigger CSPM scan. Check that provider credentials are configured.'),
  })

  const providers = data ?? []

  return (
    <div id="providers-page" className="min-h-screen bg-slate-950 text-slate-100">
      <div className="max-w-6xl mx-auto px-6 py-8">
        <div className="flex items-center justify-end mb-8">
          <button
            onClick={() => setShowWizard(true)}
            className="flex items-center gap-2 px-4 py-2 bg-orange-500 hover:bg-orange-600 text-white text-sm font-medium rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" />
            Connect Account
          </button>
        </div>

        {scanSuccess && (
          <div className="mb-4 p-3 bg-green-950 border border-green-800 rounded-lg text-green-400 text-sm flex items-center justify-between">
            <span className="flex items-center gap-2">
              <CheckCircle2 className="w-4 h-4 flex-shrink-0" />
              {scanSuccess}
            </span>
            <button onClick={() => setScanSuccess(null)} className="text-green-600 hover:text-green-400 ml-4">×</button>
          </div>
        )}

        {actionError && (
          <div className="mb-4 p-3 bg-red-950 border border-red-800 rounded-lg text-red-400 text-sm flex items-center justify-between">
            {actionError}
            <button onClick={() => setActionError(null)} className="text-red-600 hover:text-red-400 ml-4">×</button>
          </div>
        )}

        <div id="providers-table" className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
          {isLoading ? (
            <div className="py-16 text-center text-slate-500 text-sm">Loading...</div>
          ) : (
            <>
              <div className="px-4 py-3 border-b border-slate-800 flex items-center justify-between">
                <span className="text-slate-400 text-sm">
                  {providers.length} {providers.length === 1 ? 'account' : 'accounts'} connected
                </span>
              </div>
              <ProvidersTable
                providers={providers}
                onEdit={(p) => setEditingProvider(p)}
                onToggle={(id, enabled) => toggleMutation.mutateAsync({ id, enabled })}
                onDiscover={(id) => discoverMutation.mutateAsync(id)}
                onScan={(id) => scanMutation.mutateAsync(id)}
                onDelete={(id) => deleteMutation.mutateAsync(id)}
              />
            </>
          )}
        </div>
      </div>

      {showWizard && (
        <ConnectWizard
          onComplete={() => {
            setShowWizard(false)
            invalidate()
            router.push('/inventory')
          }}
          onCancel={() => setShowWizard(false)}
        />
      )}

      {editingProvider && (
        <EditProviderModal
          provider={editingProvider}
          onSave={() => {
            setEditingProvider(null)
            invalidate()
          }}
          onCancel={() => setEditingProvider(null)}
        />
      )}
    </div>
  )
}
