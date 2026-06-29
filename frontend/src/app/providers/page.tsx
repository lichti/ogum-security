'use client'
import { useState } from 'react'
import { useRouter } from 'next/navigation'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus } from 'lucide-react'
import { providersApi } from '@/lib/api'
import { ProvidersTable } from '@/components/providers/ProvidersTable'
import { ConnectWizard } from '@/components/providers/ConnectWizard'

export default function ProvidersPage() {
  const router = useRouter()
  const queryClient = useQueryClient()
  const [showWizard, setShowWizard] = useState(false)
  const [actionError, setActionError] = useState<string | null>(null)

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

  const providers = data ?? []

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100">
      <div className="max-w-6xl mx-auto px-6 py-8">
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl font-semibold text-slate-100">Connected Accounts</h1>
            <p className="text-slate-400 text-sm mt-1">
              Manage cloud provider connections and trigger discovery jobs.
            </p>
          </div>
          <button
            onClick={() => setShowWizard(true)}
            className="flex items-center gap-2 px-4 py-2 bg-orange-500 hover:bg-orange-600 text-white text-sm font-medium rounded-lg transition-colors"
          >
            <Plus className="w-4 h-4" />
            Connect Account
          </button>
        </div>

        {actionError && (
          <div className="mb-4 p-3 bg-red-950 border border-red-800 rounded-lg text-red-400 text-sm flex items-center justify-between">
            {actionError}
            <button onClick={() => setActionError(null)} className="text-red-600 hover:text-red-400 ml-4">×</button>
          </div>
        )}

        <div className="bg-slate-900 border border-slate-800 rounded-xl overflow-hidden">
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
                onToggle={(id, enabled) => toggleMutation.mutateAsync({ id, enabled })}
                onDiscover={(id) => discoverMutation.mutateAsync(id)}
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
    </div>
  )
}
