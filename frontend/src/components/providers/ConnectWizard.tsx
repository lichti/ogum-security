'use client'
import { useState } from 'react'
import { CheckCircle, ChevronRight, Loader2 } from 'lucide-react'
import { providersApi } from '@/lib/api'

type Step = 'select' | 'configure' | 'connecting' | 'done'

const PROVIDERS = [
  { id: 'aws', name: 'Amazon Web Services', description: 'EC2, S3, IAM, RDS, Lambda and more' },
  { id: 'azure', name: 'Microsoft Azure', description: 'VMs, VNets, AKS, Storage Accounts' },
  { id: 'gcp', name: 'Google Cloud Platform', description: 'Compute, GCS, GKE, Cloud SQL' },
  { id: 'k8s', name: 'Kubernetes', description: 'Pods, Deployments, Services, RBAC' },
] as const

interface ConnectWizardProps {
  onComplete: () => void
  onCancel: () => void
}

export function ConnectWizard({ onComplete, onCancel }: ConnectWizardProps) {
  const [step, setStep] = useState<Step>('select')
  const [selectedProvider, setSelectedProvider] = useState<string>('')
  const [form, setForm] = useState({
    display_name: '',
    account_id: '',
    subscription_id: '',
    project_id: '',
    cluster_name: '',
    regions: 'us-east-1',
  })
  const [error, setError] = useState<string | null>(null)
  const [jobId, setJobId] = useState<string | null>(null)

  const handleConnect = async () => {
    setStep('connecting')
    setError(null)
    try {
      const regions = form.regions.split(',').map((r) => r.trim()).filter(Boolean)
      const resp = await providersApi.register({
        provider: selectedProvider,
        display_name: form.display_name || `${selectedProvider.toUpperCase()} Account`,
        account_id: form.account_id || undefined,
        subscription_id: form.subscription_id || undefined,
        project_id: form.project_id || undefined,
        cluster_name: form.cluster_name || undefined,
        regions,
        validate_connection: false,
      })
      setJobId(resp.data.data.discovery_job_id ?? null)
      setStep('done')
    } catch (e: unknown) {
      const msg =
        e instanceof Error
          ? e.message
          : (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
            'Connection failed. Please check your settings.'
      setError(msg)
      setStep('configure')
    }
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50">
      <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-lg p-6 shadow-2xl">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-lg font-semibold text-slate-100">Connect Cloud Account</h2>
          <button onClick={onCancel} className="text-slate-500 hover:text-slate-300 text-xl leading-none">
            ×
          </button>
        </div>

        {step === 'select' && (
          <div className="space-y-3">
            <p className="text-slate-400 text-sm mb-4">Select the cloud provider to connect:</p>
            {PROVIDERS.map((p) => (
              <button
                key={p.id}
                onClick={() => {
                  setSelectedProvider(p.id)
                  setStep('configure')
                }}
                className="w-full text-left p-4 rounded-lg border border-slate-700 hover:border-orange-500 hover:bg-slate-800 transition-colors group"
              >
                <div className="flex items-center justify-between">
                  <div>
                    <div className="text-slate-200 font-medium">{p.name}</div>
                    <div className="text-slate-500 text-sm">{p.description}</div>
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-600 group-hover:text-orange-400" />
                </div>
              </button>
            ))}
          </div>
        )}

        {step === 'configure' && (
          <div className="space-y-4">
            <button
              onClick={() => setStep('select')}
              className="text-slate-500 hover:text-slate-300 text-sm flex items-center gap-1"
            >
              ← Back
            </button>

            <div>
              <label className="block text-sm text-slate-400 mb-1">Display name</label>
              <input
                type="text"
                placeholder={`${selectedProvider.toUpperCase()} Production`}
                value={form.display_name}
                onChange={(e) => setForm((f) => ({ ...f, display_name: e.target.value }))}
                className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-orange-500"
              />
            </div>

            {selectedProvider === 'aws' && (
              <>
                <div>
                  <label className="block text-sm text-slate-400 mb-1">AWS Account ID</label>
                  <input
                    type="text"
                    placeholder="123456789012"
                    value={form.account_id}
                    onChange={(e) => setForm((f) => ({ ...f, account_id: e.target.value }))}
                    className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-orange-500"
                  />
                </div>
                <div>
                  <label className="block text-sm text-slate-400 mb-1">Regions (comma-separated)</label>
                  <input
                    type="text"
                    placeholder="us-east-1, us-west-2"
                    value={form.regions}
                    onChange={(e) => setForm((f) => ({ ...f, regions: e.target.value }))}
                    className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-orange-500"
                  />
                </div>
              </>
            )}

            {selectedProvider === 'azure' && (
              <div>
                <label className="block text-sm text-slate-400 mb-1">Subscription ID</label>
                <input
                  type="text"
                  placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                  value={form.subscription_id}
                  onChange={(e) => setForm((f) => ({ ...f, subscription_id: e.target.value }))}
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-orange-500"
                />
              </div>
            )}

            {selectedProvider === 'gcp' && (
              <div>
                <label className="block text-sm text-slate-400 mb-1">Project ID</label>
                <input
                  type="text"
                  placeholder="my-project-id"
                  value={form.project_id}
                  onChange={(e) => setForm((f) => ({ ...f, project_id: e.target.value }))}
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-orange-500"
                />
              </div>
            )}

            {selectedProvider === 'k8s' && (
              <div>
                <label className="block text-sm text-slate-400 mb-1">Cluster Name</label>
                <input
                  type="text"
                  placeholder="prod-cluster"
                  value={form.cluster_name}
                  onChange={(e) => setForm((f) => ({ ...f, cluster_name: e.target.value }))}
                  className="w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-orange-500"
                />
              </div>
            )}

            {error && (
              <div className="text-red-400 text-sm bg-red-950 border border-red-800 rounded-lg p-3">
                {error}
              </div>
            )}

            <button
              onClick={handleConnect}
              className="w-full py-2.5 bg-orange-500 hover:bg-orange-600 text-white font-medium rounded-lg transition-colors"
            >
              Connect &amp; Start Discovery
            </button>
          </div>
        )}

        {step === 'connecting' && (
          <div className="text-center py-8">
            <Loader2 className="w-8 h-8 text-orange-400 animate-spin mx-auto mb-4" />
            <p className="text-slate-300">Connecting and starting discovery...</p>
            <p className="text-slate-500 text-sm mt-1">This may take a moment.</p>
          </div>
        )}

        {step === 'done' && (
          <div className="text-center py-8">
            <CheckCircle className="w-10 h-10 text-green-400 mx-auto mb-4" />
            <h3 className="text-slate-200 font-semibold mb-2">Account Connected!</h3>
            <p className="text-slate-400 text-sm mb-1">Discovery is running in the background.</p>
            {jobId && <p className="text-slate-600 text-xs font-mono">Job: {jobId}</p>}
            <button
              onClick={onComplete}
              className="mt-6 px-6 py-2 bg-orange-500 hover:bg-orange-600 text-white text-sm font-medium rounded-lg transition-colors"
            >
              View Inventory
            </button>
          </div>
        )}
      </div>
    </div>
  )
}
