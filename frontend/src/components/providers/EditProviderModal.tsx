'use client'
import { useState } from 'react'
import { ChevronDown, ChevronUp, Loader2 } from 'lucide-react'
import { providersApi } from '@/lib/api'
import type { ProviderConfig, DiscoverRequest } from '@/lib/types'

const INPUT_CLASS =
  'w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-orange-500 font-mono'
const INPUT_READONLY_CLASS =
  'w-full px-3 py-2 bg-slate-900 border border-slate-800 rounded-lg text-sm text-slate-500 font-mono cursor-not-allowed'
const TEXTAREA_CLASS =
  'w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-orange-500 font-mono h-32 resize-none'
const LABEL_CLASS = 'block text-sm text-slate-400 mb-1'

interface EditProviderModalProps {
  provider: ProviderConfig
  onSave: () => void
  onCancel: () => void
}

export function EditProviderModal({ provider, onSave, onCancel }: EditProviderModalProps) {
  const [displayName, setDisplayName] = useState(provider.display_name)
  const [regions, setRegions] = useState(provider.regions.join(', '))
  const [roleArn, setRoleArn] = useState(provider.role_arn ?? '')
  const [azureTenantId, setAzureTenantId] = useState(provider.azure_tenant_id ?? '')
  const [azureClientId, setAzureClientId] = useState(provider.azure_client_id ?? '')

  // Credential fields — stored in ArangoDB for scheduled jobs; re-enter to update
  const [showCredSection, setShowCredSection] = useState(false)
  const [awsKeyId, setAwsKeyId] = useState('')
  const [awsKeySecret, setAwsKeySecret] = useState('')
  const [azureClientSecret, setAzureClientSecret] = useState('')
  const [gcpJson, setGcpJson] = useState('')
  const [kubeconfig, setKubeconfig] = useState('')

  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const hasEphemeralCreds = (): boolean => {
    if (provider.provider === 'aws') return !!(awsKeyId && awsKeySecret)
    if (provider.provider === 'azure') return !!azureClientSecret
    if (provider.provider === 'gcp') return !!gcpJson.trim()
    if (provider.provider === 'k8s') return !!kubeconfig.trim()
    return false
  }

  const buildDiscoverRequest = (): DiscoverRequest | null => {
    if (provider.provider === 'aws' && awsKeyId && awsKeySecret) {
      return { aws_access_key_id: awsKeyId, aws_secret_access_key: awsKeySecret }
    }
    if (provider.provider === 'azure' && azureClientSecret) {
      return { azure_client_secret: azureClientSecret }
    }
    if (provider.provider === 'gcp' && gcpJson.trim()) {
      try {
        return { gcp_service_account_json: JSON.parse(gcpJson) }
      } catch {
        throw new Error('Invalid JSON in Service Account field.')
      }
    }
    if (provider.provider === 'k8s' && kubeconfig.trim()) {
      try {
        return { kubeconfig: JSON.parse(kubeconfig) }
      } catch {
        throw new Error('Invalid JSON in Kubeconfig field.')
      }
    }
    return null
  }

  const handleSave = async () => {
    setSaving(true)
    setError(null)
    try {
      const regionList = regions.split(',').map((r) => r.trim()).filter(Boolean)

      // Build credential update payload (only include fields that were filled in)
      const credUpdate: Record<string, unknown> = {}
      if (provider.provider === 'aws') {
        if (awsKeyId) credUpdate.aws_access_key_id = awsKeyId
        if (awsKeySecret) credUpdate.aws_secret_access_key = awsKeySecret
      }
      if (provider.provider === 'azure' && azureClientSecret) {
        credUpdate.azure_client_secret = azureClientSecret
      }
      if (provider.provider === 'gcp' && gcpJson.trim()) {
        credUpdate.gcp_service_account_json = JSON.parse(gcpJson)
      }
      if (provider.provider === 'k8s' && kubeconfig.trim()) {
        credUpdate.kubeconfig = JSON.parse(kubeconfig)
      }

      await providersApi.update(provider.key, {
        display_name: displayName || undefined,
        // Send explicit empty list for AWS to mean "all regions"; undefined = don't update
        regions: provider.provider === 'aws' ? regionList : undefined,
        role_arn: provider.provider === 'aws' ? (roleArn || null) : undefined,
        azure_tenant_id:
          provider.provider === 'azure' ? (azureTenantId || null) : undefined,
        azure_client_id:
          provider.provider === 'azure' ? (azureClientId || null) : undefined,
        ...credUpdate,
      })

      onSave()
    } catch (e: unknown) {
      const msg =
        e instanceof Error
          ? e.message
          : (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
            'Failed to save changes.'
      setError(msg)
    } finally {
      setSaving(false)
    }
  }

  const credSectionLabel = {
    aws: 'Update API Keys (dev only)',
    azure: 'Update Client Secret',
    gcp: 'Update Service Account JSON',
    k8s: 'Update Kubeconfig',
  }[provider.provider]

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-lg shadow-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-6 pb-4">
          <div>
            <h2 className="text-lg font-semibold text-slate-100">Edit Provider</h2>
            <p className="text-slate-500 text-xs mt-0.5 font-mono">
              {provider.provider.toUpperCase()} ·{' '}
              {provider.account_id ?? provider.subscription_id ?? provider.project_id ?? provider.cluster_name ?? provider.key}
            </p>
          </div>
          <button onClick={onCancel} className="text-slate-500 hover:text-slate-300 text-xl leading-none">
            ×
          </button>
        </div>

        <div className="px-6 pb-6 space-y-4">
          {/* Display name */}
          <div>
            <label className={LABEL_CLASS}>Display name</label>
            <input
              type="text"
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              className={INPUT_CLASS}
            />
          </div>

          {/* Regions — AWS only */}
          {provider.provider === 'aws' && (
            <div>
              <label className={LABEL_CLASS}>Regions (comma-separated)</label>
              <input
                type="text"
                value={regions}
                onChange={(e) => setRegions(e.target.value)}
                placeholder="Leave empty to scan all available regions"
                className={INPUT_CLASS}
              />
            </div>
          )}

          {/* AWS — Role ARN */}
          {provider.provider === 'aws' && (
            <div>
              <label className={LABEL_CLASS}>IAM Role ARN</label>
              <input
                type="text"
                value={roleArn}
                onChange={(e) => setRoleArn(e.target.value)}
                placeholder="arn:aws:iam::123456789012:role/OgumReadRole"
                className={INPUT_CLASS}
              />
              <p className="text-slate-500 text-xs mt-1">
                Leave empty to use ambient worker credentials. Stored in config (not a secret).
              </p>
            </div>
          )}

          {/* Azure — Subscription ID (readonly) */}
          {provider.provider === 'azure' && provider.subscription_id && (
            <div>
              <label className={LABEL_CLASS}>Subscription ID <span className="text-slate-600">(read-only)</span></label>
              <input type="text" value={provider.subscription_id} readOnly className={INPUT_READONLY_CLASS} />
            </div>
          )}

          {/* Azure — Tenant ID + Client ID */}
          {provider.provider === 'azure' && (
            <>
              <div>
                <label className={LABEL_CLASS}>Azure Tenant ID</label>
                <input
                  type="text"
                  value={azureTenantId}
                  onChange={(e) => setAzureTenantId(e.target.value)}
                  placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                  className={INPUT_CLASS}
                />
              </div>
              <div>
                <label className={LABEL_CLASS}>Client ID (App Registration)</label>
                <input
                  type="text"
                  value={azureClientId}
                  onChange={(e) => setAzureClientId(e.target.value)}
                  placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                  className={INPUT_CLASS}
                />
              </div>
            </>
          )}

          {/* GCP — Project ID (readonly) */}
          {provider.provider === 'gcp' && provider.project_id && (
            <div>
              <label className={LABEL_CLASS}>Project ID <span className="text-slate-600">(read-only)</span></label>
              <input type="text" value={provider.project_id} readOnly className={INPUT_READONLY_CLASS} />
            </div>
          )}

          {/* K8s — Cluster Name (readonly) */}
          {provider.provider === 'k8s' && provider.cluster_name && (
            <div>
              <label className={LABEL_CLASS}>Cluster Name <span className="text-slate-600">(read-only)</span></label>
              <input type="text" value={provider.cluster_name} readOnly className={INPUT_READONLY_CLASS} />
            </div>
          )}

          {/* Collapsible ephemeral credentials section */}
          <div className="border border-slate-700 rounded-lg overflow-hidden">
            <button
              type="button"
              onClick={() => setShowCredSection((v) => !v)}
              className="w-full flex items-center justify-between px-4 py-3 text-sm text-slate-300 hover:bg-slate-800 transition-colors"
            >
              <span>{credSectionLabel}</span>
              {showCredSection
                ? <ChevronUp className="w-4 h-4 text-slate-500" />
                : <ChevronDown className="w-4 h-4 text-slate-500" />}
            </button>
            {showCredSection && (
              <div className="px-4 pb-4 border-t border-slate-700 pt-3 space-y-3">
                <p className="text-xs text-slate-500">
                  Credentials provided here are passed directly to the discovery worker and are{' '}
                  <strong className="text-slate-400">not stored</strong>. Filling in these fields
                  will trigger a re-discovery after saving.
                </p>

                {/* AWS static keys */}
                {provider.provider === 'aws' && (
                  <>
                    <div>
                      <label className={LABEL_CLASS}>Access Key ID</label>
                      <input
                        type="text"
                        value={awsKeyId}
                        onChange={(e) => setAwsKeyId(e.target.value)}
                        placeholder="AKIAIOSFODNN7EXAMPLE"
                        className={INPUT_CLASS}
                      />
                    </div>
                    <div>
                      <label className={LABEL_CLASS}>Secret Access Key</label>
                      <input
                        type="password"
                        value={awsKeySecret}
                        onChange={(e) => setAwsKeySecret(e.target.value)}
                        placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                        className={INPUT_CLASS}
                      />
                    </div>
                  </>
                )}

                {/* Azure client secret */}
                {provider.provider === 'azure' && (
                  <div>
                    <label className={LABEL_CLASS}>Client Secret</label>
                    <input
                      type="password"
                      value={azureClientSecret}
                      onChange={(e) => setAzureClientSecret(e.target.value)}
                      placeholder="Your service principal secret"
                      className={INPUT_CLASS}
                    />
                  </div>
                )}

                {/* GCP service account JSON */}
                {provider.provider === 'gcp' && (
                  <div>
                    <label className={LABEL_CLASS}>Service Account JSON</label>
                    <textarea
                      value={gcpJson}
                      onChange={(e) => setGcpJson(e.target.value)}
                      placeholder={'{\n  "type": "service_account",\n  "project_id": "...",\n  ...\n}'}
                      className={TEXTAREA_CLASS}
                      spellCheck={false}
                    />
                  </div>
                )}

                {/* K8s kubeconfig */}
                {provider.provider === 'k8s' && (
                  <div>
                    <label className={LABEL_CLASS}>Kubeconfig (JSON format)</label>
                    <textarea
                      value={kubeconfig}
                      onChange={(e) => setKubeconfig(e.target.value)}
                      placeholder={'{\n  "apiVersion": "v1",\n  "kind": "Config",\n  ...\n}'}
                      className={TEXTAREA_CLASS}
                      spellCheck={false}
                    />
                    <p className="text-slate-500 text-xs mt-1">
                      Convert YAML to JSON with <code>yq -o json &lt; kubeconfig.yaml</code>.
                    </p>
                  </div>
                )}
              </div>
            )}
          </div>

          {error && (
            <div className="text-red-400 text-sm bg-red-950 border border-red-800 rounded-lg p-3">
              {error}
            </div>
          )}

          <div className="flex items-center gap-3 pt-1">
            <button
              onClick={handleSave}
              disabled={saving}
              className="flex-1 flex items-center justify-center gap-2 py-2.5 bg-orange-500 hover:bg-orange-600 disabled:opacity-60 disabled:cursor-not-allowed text-white font-medium rounded-lg transition-colors text-sm"
            >
              {saving && <Loader2 className="w-4 h-4 animate-spin" />}
              {saving ? 'Saving...' : 'Save Changes'}
            </button>
            <button
              onClick={onCancel}
              disabled={saving}
              className="px-4 py-2.5 text-slate-400 hover:text-slate-200 text-sm transition-colors"
            >
              Cancel
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
