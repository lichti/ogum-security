'use client'
import { useState } from 'react'
import { CheckCircle, ChevronRight, Loader2, ChevronDown, ChevronUp } from 'lucide-react'
import { providersApi } from '@/lib/api'
import type { ProviderType } from '@/lib/types'

type Step = 'select' | 'configure' | 'connecting' | 'done'

const PROVIDERS = [
  { id: 'aws' as ProviderType, name: 'Amazon Web Services', description: 'EC2, S3, IAM, RDS, Lambda and more' },
  { id: 'azure' as ProviderType, name: 'Microsoft Azure', description: 'VMs, VNets, AKS, Storage Accounts' },
  { id: 'gcp' as ProviderType, name: 'Google Cloud Platform', description: 'Compute, GCS, GKE, Cloud SQL' },
  { id: 'k8s' as ProviderType, name: 'Kubernetes', description: 'Pods, Deployments, Services, RBAC' },
] as const

const INPUT_CLASS = 'w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-orange-500 font-mono'
const LABEL_CLASS = 'block text-sm text-slate-400 mb-1'

interface ConnectWizardProps {
  onComplete: () => void
  onCancel: () => void
}

export function ConnectWizard({ onComplete, onCancel }: ConnectWizardProps) {
  const [step, setStep] = useState<Step>('select')
  const [selectedProvider, setSelectedProvider] = useState<ProviderType>('aws')
  const [form, setForm] = useState({
    display_name: '',
    account_id: '',
    role_arn: '',
    subscription_id: '',
    project_id: '',
    cluster_name: '',
    regions: 'us-east-1',
  })
  const [showSetupGuide, setShowSetupGuide] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [jobId, setJobId] = useState<string | null>(null)

  const set = (field: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) =>
    setForm((f) => ({ ...f, [field]: e.target.value }))

  const handleConnect = async () => {
    setStep('connecting')
    setError(null)
    try {
      const regions = form.regions.split(',').map((r) => r.trim()).filter(Boolean)
      const resp = await providersApi.register({
        provider: selectedProvider,
        display_name: form.display_name || `${selectedProvider.toUpperCase()} Account`,
        account_id: form.account_id || undefined,
        role_arn: form.role_arn || undefined,
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
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-slate-900 border border-slate-700 rounded-xl w-full max-w-lg shadow-2xl max-h-[90vh] overflow-y-auto">
        <div className="flex items-center justify-between p-6 pb-4">
          <h2 className="text-lg font-semibold text-slate-100">Connect Cloud Account</h2>
          <button onClick={onCancel} className="text-slate-500 hover:text-slate-300 text-xl leading-none">×</button>
        </div>

        <div className="px-6 pb-6">
          {step === 'select' && (
            <div className="space-y-3">
              <p className="text-slate-400 text-sm mb-4">Select the cloud provider to connect:</p>
              {PROVIDERS.map((p) => (
                <button
                  key={p.id}
                  onClick={() => { setSelectedProvider(p.id); setStep('configure') }}
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
                <label className={LABEL_CLASS}>Display name</label>
                <input
                  type="text"
                  placeholder={`${selectedProvider.toUpperCase()} Production`}
                  value={form.display_name}
                  onChange={set('display_name')}
                  className={INPUT_CLASS}
                />
              </div>

              {selectedProvider === 'aws' && (
                <>
                  <div>
                    <label className={LABEL_CLASS}>AWS Account ID</label>
                    <input
                      type="text"
                      placeholder="123456789012"
                      value={form.account_id}
                      onChange={set('account_id')}
                      className={INPUT_CLASS}
                    />
                  </div>

                  <div>
                    <label className={LABEL_CLASS}>
                      IAM Role ARN{' '}
                      <span className="text-slate-500 font-normal">(recommended)</span>
                    </label>
                    <input
                      type="text"
                      placeholder="arn:aws:iam::123456789012:role/OgumReadRole"
                      value={form.role_arn}
                      onChange={set('role_arn')}
                      className={INPUT_CLASS}
                    />
                    <p className="text-slate-500 text-xs mt-1">
                      Cross-account role Ogum will assume to scan your account.
                      Leave empty to use the worker&apos;s ambient credentials (dev only).
                    </p>
                  </div>

                  {/* Setup guide */}
                  <div className="border border-slate-700 rounded-lg overflow-hidden">
                    <button
                      type="button"
                      onClick={() => setShowSetupGuide((v) => !v)}
                      className="w-full flex items-center justify-between px-4 py-3 text-sm text-slate-300 hover:bg-slate-800 transition-colors"
                    >
                      <span>How to create the IAM Role</span>
                      {showSetupGuide
                        ? <ChevronUp className="w-4 h-4 text-slate-500" />
                        : <ChevronDown className="w-4 h-4 text-slate-500" />}
                    </button>
                    {showSetupGuide && (
                      <div className="px-4 pb-4 text-xs text-slate-400 space-y-3 border-t border-slate-700 pt-3">
                        <p>Run this in your AWS account to create the cross-account role:</p>
                        <pre className="bg-slate-950 rounded p-3 overflow-x-auto text-slate-300 leading-relaxed">{`# 1. Create the IAM policy
aws iam create-policy \\
  --policy-name OgumInventoryPolicy \\
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*", "iam:List*", "iam:Get*",
        "s3:ListAllMyBuckets", "s3:GetBucketLocation",
        "s3:GetBucketPolicy", "rds:Describe*",
        "lambda:List*", "lambda:GetFunction",
        "eks:List*", "eks:Describe*",
        "kms:ListKeys", "kms:DescribeKey",
        "secretsmanager:ListSecrets",
        "secretsmanager:DescribeSecret",
        "cloudtrail:DescribeTrails",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }]
  }'

# 2. Create the role (replace <OGUM_ACCOUNT_ID>)
aws iam create-role \\
  --role-name OgumReadRole \\
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<OGUM_ACCOUNT_ID>:root"
      },
      "Action": "sts:AssumeRole"
    }]
  }'

# 3. Attach the policy
aws iam attach-role-policy \\
  --role-name OgumReadRole \\
  --policy-arn arn:aws:iam::<YOUR_ACCOUNT_ID>:policy/OgumInventoryPolicy`}</pre>
                        <p>Then paste the role ARN above.</p>
                      </div>
                    )}
                  </div>

                  <div>
                    <label className={LABEL_CLASS}>Regions (comma-separated)</label>
                    <input
                      type="text"
                      placeholder="us-east-1, us-west-2"
                      value={form.regions}
                      onChange={set('regions')}
                      className={INPUT_CLASS}
                    />
                  </div>
                </>
              )}

              {selectedProvider === 'azure' && (
                <div>
                  <label className={LABEL_CLASS}>Subscription ID</label>
                  <input
                    type="text"
                    placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                    value={form.subscription_id}
                    onChange={set('subscription_id')}
                    className={INPUT_CLASS}
                  />
                  <p className="text-slate-500 text-xs mt-1">
                    Ensure the worker has <code>AZURE_TENANT_ID</code>, <code>AZURE_CLIENT_ID</code>,
                    and <code>AZURE_CLIENT_SECRET</code> set in its environment.
                  </p>
                </div>
              )}

              {selectedProvider === 'gcp' && (
                <div>
                  <label className={LABEL_CLASS}>Project ID</label>
                  <input
                    type="text"
                    placeholder="my-project-id"
                    value={form.project_id}
                    onChange={set('project_id')}
                    className={INPUT_CLASS}
                  />
                  <p className="text-slate-500 text-xs mt-1">
                    Ensure <code>GOOGLE_APPLICATION_CREDENTIALS</code> is set in the worker environment.
                  </p>
                </div>
              )}

              {selectedProvider === 'k8s' && (
                <div>
                  <label className={LABEL_CLASS}>Cluster Name</label>
                  <input
                    type="text"
                    placeholder="prod-cluster"
                    value={form.cluster_name}
                    onChange={set('cluster_name')}
                    className={INPUT_CLASS}
                  />
                  <p className="text-slate-500 text-xs mt-1">
                    Ensure <code>KUBECONFIG</code> is set in the worker environment.
                  </p>
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
              <p className="text-slate-500 text-xs mt-1">
                Status will change from <em>Pending</em> to <em>Active</em> when the first scan completes.
              </p>
              {jobId && <p className="text-slate-600 text-xs font-mono mt-2">Job: {jobId}</p>}
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
    </div>
  )
}
