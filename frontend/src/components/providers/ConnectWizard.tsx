'use client'
import { useState } from 'react'
import { CheckCircle, ChevronRight, Loader2, ChevronDown, ChevronUp } from 'lucide-react'
import { providersApi } from '@/lib/api'
import type { ProviderType, ProviderRegisterRequest } from '@/lib/types'

type Step = 'select' | 'configure' | 'connecting' | 'done'

// Credential method for each provider
type AWSMethod = 'role' | 'static'
type AzureMethod = 'service_principal' | 'managed_identity'
type GCPMethod = 'service_account' | 'adc'
type K8sMethod = 'kubeconfig' | 'incluster'

const PROVIDERS = [
  { id: 'aws' as ProviderType, name: 'Amazon Web Services', description: 'EC2, S3, IAM, RDS, Lambda and more' },
  { id: 'azure' as ProviderType, name: 'Microsoft Azure', description: 'VMs, VNets, AKS, Storage Accounts' },
  { id: 'gcp' as ProviderType, name: 'Google Cloud Platform', description: 'Compute, GCS, GKE, Cloud SQL' },
  { id: 'k8s' as ProviderType, name: 'Kubernetes', description: 'Pods, Deployments, Services, RBAC' },
] as const

const INPUT_CLASS = 'w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 focus:outline-none focus:border-orange-500 font-mono'
const TEXTAREA_CLASS = 'w-full px-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-xs text-slate-200 focus:outline-none focus:border-orange-500 font-mono h-32 resize-none'
const LABEL_CLASS = 'block text-sm text-slate-400 mb-1'

function MethodSelector<T extends string>({
  options,
  value,
  onChange,
}: {
  options: { value: T; label: string }[]
  value: T
  onChange: (v: T) => void
}) {
  return (
    <div className="flex rounded-lg border border-slate-700 overflow-hidden text-sm">
      {options.map((opt, i) => (
        <button
          key={opt.value}
          type="button"
          onClick={() => onChange(opt.value)}
          className={[
            'flex-1 py-2 px-3 transition-colors',
            value === opt.value
              ? 'bg-orange-500/20 text-orange-400'
              : 'text-slate-400 hover:bg-slate-800',
            i < options.length - 1 ? 'border-r border-slate-700' : '',
          ].join(' ')}
        >
          {opt.label}
        </button>
      ))}
    </div>
  )
}

interface ConnectWizardProps {
  onComplete: () => void
  onCancel: () => void
}

export function ConnectWizard({ onComplete, onCancel }: ConnectWizardProps) {
  const [step, setStep] = useState<Step>('select')
  const [selectedProvider, setSelectedProvider] = useState<ProviderType>('aws')

  // AWS
  const [awsMethod, setAwsMethod] = useState<AWSMethod>('role')
  // Azure
  const [azureMethod, setAzureMethod] = useState<AzureMethod>('service_principal')
  // GCP
  const [gcpMethod, setGcpMethod] = useState<GCPMethod>('service_account')
  // K8s
  const [k8sMethod, setK8sMethod] = useState<K8sMethod>('incluster')

  const [form, setForm] = useState({
    display_name: '',
    // AWS
    account_id: '',
    role_arn: '',
    aws_access_key_id: '',
    aws_secret_access_key: '',
    regions: 'us-east-1',
    // Azure
    subscription_id: '',
    azure_tenant_id: '',
    azure_client_id: '',
    azure_client_secret: '',
    // GCP
    project_id: '',
    gcp_service_account_json: '',
    // K8s
    cluster_name: '',
    kubeconfig: '',
  })

  const [showSetupGuide, setShowSetupGuide] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [jobId, setJobId] = useState<string | null>(null)

  const set = (field: keyof typeof form) => (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ) => setForm((f) => ({ ...f, [field]: e.target.value }))

  const handleConnect = async () => {
    setStep('connecting')
    setError(null)
    try {
      const regions = form.regions.split(',').map((r) => r.trim()).filter(Boolean)

      const payload: ProviderRegisterRequest = {
        provider: selectedProvider,
        display_name: form.display_name || `${selectedProvider.toUpperCase()} Account`,
        regions,
        validate_connection: false,
      }

      if (selectedProvider === 'aws') {
        payload.account_id = form.account_id || undefined
        if (awsMethod === 'role') {
          payload.role_arn = form.role_arn || undefined
        } else {
          payload.aws_access_key_id = form.aws_access_key_id || undefined
          payload.aws_secret_access_key = form.aws_secret_access_key || undefined
        }
      }

      if (selectedProvider === 'azure') {
        payload.subscription_id = form.subscription_id || undefined
        if (azureMethod === 'service_principal') {
          payload.azure_tenant_id = form.azure_tenant_id || undefined
          payload.azure_client_id = form.azure_client_id || undefined
          payload.azure_client_secret = form.azure_client_secret || undefined
        }
      }

      if (selectedProvider === 'gcp') {
        payload.project_id = form.project_id || undefined
        if (gcpMethod === 'service_account' && form.gcp_service_account_json.trim()) {
          payload.gcp_service_account_json = JSON.parse(form.gcp_service_account_json)
        }
      }

      if (selectedProvider === 'k8s') {
        payload.cluster_name = form.cluster_name || undefined
        if (k8sMethod === 'kubeconfig' && form.kubeconfig.trim()) {
          payload.kubeconfig = JSON.parse(form.kubeconfig)
        }
      }

      const resp = await providersApi.register(payload)
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

              {/* ── AWS ── */}
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
                    <label className={LABEL_CLASS}>Credential method</label>
                    <MethodSelector<AWSMethod>
                      options={[
                        { value: 'role', label: 'IAM Role (recommended)' },
                        { value: 'static', label: 'API Keys (dev only)' },
                      ]}
                      value={awsMethod}
                      onChange={setAwsMethod}
                    />
                  </div>

                  {awsMethod === 'role' && (
                    <>
                      <div>
                        <label className={LABEL_CLASS}>IAM Role ARN</label>
                        <input
                          type="text"
                          placeholder="arn:aws:iam::123456789012:role/OgumReadRole"
                          value={form.role_arn}
                          onChange={set('role_arn')}
                          className={INPUT_CLASS}
                        />
                        <p className="text-slate-500 text-xs mt-1">
                          Cross-account role Ogum will assume to scan your account.
                          Leave empty to use the worker&apos;s ambient credentials.
                        </p>
                      </div>

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
                    </>
                  )}

                  {awsMethod === 'static' && (
                    <div className="space-y-3">
                      <div className="text-xs text-amber-400 bg-amber-950/40 border border-amber-800/50 rounded-lg px-3 py-2">
                        Static keys are for local development only. These credentials are passed
                        directly to the worker and are <strong>not stored</strong> in the database.
                        Use IAM Role for any shared or production environment.
                      </div>
                      <div>
                        <label className={LABEL_CLASS}>Access Key ID</label>
                        <input
                          type="text"
                          placeholder="AKIAIOSFODNN7EXAMPLE"
                          value={form.aws_access_key_id}
                          onChange={set('aws_access_key_id')}
                          className={INPUT_CLASS}
                        />
                      </div>
                      <div>
                        <label className={LABEL_CLASS}>Secret Access Key</label>
                        <input
                          type="password"
                          placeholder="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
                          value={form.aws_secret_access_key}
                          onChange={set('aws_secret_access_key')}
                          className={INPUT_CLASS}
                        />
                      </div>
                    </div>
                  )}

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

              {/* ── Azure ── */}
              {selectedProvider === 'azure' && (
                <>
                  <div>
                    <label className={LABEL_CLASS}>Subscription ID</label>
                    <input
                      type="text"
                      placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                      value={form.subscription_id}
                      onChange={set('subscription_id')}
                      className={INPUT_CLASS}
                    />
                  </div>

                  <div>
                    <label className={LABEL_CLASS}>Credential method</label>
                    <MethodSelector<AzureMethod>
                      options={[
                        { value: 'service_principal', label: 'Service Principal' },
                        { value: 'managed_identity', label: 'Managed Identity / ADC' },
                      ]}
                      value={azureMethod}
                      onChange={setAzureMethod}
                    />
                  </div>

                  {azureMethod === 'service_principal' && (
                    <div className="space-y-3">
                      <div>
                        <label className={LABEL_CLASS}>Azure Tenant ID</label>
                        <input
                          type="text"
                          placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                          value={form.azure_tenant_id}
                          onChange={set('azure_tenant_id')}
                          className={INPUT_CLASS}
                        />
                      </div>
                      <div>
                        <label className={LABEL_CLASS}>Client ID (App Registration)</label>
                        <input
                          type="text"
                          placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
                          value={form.azure_client_id}
                          onChange={set('azure_client_id')}
                          className={INPUT_CLASS}
                        />
                      </div>
                      <div>
                        <label className={LABEL_CLASS}>Client Secret</label>
                        <input
                          type="password"
                          placeholder="Your service principal secret"
                          value={form.azure_client_secret}
                          onChange={set('azure_client_secret')}
                          className={INPUT_CLASS}
                        />
                        <p className="text-slate-500 text-xs mt-1">
                          Secret is passed directly to the worker — <strong>not stored</strong> in the database.
                          Assign the <code>Reader</code> role to the service principal on the subscription.
                        </p>
                      </div>
                    </div>
                  )}

                  {azureMethod === 'managed_identity' && (
                    <div className="text-xs text-slate-400 bg-slate-800/60 border border-slate-700 rounded-lg px-3 py-3">
                      The worker will authenticate using{' '}
                      <code className="text-slate-300">DefaultAzureCredential</code> — this resolves
                      to a Managed Identity when running in Azure, or environment variables
                      (<code>AZURE_TENANT_ID</code>, <code>AZURE_CLIENT_ID</code>,{' '}
                      <code>AZURE_CLIENT_SECRET</code>) in other environments.
                    </div>
                  )}
                </>
              )}

              {/* ── GCP ── */}
              {selectedProvider === 'gcp' && (
                <>
                  <div>
                    <label className={LABEL_CLASS}>Project ID</label>
                    <input
                      type="text"
                      placeholder="my-project-id"
                      value={form.project_id}
                      onChange={set('project_id')}
                      className={INPUT_CLASS}
                    />
                  </div>

                  <div>
                    <label className={LABEL_CLASS}>Credential method</label>
                    <MethodSelector<GCPMethod>
                      options={[
                        { value: 'service_account', label: 'Service Account JSON' },
                        { value: 'adc', label: 'Application Default Credentials' },
                      ]}
                      value={gcpMethod}
                      onChange={setGcpMethod}
                    />
                  </div>

                  {gcpMethod === 'service_account' && (
                    <div>
                      <label className={LABEL_CLASS}>Service Account JSON</label>
                      <textarea
                        placeholder={'{\n  "type": "service_account",\n  "project_id": "...",\n  ...\n}'}
                        value={form.gcp_service_account_json}
                        onChange={set('gcp_service_account_json')}
                        className={TEXTAREA_CLASS}
                        spellCheck={false}
                      />
                      <p className="text-slate-500 text-xs mt-1">
                        Paste the JSON key file content. It is passed directly to the worker —{' '}
                        <strong>not stored</strong> in the database. Assign{' '}
                        <code>roles/viewer</code> to the service account.
                      </p>
                    </div>
                  )}

                  {gcpMethod === 'adc' && (
                    <div className="text-xs text-slate-400 bg-slate-800/60 border border-slate-700 rounded-lg px-3 py-3">
                      The worker uses{' '}
                      <code className="text-slate-300">Application Default Credentials</code>.
                      Authenticate with <code>gcloud auth application-default login</code> on the
                      worker host, or set <code>GOOGLE_APPLICATION_CREDENTIALS</code> to the path
                      of a service account key file.
                    </div>
                  )}
                </>
              )}

              {/* ── Kubernetes ── */}
              {selectedProvider === 'k8s' && (
                <>
                  <div>
                    <label className={LABEL_CLASS}>Cluster Name</label>
                    <input
                      type="text"
                      placeholder="prod-cluster"
                      value={form.cluster_name}
                      onChange={set('cluster_name')}
                      className={INPUT_CLASS}
                    />
                  </div>

                  <div>
                    <label className={LABEL_CLASS}>Credential method</label>
                    <MethodSelector<K8sMethod>
                      options={[
                        { value: 'incluster', label: 'In-Cluster (recommended)' },
                        { value: 'kubeconfig', label: 'Kubeconfig' },
                      ]}
                      value={k8sMethod}
                      onChange={setK8sMethod}
                    />
                  </div>

                  {k8sMethod === 'incluster' && (
                    <div className="text-xs text-slate-400 bg-slate-800/60 border border-slate-700 rounded-lg px-3 py-3">
                      The worker uses the ServiceAccount token mounted automatically by Kubernetes
                      when deployed inside the cluster (<code>in-cluster config</code>). Make sure
                      the Ogum worker ServiceAccount has{' '}
                      <code>get</code>, <code>list</code>, and <code>watch</code> permissions
                      across all namespaces.
                    </div>
                  )}

                  {k8sMethod === 'kubeconfig' && (
                    <div>
                      <label className={LABEL_CLASS}>Kubeconfig (JSON format)</label>
                      <textarea
                        placeholder={'{\n  "apiVersion": "v1",\n  "kind": "Config",\n  ...\n}'}
                        value={form.kubeconfig}
                        onChange={set('kubeconfig')}
                        className={TEXTAREA_CLASS}
                        spellCheck={false}
                      />
                      <p className="text-slate-500 text-xs mt-1">
                        Paste your kubeconfig as JSON. It is passed directly to the worker —{' '}
                        <strong>not stored</strong> in the database.
                        Convert YAML to JSON with <code>yq -o json &lt; kubeconfig.yaml</code>.
                      </p>
                    </div>
                  )}
                </>
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
