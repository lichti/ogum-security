'use client'
import { useRouter } from 'next/navigation'
import { ConnectWizard } from '@/components/providers/ConnectWizard'

export default function NewProviderPage() {
  const router = useRouter()
  return (
    <div id="providers-new-page" className="min-h-screen bg-slate-950">
      <ConnectWizard
        onComplete={() => router.push('/inventory')}
        onCancel={() => router.back()}
      />
    </div>
  )
}
