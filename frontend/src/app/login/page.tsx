'use client'

import { useState, Suspense } from 'react'
import { useSearchParams } from 'next/navigation'
import { ShieldCheck, Loader2, LogIn, KeyRound } from 'lucide-react'
import { authApi, getErrorMessage, setApiToken } from '@/lib/api'

/**
 * US-06.01 — página de login.
 *
 * Fluxo principal: OIDC do tenant (botão "Entrar com {IdP}" — o nome vem do
 * GET /auth/oidc/status). O callback do backend grava os cookies HttpOnly e
 * redireciona para /dashboard. Fluxo secundário interim (US-06.09): colar um
 * API token de tenant enquanto o provisioning completo (US-06.04) não existe.
 *
 * `?next=/rota` é preservado pelo interceptor de 401 do apiClient e volta
 * após o login.
 */

function LoginInner() {
  const searchParams = useSearchParams()
  const nextPath = searchParams.get('next') ?? '/dashboard'
  const [tenantId, setTenantId] = useState('')
  const [idpName, setIdpName] = useState<string | null>(null)
  const [statusError, setStatusError] = useState<string | null>(null)
  const [checking, setChecking] = useState(false)
  const [interimToken, setInterimToken] = useState('')
  const [tokenSaved, setTokenSaved] = useState(false)

  async function lookupIdp() {
    if (!tenantId.trim()) return
    setChecking(true)
    setStatusError(null)
    setIdpName(null)
    try {
      const { data } = await authApi.status(tenantId.trim())
      setIdpName(data.data.idp_name)
    } catch (error) {
      setStatusError(getErrorMessage(error, 'Nenhum IdP OIDC configurado para este tenant'))
    } finally {
      setChecking(false)
    }
  }

  function startOidcLogin() {
    const base = process.env.NEXT_PUBLIC_API_URL ?? 'http://localhost:8000'
    window.location.assign(
      `${base}/api/v1/auth/oidc/login?tenant_id=${encodeURIComponent(tenantId.trim())}&next=${encodeURIComponent(nextPath)}`,
    )
  }

  function saveInterimToken() {
    setApiToken(interimToken.trim() || null)
    setTokenSaved(true)
    window.location.href = nextPath
  }

  return (
    <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4">
      <div className="w-full max-w-md space-y-6">
        <div className="text-center space-y-2">
          <ShieldCheck className="w-10 h-10 text-emerald-400 mx-auto" aria-hidden />
          <h1 className="text-2xl font-semibold text-slate-100">Ogum Security</h1>
          <p className="text-sm text-slate-400">Entre com seu tenant corporativo</p>
        </div>

        <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-6 space-y-4">
          <label htmlFor="tenant-id" className="block text-sm font-medium text-slate-300">
            Tenant
          </label>
          <div className="flex gap-2">
            <input
              id="tenant-id"
              value={tenantId}
              onChange={(event) => setTenantId(event.target.value)}
              placeholder="ex.: minha-empresa"
              className="flex-1 rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-emerald-500 focus:outline-none"
            />
            <button
              type="button"
              onClick={lookupIdp}
              disabled={!tenantId.trim() || checking}
              className="rounded-md border border-slate-700 px-3 py-2 text-sm text-slate-300 hover:border-slate-500 disabled:opacity-40"
            >
              {checking ? <Loader2 className="w-4 h-4 animate-spin" aria-hidden /> : 'Verificar'}
            </button>
          </div>

          {statusError && (
            <p role="alert" className="text-sm text-red-400">
              {statusError}
            </p>
          )}

          {idpName && (
            <button
              type="button"
              onClick={startOidcLogin}
              data-testid="oidc-login-button"
              className="w-full flex items-center justify-center gap-2 rounded-md bg-emerald-600 px-4 py-2.5 text-sm font-medium text-white hover:bg-emerald-500"
            >
              <LogIn className="w-4 h-4" aria-hidden />
              Entrar com {idpName}
            </button>
          )}
        </div>

        <details className="rounded-lg border border-slate-800 bg-slate-900/60 p-4">
          <summary className="cursor-pointer text-sm text-slate-400 flex items-center gap-2">
            <KeyRound className="w-4 h-4" aria-hidden />
            Tenho um token de API interim
          </summary>
          <div className="mt-3 space-y-3">
            <input
              type="password"
              value={interimToken}
              onChange={(event) => setInterimToken(event.target.value)}
              placeholder="cole o token (US-06.09)"
              className="w-full rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 placeholder:text-slate-600 focus:border-emerald-500 focus:outline-none"
            />
            <button
              type="button"
              onClick={saveInterimToken}
              disabled={!interimToken.trim()}
              className="w-full rounded-md border border-slate-700 px-4 py-2 text-sm text-slate-200 hover:border-slate-500 disabled:opacity-40"
            >
              {tokenSaved ? 'Salvo — redirecionando…' : 'Usar token'}
            </button>
          </div>
        </details>
      </div>
    </div>
  )
}

export default function LoginPage() {
  return (
    <Suspense>
      <LoginInner />
    </Suspense>
  )
}
