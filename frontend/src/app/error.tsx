'use client'

import { useEffect } from 'react'

/**
 * US-14.24 — boundary de erro por rota (App Router).
 * Qualquer throw em render das 15 rotas cai aqui com recovery local.
 */

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    console.error(error)
  }, [error])

  return (
    <div
      id="route-error-boundary"
      className="min-h-[50vh] flex items-center justify-center p-8"
      role="alert"
    >
      <div className="max-w-md text-center space-y-4">
        <h2 className="text-xl font-semibold text-slate-100">Erro ao carregar esta página</h2>
        <p className="text-slate-400 text-sm">
          A requisição falhou ou retornou dados inválidos. A API está acessível?
        </p>
        <button
          onClick={reset}
          className="px-4 py-2 rounded-md bg-orange-600 hover:bg-orange-500 text-white text-sm font-medium"
        >
          Tentar novamente
        </button>
      </div>
    </div>
  )
}
