'use client'

import { useEffect } from 'react'

/**
 * US-14.24 — boundary global de erro do App Router.
 * Renderiza quando qualquer Server/Client Component lança em runtime.
 * `global-error.tsx` cobre falhas no layout raiz.
 */

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    // Hook de telemetria futuro (Sentry etc.) — por ora, console do browser
    console.error(error)
  }, [error])

  return (
    <html lang="en">
      <body className="min-h-screen bg-slate-950 text-slate-100 flex items-center justify-center p-8">
        <div className="max-w-md text-center space-y-4">
          <h2 className="text-xl font-semibold">Algo deu errado</h2>
          <p className="text-slate-400 text-sm">
            Ocorreu um erro inesperado. Tente novamente — se persistir, verifique a
            saúde da API em <code className="text-slate-300">/health</code>.
          </p>
          <button
            onClick={reset}
            className="px-4 py-2 rounded-md bg-orange-600 hover:bg-orange-500 text-white text-sm font-medium"
          >
            Tentar novamente
          </button>
        </div>
      </body>
    </html>
  )
}
