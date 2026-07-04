'use client'
import { Download } from 'lucide-react'
import { useRef, useState } from 'react'
import { apiClient } from '@/lib/api'
import type { FindingsFilter } from '@/lib/types'

interface ExportButtonProps {
  filters: FindingsFilter
}

function buildParams(filters: FindingsFilter, format: 'csv' | 'json'): URLSearchParams {
  const p = new URLSearchParams({ format })
  if (filters.provider) p.set('provider', filters.provider)
  if (filters.severity) p.set('severity', filters.severity)
  if (filters.status) p.set('status', filters.status)
  if (filters.framework) p.set('framework', filters.framework)
  if (filters.region) p.set('region', filters.region)
  if (filters.account_id) p.set('account_id', filters.account_id)
  if (filters.resource_type) p.set('resource_type', filters.resource_type)
  if (filters.source) p.set('source', filters.source)
  if (filters.q) p.set('q', filters.q)
  return p
}

export function ExportButton({ filters }: ExportButtonProps) {
  const [open, setOpen] = useState(false)
  const [loading, setLoading] = useState(false)
  const menuRef = useRef<HTMLDivElement>(null)

  const doExport = async (format: 'csv' | 'json') => {
    setOpen(false)
    setLoading(true)
    try {
      const params = buildParams(filters, format)
      const resp = await apiClient.get(`/api/v1/findings/export?${params.toString()}`, {
        responseType: 'blob',
      })
      const blob = new Blob([resp.data], {
        type: format === 'csv' ? 'text/csv' : 'application/json',
      })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      const cd = resp.headers['content-disposition'] ?? ''
      const match = cd.match(/filename="([^"]+)"/)
      a.download = match?.[1] ?? `findings.${format}`
      a.click()
      URL.revokeObjectURL(url)
    } catch {
      /* ignore — user can retry */
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="relative" ref={menuRef}>
      <button
        onClick={() => setOpen((o) => !o)}
        disabled={loading}
        className="flex items-center gap-1.5 px-3 py-1.5 text-sm border border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-500 rounded transition-colors disabled:opacity-50"
        aria-label="Export findings"
        aria-haspopup="true"
        aria-expanded={open}
      >
        <Download className="w-3.5 h-3.5" />
        {loading ? 'Exporting…' : 'Export'}
      </button>

      {open && (
        <>
          <div
            className="fixed inset-0 z-10"
            onClick={() => setOpen(false)}
            aria-hidden="true"
          />
          <div className="absolute right-0 mt-1 w-40 bg-slate-900 border border-slate-700 rounded shadow-lg z-20">
            <button
              onClick={() => doExport('csv')}
              className="block w-full text-left px-4 py-2 text-sm text-slate-300 hover:bg-slate-800 hover:text-slate-100"
            >
              CSV
            </button>
            <button
              onClick={() => doExport('json')}
              className="block w-full text-left px-4 py-2 text-sm text-slate-300 hover:bg-slate-800 hover:text-slate-100"
            >
              JSON (OCSF)
            </button>
          </div>
        </>
      )}
    </div>
  )
}
