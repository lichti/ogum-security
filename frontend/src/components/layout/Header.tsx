'use client'

import { usePathname } from 'next/navigation'

const ROUTE_LABELS: Record<string, string> = {
  '/': 'Dashboard',
  '/inventory': 'Inventory',
  '/findings': 'Findings',
  '/compliance': 'Compliance',
  '/providers': 'Cloud Providers',
  '/providers/new': 'Cloud Providers / Connect',
}

export function Header() {
  const pathname = usePathname()
  const label = ROUTE_LABELS[pathname] ?? pathname.replace(/^\//, '').replace(/-/g, ' ')

  return (
    <header className="h-14 bg-slate-900 border-b border-slate-800 flex items-center justify-between px-6 shrink-0">
      <h1 className="text-sm font-medium text-slate-200 capitalize">{label}</h1>
      <div className="w-8 h-8 bg-slate-700 rounded-full" aria-label="User avatar" />
    </header>
  )
}
