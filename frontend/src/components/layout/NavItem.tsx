'use client'

import Link from 'next/link'
import { usePathname } from 'next/navigation'
import type { LucideIcon } from 'lucide-react'

interface NavItemProps {
  icon: LucideIcon
  label: string
  href?: string
  disabled?: boolean
  badge?: string
}

export function NavItem({ icon: Icon, label, href, disabled = false, badge }: NavItemProps) {
  const pathname = usePathname()
  const isActive = !!href && pathname === href

  const baseClasses =
    'flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors w-full'

  const stateClasses = disabled
    ? 'opacity-50 cursor-not-allowed text-slate-400'
    : isActive
      ? 'border-l-2 border-orange-500 bg-slate-800 text-white pl-[10px]'
      : 'text-slate-400 hover:bg-slate-800 hover:text-white'

  const content = (
    <>
      <Icon size={16} className="shrink-0" />
      <span className="flex-1">{label}</span>
      {badge && (
        <span className="bg-slate-700 text-slate-400 text-[10px] px-1.5 py-0.5 rounded">
          {badge}
        </span>
      )}
    </>
  )

  if (disabled) {
    return (
      <span className={`${baseClasses} ${stateClasses}`} aria-disabled="true">
        {content}
      </span>
    )
  }

  return (
    <Link href={href!} className={`${baseClasses} ${stateClasses}`}>
      {content}
    </Link>
  )
}
