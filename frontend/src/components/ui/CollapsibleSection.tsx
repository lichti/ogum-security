'use client'
import { useState, type ReactNode } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'

interface CollapsibleSectionProps {
  title: ReactNode
  children: ReactNode
  headerExtra?: ReactNode
  defaultOpen?: boolean
  className?: string
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '')
}

// headerExtra (filters, period selectors, etc.) stays visible and interactive
// regardless of open state — only the body collapses.
export function CollapsibleSection({
  title,
  children,
  headerExtra,
  defaultOpen = true,
  className,
}: CollapsibleSectionProps) {
  const [open, setOpen] = useState(defaultOpen)
  const testId = typeof title === 'string' ? `collapsible-section-${slugify(title)}` : undefined

  return (
    <div className={className} data-testid={testId}>
      <div className="flex items-center justify-between gap-3 mb-3">
        <button
          type="button"
          onClick={() => setOpen((prev) => !prev)}
          aria-expanded={open}
          className="flex items-center gap-1.5 text-xs font-semibold text-slate-500 uppercase tracking-wider hover:text-slate-300 transition-colors flex-shrink-0"
        >
          {open ? (
            <ChevronDown size={14} className="text-slate-600 flex-shrink-0" />
          ) : (
            <ChevronRight size={14} className="text-slate-600 flex-shrink-0" />
          )}
          {title}
        </button>
        {headerExtra}
      </div>
      {open && children}
    </div>
  )
}
