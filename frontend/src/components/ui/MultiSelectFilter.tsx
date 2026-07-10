'use client'
import { useEffect, useRef, useState } from 'react'
import { ChevronDown } from 'lucide-react'
import { clsx } from 'clsx'

export interface MultiSelectOption {
  value: string
  label: string
  count?: number
}

interface MultiSelectFilterProps {
  label: string
  options: MultiSelectOption[]
  selected: string[]
  onChange: (values: string[]) => void
}

export function MultiSelectFilter({ label, options, selected, onChange }: MultiSelectFilterProps) {
  const [open, setOpen] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setOpen(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const buttonLabel =
    selected.length === 0
      ? `All ${label}`
      : selected.length === 1
        ? (options.find((o) => o.value === selected[0])?.label ?? selected[0])
        : `${selected.length} ${label}`

  function toggle(value: string) {
    onChange(selected.includes(value) ? selected.filter((v) => v !== value) : [...selected, value])
  }

  return (
    <div className="relative" ref={containerRef}>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        className={clsx(
          'flex items-center gap-2 px-3 py-2 border rounded-lg text-sm transition-colors whitespace-nowrap',
          selected.length > 0
            ? 'bg-orange-950/40 border-orange-500/50 text-orange-300'
            : 'bg-slate-800 border-slate-700 text-slate-300 hover:border-slate-600',
        )}
        aria-haspopup="listbox"
        aria-expanded={open}
      >
        <span>{buttonLabel}</span>
        <ChevronDown className="w-3.5 h-3.5" />
      </button>

      {open && (
        <div
          role="listbox"
          aria-label={label}
          className="absolute z-20 mt-1 w-64 max-h-72 overflow-auto bg-slate-800 border border-slate-700 rounded-lg shadow-xl py-1"
        >
          <label className="flex items-center gap-2 px-3 py-1.5 hover:bg-slate-700/50 cursor-pointer text-sm border-b border-slate-700 mb-1">
            <input
              type="checkbox"
              checked={selected.length === 0}
              onChange={() => onChange([])}
              className="w-4 h-4 rounded accent-orange-500"
            />
            <span className="text-slate-200 font-medium">All {label}</span>
          </label>

          {options.length === 0 && <div className="px-3 py-2 text-slate-500 text-sm">No options</div>}

          {options.map((opt) => (
            <label
              key={opt.value}
              className="flex items-center justify-between gap-2 px-3 py-1.5 hover:bg-slate-700/50 cursor-pointer text-sm"
            >
              <span className="flex items-center gap-2 min-w-0">
                <input
                  type="checkbox"
                  checked={selected.includes(opt.value)}
                  onChange={() => toggle(opt.value)}
                  className="w-4 h-4 rounded accent-orange-500 flex-shrink-0"
                />
                <span className="text-slate-300 truncate">{opt.label}</span>
              </span>
              {opt.count !== undefined && (
                <span className="text-slate-500 text-xs flex-shrink-0">{opt.count.toLocaleString()}</span>
              )}
            </label>
          ))}
        </div>
      )}
    </div>
  )
}
