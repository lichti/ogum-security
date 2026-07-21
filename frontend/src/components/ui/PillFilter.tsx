'use client'
import { useEffect, useRef, useState } from 'react'
import { ChevronDown } from 'lucide-react'
import { clsx } from 'clsx'

export type PillFilterOperator = 'is' | 'is_not' | 'contains'

export interface PillFilterOption {
  value: string
  label: string
  count?: number
}

interface PillFilterProps {
  label: string
  options: PillFilterOption[]
  selected: string[]
  operator?: PillFilterOperator
  operators?: PillFilterOperator[]
  onApply: (values: string[], operator: PillFilterOperator) => void
}

const OPERATOR_LABELS: Record<PillFilterOperator, string> = {
  is: 'is',
  is_not: 'is not',
  contains: 'contains',
}

function slugify(value: string): string {
  return value
    .toLowerCase()
    .trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '')
}

export function PillFilter({
  label,
  options,
  selected,
  operator = 'is',
  operators = ['is'],
  onApply,
}: PillFilterProps) {
  const [open, setOpen] = useState(false)
  const [search, setSearch] = useState('')
  const [draftSelected, setDraftSelected] = useState<string[]>(selected)
  const [draftOperator, setDraftOperator] = useState<PillFilterOperator>(operator)
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

  function openPopover() {
    setDraftSelected(selected)
    setDraftOperator(operator)
    setSearch('')
    setOpen(true)
  }

  function toggle(value: string) {
    setDraftSelected((prev) => (prev.includes(value) ? prev.filter((v) => v !== value) : [...prev, value]))
  }

  function handleApply() {
    onApply(draftSelected, draftOperator)
    setOpen(false)
  }

  function handleClear() {
    setDraftSelected([])
    onApply([], draftOperator)
    setOpen(false)
  }

  const filteredOptions = options.filter((opt) => opt.label.toLowerCase().includes(search.toLowerCase()))
  const allSelected = draftSelected.length === options.length && options.length > 0

  return (
    <div className="relative inline-block" ref={containerRef} data-testid={`pill-filter-${slugify(label)}`}>
      <button
        type="button"
        onClick={() => (open ? setOpen(false) : openPopover())}
        className={clsx(
          'flex items-center gap-1.5 px-3 py-1.5 border rounded-full text-sm transition-colors whitespace-nowrap',
          selected.length > 0
            ? 'border-orange-500 bg-orange-950/30 text-orange-400'
            : 'bg-slate-800 border-slate-700 text-slate-300 hover:border-slate-600',
        )}
        aria-haspopup="dialog"
        aria-expanded={open}
      >
        <span>{label}</span>
        <ChevronDown className="w-3.5 h-3.5" />
      </button>

      {open && (
        <div
          role="dialog"
          aria-label={`${label} filter`}
          className="absolute z-50 mt-1 w-80 bg-slate-900 border border-slate-700 shadow-lg rounded-md"
        >
          {operators.length > 1 && (
            <div className="px-3 pt-2">
              <select
                aria-label="Operator"
                value={draftOperator}
                onChange={(e) => setDraftOperator(e.target.value as PillFilterOperator)}
                className="bg-slate-800 border border-slate-700 rounded px-2 py-1 text-xs text-slate-300"
              >
                {operators.map((op) => (
                  <option key={op} value={op}>
                    {OPERATOR_LABELS[op]}
                  </option>
                ))}
              </select>
            </div>
          )}

          <div className="px-3 pt-2">
            <input
              type="text"
              placeholder="Search..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full px-2 py-1.5 bg-slate-800 border border-slate-700 rounded text-sm text-slate-200 placeholder:text-slate-500"
            />
          </div>

          <div className="max-h-64 overflow-auto py-1 mt-2 border-t border-slate-700">
            <label className="flex items-center gap-2 px-3 py-1.5 hover:bg-slate-800/50 cursor-pointer text-sm">
              <input
                type="checkbox"
                checked={allSelected}
                onChange={() => setDraftSelected(allSelected ? [] : options.map((o) => o.value))}
                className="w-4 h-4 rounded accent-orange-500"
              />
              <span className="text-slate-200 font-medium">
                Select All ({options.reduce((sum, o) => sum + (o.count ?? 0), 0).toLocaleString()})
              </span>
            </label>

            {filteredOptions.length === 0 && <div className="px-3 py-2 text-slate-500 text-sm">No options</div>}

            {filteredOptions.map((opt) => (
              <label
                key={opt.value}
                data-testid={`pill-filter-option-${opt.value}`}
                className="flex items-center justify-between gap-2 px-3 py-1.5 hover:bg-slate-800/50 cursor-pointer text-sm"
              >
                <span className="flex items-center gap-2 min-w-0">
                  <input
                    type="checkbox"
                    checked={draftSelected.includes(opt.value)}
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

          <div className="flex items-center justify-end gap-2 px-3 py-2 border-t border-slate-700">
            <button
              type="button"
              onClick={handleClear}
              className="px-3 py-1.5 rounded text-sm text-slate-400 hover:text-slate-200"
            >
              Clear
            </button>
            <button
              type="button"
              onClick={handleApply}
              className="px-3 py-1.5 rounded text-sm bg-orange-600 hover:bg-orange-500 text-white font-medium"
            >
              Apply
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
