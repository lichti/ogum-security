'use client'
import { useEffect, useRef, useState } from 'react'
import { ChevronDown, Pin } from 'lucide-react'
import { clsx } from 'clsx'
import type { SavedView } from '@/lib/types'

interface SavedViewSelectorProps {
  views: SavedView[]
  activeViewKey?: string
  onSelect: (view: SavedView) => void
  onPinToggle: (view: SavedView) => void
  onSaveAsNew: (name: string) => void
}

export function SavedViewSelector({
  views,
  activeViewKey,
  onSelect,
  onPinToggle,
  onSaveAsNew,
}: SavedViewSelectorProps) {
  const [open, setOpen] = useState(false)
  const [saving, setSaving] = useState(false)
  const [newName, setNewName] = useState('')
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    function handleClickOutside(event: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(event.target as Node)) {
        setOpen(false)
        setSaving(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  const pinned = views.filter((v) => v.pinned)

  function handleSave() {
    if (!newName.trim()) return
    onSaveAsNew(newName.trim())
    setNewName('')
    setSaving(false)
  }

  return (
    <div className="flex items-center gap-3" ref={containerRef}>
      {pinned.length > 0 && (
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-500 flex items-center gap-1">
            <Pin className="w-3 h-3" /> Pinned Views ({pinned.length})
          </span>
          {pinned.map((view) => (
            <button
              key={view.key}
              type="button"
              onClick={() => onSelect(view)}
              className={clsx(
                'px-2.5 py-1 rounded text-xs border',
                view.key === activeViewKey
                  ? 'border-orange-500 bg-orange-950/30 text-orange-400'
                  : 'border-slate-700 bg-slate-800 text-slate-300 hover:border-slate-600',
              )}
            >
              {view.name}
            </button>
          ))}
        </div>
      )}

      <div className="relative">
        <button
          type="button"
          onClick={() => setOpen((o) => !o)}
          className="flex items-center gap-1.5 px-3 py-1.5 border border-slate-700 bg-slate-800 rounded text-sm text-slate-300 hover:border-slate-600"
          aria-haspopup="listbox"
          aria-expanded={open}
        >
          All Views
          <ChevronDown className="w-3.5 h-3.5" />
        </button>

        {open && (
          <div
            role="listbox"
            aria-label="All Views"
            className="absolute z-50 mt-1 w-64 max-h-72 overflow-auto bg-slate-900 border border-slate-700 rounded-md shadow-lg py-1"
          >
            {views.length === 0 && <div className="px-3 py-2 text-slate-500 text-sm">No views yet</div>}
            {views.map((view) => (
              <div
                key={view.key}
                className="flex items-center justify-between gap-2 px-3 py-1.5 hover:bg-slate-800/50 text-sm"
              >
                <button
                  type="button"
                  onClick={() => {
                    onSelect(view)
                    setOpen(false)
                  }}
                  className="flex-1 text-left text-slate-300 truncate"
                >
                  {view.name}
                  {view.is_system && <span className="text-slate-600 text-xs ml-1">(system)</span>}
                </button>
                {!view.is_system && (
                  <button
                    type="button"
                    aria-label={view.pinned ? `Unpin ${view.name}` : `Pin ${view.name}`}
                    onClick={() => onPinToggle(view)}
                    className={view.pinned ? 'text-orange-400' : 'text-slate-600 hover:text-slate-400'}
                  >
                    <Pin className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {saving ? (
        <div className="flex items-center gap-1.5">
          <input
            autoFocus
            type="text"
            value={newName}
            onChange={(e) => setNewName(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSave()}
            placeholder="View name"
            className="px-2 py-1 bg-slate-800 border border-slate-700 rounded text-sm text-slate-200 placeholder:text-slate-500"
          />
          <button
            type="button"
            onClick={handleSave}
            className="px-2 py-1 rounded text-xs bg-orange-600 hover:bg-orange-500 text-white font-medium"
          >
            Save
          </button>
        </div>
      ) : (
        <button
          type="button"
          onClick={() => setSaving(true)}
          className="px-3 py-1.5 rounded text-sm border border-slate-700 text-slate-300 hover:border-slate-600"
        >
          Save as New
        </button>
      )}
    </div>
  )
}
