'use client'
import { useMemo, useState } from 'react'
import { Search } from 'lucide-react'
import { ScoreGauge, scoreColor } from './ScoreGauge'
import type { ComplianceFamily } from '@/lib/types'

interface FrameworkSidebarProps {
  families: ComplianceFamily[]
  selectedFamily: string | null
  onSelect: (familyKey: string) => void
}

export function FrameworkSidebar({ families, selectedFamily, onSelect }: FrameworkSidebarProps) {
  const [query, setQuery] = useState('')

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase()
    if (!q) return families
    return families.filter((f) => f.label.toLowerCase().includes(q) || f.family.toLowerCase().includes(q))
  }, [families, query])

  return (
    <div className="space-y-3">
      <h2 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">
        Frameworks
        <span className="ml-1.5 normal-case font-normal text-slate-600">({families.length})</span>
      </h2>

      <div className="relative">
        <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search frameworks…"
          className="w-full bg-slate-800 border border-slate-700 rounded pl-8 pr-3 py-1.5 text-sm text-slate-300 placeholder-slate-600 focus:outline-none focus:border-orange-500 focus:ring-1 focus:ring-orange-500/30"
          aria-label="Search frameworks"
        />
      </div>

      <div className="space-y-2 max-h-[calc(100vh-260px)] overflow-y-auto pr-1">
        {filtered.length === 0 && <p className="text-slate-600 text-sm px-1">No frameworks match your search.</p>}
        {filtered.map((fw) => {
          const headline = fw.versions[0]
          if (!headline) return null
          return (
            <button
              key={fw.family}
              onClick={() => onSelect(fw.family)}
              className={`w-full text-left p-3 rounded border transition-colors ${
                selectedFamily === fw.family
                  ? 'border-orange-500 bg-orange-500/5'
                  : 'border-slate-800 hover:border-slate-700 bg-slate-900'
              }`}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-slate-300 text-sm font-medium leading-tight">{fw.label}</span>
                <span className={`text-sm font-bold font-mono flex-shrink-0 ${scoreColor(headline.score)}`}>
                  {headline.score}%
                </span>
              </div>
              {fw.versions.length > 1 && (
                <div className="text-slate-600 text-xs mt-0.5">{fw.versions.length} versions</div>
              )}
              <ScoreGauge score={headline.score} />
              <div className="flex gap-3 mt-2 text-xs text-slate-500">
                <span className="text-green-400">{headline.pass} pass</span>
                <span className="text-red-400">{headline.fail} fail</span>
              </div>
            </button>
          )
        })}
      </div>
    </div>
  )
}
