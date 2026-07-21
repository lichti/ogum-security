'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ChevronLeft, ChevronRight } from 'lucide-react'
import { attackPathsApi } from '@/lib/api'

interface AttackPathNarrativeProps {
  pathKey: string
}

export function AttackPathNarrative({ pathKey }: AttackPathNarrativeProps) {
  const [stepIndex, setStepIndex] = useState(0)

  const { data, isLoading } = useQuery({
    queryKey: ['attack-path-narrative', pathKey],
    queryFn: () => attackPathsApi.getNarrative(pathKey).then((r) => r.data.data),
    staleTime: 60_000,
  })

  if (isLoading) {
    return <div className="h-4 w-3/4 bg-slate-800 rounded animate-pulse" data-testid="narrative-loading" />
  }
  if (!data || data.steps.length === 0) return null

  const step = data.steps[Math.min(stepIndex, data.steps.length - 1)]

  return (
    <div id="attack-path-narrative" className="space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-slate-500 text-[11px] font-semibold uppercase tracking-wide">{step.title}</span>
        <span className="text-slate-600 text-[11px] tabular-nums">
          {step.index}/{step.total}
        </span>
      </div>
      <p className="text-slate-300 text-sm leading-relaxed">{step.text}</p>
      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={() => setStepIndex((i) => Math.max(0, i - 1))}
          disabled={stepIndex === 0}
          aria-label="Previous step"
          className="p-1 rounded bg-slate-800 border border-slate-700 text-slate-400 disabled:opacity-30 disabled:cursor-not-allowed hover:border-orange-500"
        >
          <ChevronLeft size={12} />
        </button>
        <button
          type="button"
          onClick={() => setStepIndex((i) => Math.min(data.steps.length - 1, i + 1))}
          disabled={stepIndex === data.steps.length - 1}
          aria-label="Next step"
          className="p-1 rounded bg-slate-800 border border-slate-700 text-slate-400 disabled:opacity-30 disabled:cursor-not-allowed hover:border-orange-500"
        >
          <ChevronRight size={12} />
        </button>
      </div>
    </div>
  )
}
