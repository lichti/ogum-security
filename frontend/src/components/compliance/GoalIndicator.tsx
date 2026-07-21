import { useEffect, useState } from 'react'

interface GoalIndicatorProps {
  score: number
  target: number | null
  onSetTarget?: (value: number | null) => void
  saving?: boolean
}

function clampGoal(raw: string): number | null {
  if (raw.trim() === '') return null
  const parsed = Number(raw)
  if (Number.isNaN(parsed)) return null
  return Math.min(100, Math.max(0, Math.round(parsed)))
}

// Compliance Settings (US-14.19) target — vs-goal marker shown wherever a target is
// configured. Editable inline here (not just on /settings/compliance) so a viewer can
// set or adjust a goal without leaving the framework they're already looking at.
// onSetTarget is optional so callers that only display a score (no mutation wired up)
// keep the original read-only marker instead of rendering dead controls.
export function GoalIndicator({ score, target, onSetTarget, saving }: GoalIndicatorProps) {
  const [editing, setEditing] = useState(false)
  const [draft, setDraft] = useState(target !== null ? String(target) : '')

  useEffect(() => {
    if (!editing) setDraft(target !== null ? String(target) : '')
  }, [target, editing])

  if (!onSetTarget) {
    if (target === null) return null
    const met = score >= target
    return (
      <div
        id="goal-indicator-readonly"
        className={`text-[10px] font-mono ${met ? 'text-green-500' : 'text-orange-400'}`}
        title={met ? `Meets the ${target}% goal` : `Below the ${target}% goal`}
      >
        {met ? '✓' : '▾'} Goal {target}%
      </div>
    )
  }

  if (editing) {
    const commit = () => {
      onSetTarget(clampGoal(draft))
      setEditing(false)
    }
    return (
      <div id="goal-indicator-editing" className="flex items-center gap-1 mt-0.5">
        <input
          id="goal-indicator-input"
          type="number"
          min={0}
          max={100}
          autoFocus
          value={draft}
          disabled={saving}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') commit()
            if (e.key === 'Escape') setEditing(false)
          }}
          aria-label="control goal percentage"
          className="w-14 bg-slate-800 border border-slate-700 rounded px-1.5 py-0.5 text-[10px] text-slate-200 focus:outline-none focus:border-orange-500"
        />
        <button
          type="button"
          onClick={commit}
          disabled={saving}
          aria-label="Save goal"
          className="text-green-500 hover:text-green-400 text-xs disabled:opacity-50"
        >
          ✓
        </button>
        <button
          type="button"
          onClick={() => setEditing(false)}
          aria-label="Cancel editing goal"
          className="text-slate-500 hover:text-slate-300 text-xs"
        >
          ✕
        </button>
        {target !== null && (
          <button
            type="button"
            onClick={() => {
              onSetTarget(null)
              setEditing(false)
            }}
            disabled={saving}
            aria-label="Clear goal"
            className="text-slate-600 hover:text-red-400 text-[10px] ml-1 disabled:opacity-50"
          >
            clear
          </button>
        )}
      </div>
    )
  }

  if (target === null) {
    return (
      <button
        id="goal-indicator-set-button"
        type="button"
        onClick={() => setEditing(true)}
        aria-label="Set control goal"
        className="text-[10px] font-mono text-slate-400 hover:text-slate-200 transition-colors"
      >
        + Set goal
      </button>
    )
  }

  const met = score >= target
  return (
    <button
      id="goal-indicator-edit-button"
      type="button"
      onClick={() => setEditing(true)}
      aria-label="Edit control goal"
      title={met ? `Meets the ${target}% goal — click to edit` : `Below the ${target}% goal — click to edit`}
      className={`text-[10px] font-mono hover:underline ${met ? 'text-green-500' : 'text-orange-400'}`}
    >
      {met ? '✓' : '▾'} Goal {target}%
    </button>
  )
}
