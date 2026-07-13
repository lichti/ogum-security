interface CrownJewelBadgeProps {
  origin: 'auto' | 'manual'
  className?: string
}

export function CrownJewelBadge({ origin, className }: CrownJewelBadgeProps) {
  const isAuto = origin === 'auto'
  return (
    <div className={`inline-flex flex-col ${className ?? ''}`}>
      <span
        className={`inline-flex items-center gap-1 text-orange-400 text-sm font-medium px-1.5 py-0.5 rounded border ${
          isAuto ? 'border-orange-400' : 'border-dashed border-orange-400/60'
        }`}
      >
        <span aria-hidden="true">♛</span>
        Crown Jewel
      </span>
      <span className="text-xs text-slate-500">{isAuto ? 'auto-detected' : 'manually marked'}</span>
    </div>
  )
}
