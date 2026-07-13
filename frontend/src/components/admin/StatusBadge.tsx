const STATUS_COLORS: Record<string, string> = {
  completed: 'bg-green-900 text-green-300',
  success: 'bg-green-900 text-green-300',
  running: 'bg-blue-900 text-blue-300',
  started: 'bg-blue-900 text-blue-300',
  failed: 'bg-red-900 text-red-300',
  failure: 'bg-red-900 text-red-300',
  queued: 'bg-yellow-900 text-yellow-300',
  pending: 'bg-yellow-900 text-yellow-300',
}

export function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_COLORS[status.toLowerCase()] ?? 'bg-slate-700 text-slate-300'
  return (
    <span className={`inline-flex px-2 py-0.5 rounded text-xs font-medium ${cls}`}>
      {status}
    </span>
  )
}
