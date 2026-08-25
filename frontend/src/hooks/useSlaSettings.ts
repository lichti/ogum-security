import { useQuery } from '@tanstack/react-query'
import { classifySLA, type SLAStatus } from '@/components/ui/SLABadge'
import { settingsApi } from '@/lib/api'
import type { SLASettings, SeverityLevel } from '@/lib/types'

const DEFAULT_SLA: SLASettings = { critical_days: 7, high_days: 30, medium_days: 90, low_days: 180 }

const DAYS_BY_SEVERITY: Partial<Record<SeverityLevel, keyof SLASettings>> = {
  CRITICAL: 'critical_days',
  HIGH: 'high_days',
  MEDIUM: 'medium_days',
  LOW: 'low_days',
}

export function useSlaSettings() {
  const { data } = useQuery({
    queryKey: ['sla-settings'],
    queryFn: () => settingsApi.getSla().then((r) => r.data.data),
    staleTime: 5 * 60_000,
  })
  const sla = data ?? DEFAULT_SLA

  function classify(detectedAt: string, severity: SeverityLevel): SLAStatus | null {
    const key = DAYS_BY_SEVERITY[severity]
    if (!key) return null
    return classifySLA(new Date(detectedAt), sla[key])
  }

  return { sla, classify }
}
