'use client'
import { useQuery } from '@tanstack/react-query'
import { Badge } from '@/components/ui/Badge'
import { Skeleton } from '@/components/ui/Skeleton'
import { inventoryApi } from '@/lib/api'
import type { LicenseCategory, ResourceDetail } from '@/lib/types'

interface SoftwareInventoryPanelProps {
  resource: ResourceDetail
  subtabKey: string
}

const CATEGORY_LABEL: Record<LicenseCategory, string> = {
  permissive: 'Permissive',
  copyleft: 'Copyleft',
  weak_copyleft: 'Weak Copyleft',
  unknown: 'Unknown',
}

function NotAvailableYet() {
  return <p className="text-slate-600 text-sm">This section isn&apos;t available yet.</p>
}

export function SoftwareInventoryPanel({ resource, subtabKey }: SoftwareInventoryPanelProps) {
  const { data, isLoading } = useQuery({
    queryKey: ['inventory-software', resource.key],
    queryFn: () => inventoryApi.software(resource.key).then((r) => r.data.data),
    staleTime: 60_000,
  })

  if (isLoading) {
    return (
      <div id="software-inventory-loading" className="space-y-2">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-8 w-full" />
        ))}
      </div>
    )
  }

  if (subtabKey === 'applications' || subtabKey === 'running_services') {
    return <NotAvailableYet />
  }

  if (!data || !data.sbom_generated_at) {
    return <p className="text-slate-600 text-sm">No SBOM has been generated for this resource yet.</p>
  }

  if (subtabKey === 'installed_packages') {
    if (data.installed_packages.length === 0) {
      return <p className="text-slate-600 text-sm">No packages detected in the SBOM.</p>
    }
    return (
      <table id="software-inventory-packages-table" className="w-full text-xs">
        <thead>
          <tr className="text-slate-500 text-left border-b border-slate-800">
            <th className="font-normal py-1">Name</th>
            <th className="font-normal py-1">Version</th>
            <th className="font-normal py-1">CVEs</th>
            <th className="font-normal py-1">Path</th>
          </tr>
        </thead>
        <tbody>
          {data.installed_packages.map((pkg) => (
            <tr
              key={`${pkg.name}@${pkg.version}`}
              data-testid={`software-package-row-${pkg.name}-${pkg.version}`}
              className="border-b border-slate-800/50"
            >
              <td className="py-1.5 text-slate-300 font-mono">{pkg.name}</td>
              <td className="py-1.5 text-slate-400 font-mono">{pkg.version}</td>
              <td className="py-1.5">
                <div className="flex flex-wrap gap-1">
                  {pkg.cve_ids.length > 0
                    ? pkg.cve_ids.map((cve) => (
                        <Badge key={cve} variant="severity-high">
                          {cve}
                        </Badge>
                      ))
                    : <span className="text-slate-600">—</span>}
                </div>
              </td>
              <td className="py-1.5 text-slate-500 font-mono">{pkg.filesystem_path ?? '—'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    )
  }

  if (subtabKey === 'licenses') {
    if (data.licenses.length === 0) {
      return <p className="text-slate-600 text-sm">No license information detected in the SBOM.</p>
    }
    return (
      <table id="software-inventory-licenses-table" className="w-full text-xs">
        <thead>
          <tr className="text-slate-500 text-left border-b border-slate-800">
            <th className="font-normal py-1">License</th>
            <th className="font-normal py-1">Category</th>
            <th className="font-normal py-1">Deprecated</th>
            <th className="font-normal py-1">Packages</th>
          </tr>
        </thead>
        <tbody>
          {data.licenses.map((lic) => (
            <tr
              key={lic.license_id}
              data-testid={`software-license-row-${lic.license_id}`}
              className="border-b border-slate-800/50"
            >
              <td className="py-1.5 text-slate-300 font-mono">{lic.license_id}</td>
              <td className="py-1.5">
                <Badge variant="default">{CATEGORY_LABEL[lic.category]}</Badge>
              </td>
              <td className="py-1.5">
                {lic.deprecated ? <Badge variant="severity-medium">Deprecated</Badge> : <span className="text-slate-600">—</span>}
              </td>
              <td className="py-1.5 text-slate-400">{lic.package_count}</td>
            </tr>
          ))}
        </tbody>
      </table>
    )
  }

  return <NotAvailableYet />
}
