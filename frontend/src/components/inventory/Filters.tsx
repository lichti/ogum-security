'use client'
import { Search, X } from 'lucide-react'
import { MultiSelectFilter, type MultiSelectOption } from '@/components/ui/MultiSelectFilter'

interface FiltersProps {
  search: string
  onSearch: (search: string) => void

  providerOptions: MultiSelectOption[]
  selectedProviders: string[]
  onProvidersChange: (values: string[]) => void

  categoryOptions: MultiSelectOption[]
  selectedCategories: string[]
  onCategoriesChange: (values: string[]) => void

  regionOptions: MultiSelectOption[]
  selectedRegions: string[]
  onRegionsChange: (values: string[]) => void

  accountOptions: MultiSelectOption[]
  selectedAccounts: string[]
  onAccountsChange: (values: string[]) => void

  onClear: () => void
}

export function Filters({
  search,
  onSearch,
  providerOptions,
  selectedProviders,
  onProvidersChange,
  categoryOptions,
  selectedCategories,
  onCategoriesChange,
  regionOptions,
  selectedRegions,
  onRegionsChange,
  accountOptions,
  selectedAccounts,
  onAccountsChange,
  onClear,
}: FiltersProps) {
  const hasActiveFilters =
    !!search ||
    selectedProviders.length > 0 ||
    selectedCategories.length > 0 ||
    selectedRegions.length > 0 ||
    selectedAccounts.length > 0

  return (
    <div className="flex gap-3 items-center flex-wrap">
      <div className="relative flex-1 min-w-[220px] max-w-sm">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
        <input
          type="text"
          value={search}
          placeholder="Search by name, ARN, or ID..."
          onChange={(e) => onSearch(e.target.value)}
          className="w-full pl-9 pr-3 py-2 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-orange-500"
        />
      </div>

      <MultiSelectFilter
        label="Providers"
        options={providerOptions}
        selected={selectedProviders}
        onChange={onProvidersChange}
      />
      <MultiSelectFilter
        label="Categories"
        options={categoryOptions}
        selected={selectedCategories}
        onChange={onCategoriesChange}
      />
      <MultiSelectFilter
        label="Regions"
        options={regionOptions}
        selected={selectedRegions}
        onChange={onRegionsChange}
      />
      <MultiSelectFilter
        label="Accounts"
        options={accountOptions}
        selected={selectedAccounts}
        onChange={onAccountsChange}
      />

      {hasActiveFilters && (
        <button
          onClick={onClear}
          className="flex items-center gap-1 text-slate-500 hover:text-slate-300 text-sm transition-colors"
        >
          <X className="w-3.5 h-3.5" />
          Clear filters
        </button>
      )}
    </div>
  )
}
