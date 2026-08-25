'use client'

import { useState } from 'react'
import { ChevronDown, Download, ExternalLink, Wand2 } from 'lucide-react'
import type { AttackPathDetail } from '@/lib/types'

interface TakeActionMenuProps {
  detail: AttackPathDetail
}

function downloadPathAsJson(detail: AttackPathDetail) {
  const blob = new Blob([JSON.stringify(detail, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `attack-path-${detail.path._key}.json`
  a.click()
  URL.revokeObjectURL(url)
}

export function TakeActionMenu({ detail }: TakeActionMenuProps) {
  const [open, setOpen] = useState(false)

  const resourceNodes = detail.nodes.filter((n) => typeof n['_id'] === 'string' && typeof n['_key'] === 'string')

  return (
    <div id="take-action-menu" className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-md bg-slate-800 hover:bg-slate-700 text-slate-300 border border-slate-700 transition-colors"
      >
        Take Action
        <ChevronDown size={12} />
      </button>

      {open && (
        <>
          <button
            type="button"
            aria-label="Close menu"
            onClick={() => setOpen(false)}
            className="fixed inset-0 z-10 cursor-default"
          />
          <div
            id="take-action-menu-dropdown"
            className="absolute bottom-full right-0 mb-2 z-20 w-64 rounded-lg border border-slate-700 bg-slate-900 shadow-xl py-1"
          >
            <button
              type="button"
              onClick={() => {
                downloadPathAsJson(detail)
                setOpen(false)
              }}
              className="w-full flex items-center gap-2 px-3 py-2 text-xs text-slate-300 hover:bg-slate-800 text-left"
            >
              <Download size={12} />
              Export path
            </button>

            {resourceNodes.length > 0 && (
              <div className="border-t border-slate-800 mt-1 pt-1">
                <p className="px-3 py-1 text-[10px] uppercase tracking-wide text-slate-600">
                  View each resource in Inventory
                </p>
                {resourceNodes.map((node) => {
                  const key = node['_key'] as string
                  const name = (node['name'] as string | undefined) ?? key
                  return (
                    <a
                      key={key}
                      href="/inventory"
                      title={`Search for "${name}" in Inventory`}
                      data-testid={`take-action-resource-${key}`}
                      className="flex items-center gap-2 px-3 py-2 text-xs text-slate-300 hover:bg-slate-800 truncate"
                    >
                      <ExternalLink size={12} className="shrink-0" />
                      <span className="truncate">{name}</span>
                    </a>
                  )
                })}
              </div>
            )}

            <div className="border-t border-slate-800 mt-1 pt-1">
              <button
                type="button"
                disabled
                title="Ogum.AI remediation PR generation — not available yet (Epic 05)"
                className="w-full flex items-center gap-2 px-3 py-2 text-xs text-slate-500 cursor-not-allowed text-left"
              >
                <Wand2 size={12} />
                Generate remediation PR
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
