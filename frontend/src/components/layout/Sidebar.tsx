'use client'

import {
  Activity,
  Cloud,
  Database,
  GitBranch,
  LayoutDashboard,
  Plug,
  ScanLine,
  Settings2,
  Shield,
  ShieldAlert,
  CheckSquare,
  Terminal,
  Wand2,
} from 'lucide-react'
import { NavItem } from './NavItem'

interface SectionProps {
  label: string
  children: React.ReactNode
}

function NavSection({ label, children }: SectionProps) {
  return (
    <div className="mb-6">
      <p className="text-[10px] text-slate-500 tracking-widest uppercase mb-1 px-3">{label}</p>
      <nav className="flex flex-col gap-0.5">{children}</nav>
    </div>
  )
}

export function Sidebar() {
  return (
    <aside className="w-60 bg-slate-900 flex flex-col shrink-0 h-full overflow-y-auto">
      <div className="flex items-center gap-2 px-4 py-5 border-b border-slate-800">
        <Shield size={22} className="text-orange-500" />
        <span className="text-orange-500 font-bold text-base tracking-tight">Ogum Security</span>
      </div>

      <div className="flex flex-col flex-1 px-2 pt-6 pb-4">
        <NavSection label="Overview">
          <NavItem icon={LayoutDashboard} label="Dashboard" href="/" />
        </NavSection>

        <NavSection label="Security Posture">
          <NavItem icon={Database} label="Inventory" href="/inventory" />
          <NavItem icon={ShieldAlert} label="Findings" href="/findings" />
          <NavItem icon={CheckSquare} label="Compliance" href="/compliance" />
          <NavItem icon={GitBranch} label="Attack Paths" disabled badge="Soon" />
          <NavItem icon={ScanLine} label="Side Scanning" disabled badge="Soon" />
        </NavSection>

        <NavSection label="Threat Response">
          <NavItem icon={Activity} label="Pulse (NRT)" disabled badge="Soon" />
          <NavItem icon={Shield} label="CDR" disabled badge="Soon" />
        </NavSection>

        <NavSection label="Automation">
          <NavItem icon={Wand2} label="AI Remediation" disabled badge="Soon" />
        </NavSection>

        <NavSection label="Configuration">
          <NavItem icon={Cloud} label="Cloud Providers" href="/providers" />
          <NavItem icon={Plug} label="Integrations" disabled badge="Soon" />
          <NavItem icon={Terminal} label="Agent" disabled badge="Soon" />
        </NavSection>

        <NavSection label="Platform">
          <NavItem icon={Settings2} label="Admin" disabled badge="Soon" />
        </NavSection>
      </div>
    </aside>
  )
}
