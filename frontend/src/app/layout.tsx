import type { Metadata } from 'next'
import { Inter } from 'next/font/google'
import { QueryProvider } from './providers/query-provider'
import './globals.css'

const inter = Inter({ subsets: ['latin'] })

export const metadata: Metadata = {
  title: 'Ogum Security',
  description: 'Open-Source Cloud Security Platform',
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} bg-slate-950 text-slate-50 min-h-screen`}>
        <QueryProvider>{children}</QueryProvider>
      </body>
    </html>
  )
}
