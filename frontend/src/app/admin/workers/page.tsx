"use client";

import { useEffect, useState } from "react";
import { RefreshCw, Circle } from "lucide-react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface Worker {
  hostname: string;
  status: string;
  active_tasks: number;
  processed: number;
  uptime_seconds: number | null;
}

function formatUptime(seconds: number | null): string {
  if (seconds === null) return "—";
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  return `${h}h ${m}m`;
}

export default function AdminWorkersPage() {
  const [workers, setWorkers] = useState<Worker[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function fetchWorkers() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API}/api/v1/admin/workers`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setWorkers(body.data ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load workers");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchWorkers();
  }, []);

  return (
    <div id="admin-workers-page" className="p-6">
      <div className="flex items-center justify-end mb-6">
        <button
          onClick={fetchWorkers}
          className="flex items-center gap-2 px-3 py-1.5 rounded bg-slate-800 hover:bg-slate-700 text-slate-300 text-sm transition-colors"
        >
          <RefreshCw size={14} className={loading ? "animate-spin" : ""} />
          Refresh
        </button>
      </div>

      {error && (
        <div className="mb-4 px-4 py-3 rounded bg-red-900/40 border border-red-800 text-red-300 text-sm">
          {error}
        </div>
      )}

      {!loading && workers.length === 0 && !error && (
        <div className="rounded-lg border border-slate-800 px-6 py-12 text-center text-slate-500">
          No active workers. Start a Celery worker with <code className="text-slate-400">make up-worker</code>.
        </div>
      )}

      <div id="admin-workers-list" className="grid gap-4">
        {workers.map((w) => (
          <div key={w.hostname} data-testid={`admin-worker-card-${w.hostname}`} className="rounded-lg border border-slate-800 bg-slate-900 p-5">
            <div className="flex items-center gap-2 mb-3">
              <Circle size={8} className="text-green-400 fill-green-400" />
              <span className="text-slate-100 font-medium">{w.hostname}</span>
              <span className="ml-auto text-xs text-slate-500">uptime {formatUptime(w.uptime_seconds)}</span>
            </div>
            <div className="grid grid-cols-2 gap-4 text-sm">
              <div>
                <p className="text-slate-500 text-xs mb-1">Active tasks</p>
                <p className="text-orange-400 font-semibold text-lg">{w.active_tasks}</p>
              </div>
              <div>
                <p className="text-slate-500 text-xs mb-1">Processed</p>
                <p className="text-slate-300 font-semibold text-lg">{w.processed}</p>
              </div>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
