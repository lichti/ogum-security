"use client";

import { useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface QueueDepth {
  queue: string;
  depth: number;
}

const MAX_BAR = 100;

export default function AdminQueueDepthPage() {
  const [queues, setQueues] = useState<QueueDepth[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function fetchQueues() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API}/api/v1/admin/queue-depth`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setQueues(body.data ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load queue depths");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchQueues();
    const id = setInterval(fetchQueues, 10_000);
    return () => clearInterval(id);
  }, []);

  const maxDepth = Math.max(...queues.map((q) => q.depth), 1);

  return (
    <div id="admin-queue-depth-page" className="p-6">
      <div className="flex items-center justify-end mb-6">
        <button
          onClick={fetchQueues}
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

      <div id="admin-queue-depth-list" className="rounded-lg border border-slate-800 bg-slate-900 p-6 space-y-5">
        {loading && <p className="text-slate-500 text-sm">Loading…</p>}
        {queues.map((q) => {
          const pct = Math.min((q.depth / maxDepth) * MAX_BAR, 100);
          const barColor = q.depth === 0 ? "bg-slate-700" : q.depth > 50 ? "bg-red-500" : "bg-orange-500";
          return (
            <div key={q.queue} data-testid={`queue-depth-row-${q.queue}`}>
              <div className="flex justify-between text-sm mb-1.5">
                <span className="text-slate-300 font-medium">{q.queue}</span>
                <span className={q.depth > 0 ? "text-orange-400 font-semibold" : "text-slate-500"}>
                  {q.depth} msgs
                </span>
              </div>
              <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all duration-300 ${barColor}`}
                  style={{ width: `${pct}%` }}
                />
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
