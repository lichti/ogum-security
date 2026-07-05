"use client";

import { useEffect, useState } from "react";
import { RefreshCw } from "lucide-react";

const API = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface Job {
  job_id: string;
  task_name: string;
  tenant_id: string;
  status: string;
  provider: string | null;
  created_at: string | null;
  worker: string | null;
}

const STATUS_COLORS: Record<string, string> = {
  completed: "bg-green-900 text-green-300",
  success: "bg-green-900 text-green-300",
  running: "bg-blue-900 text-blue-300",
  started: "bg-blue-900 text-blue-300",
  failed: "bg-red-900 text-red-300",
  failure: "bg-red-900 text-red-300",
  queued: "bg-yellow-900 text-yellow-300",
  pending: "bg-yellow-900 text-yellow-300",
};

function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_COLORS[status.toLowerCase()] ?? "bg-slate-700 text-slate-300";
  return (
    <span className={`inline-flex px-2 py-0.5 rounded text-xs font-medium ${cls}`}>
      {status}
    </span>
  );
}

export default function AdminJobsPage() {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  async function fetchJobs() {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`${API}/api/v1/admin/jobs`);
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const body = await res.json();
      setJobs(body.data?.items ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load jobs");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchJobs();
  }, []);

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-semibold text-slate-100">Admin — Jobs</h1>
        <button
          onClick={fetchJobs}
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

      <div className="rounded-lg border border-slate-800 overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-slate-800 text-slate-400 text-xs uppercase tracking-wider">
            <tr>
              <th className="px-4 py-3 text-left">Job ID</th>
              <th className="px-4 py-3 text-left">Tenant</th>
              <th className="px-4 py-3 text-left">Status</th>
              <th className="px-4 py-3 text-left">Provider</th>
              <th className="px-4 py-3 text-left">Created At</th>
              <th className="px-4 py-3 text-left">Worker</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800">
            {loading && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-slate-500">
                  Loading…
                </td>
              </tr>
            )}
            {!loading && jobs.length === 0 && (
              <tr>
                <td colSpan={6} className="px-4 py-8 text-center text-slate-500">
                  No jobs found.
                </td>
              </tr>
            )}
            {jobs.map((job) => (
              <tr key={job.job_id} className="hover:bg-slate-800/50 transition-colors">
                <td className="px-4 py-3 text-slate-300 font-mono text-xs">{job.job_id}</td>
                <td className="px-4 py-3 text-slate-300">{job.tenant_id}</td>
                <td className="px-4 py-3">
                  <StatusBadge status={job.status} />
                </td>
                <td className="px-4 py-3 text-slate-400">{job.provider ?? "—"}</td>
                <td className="px-4 py-3 text-slate-400">
                  {job.created_at ? new Date(job.created_at).toLocaleString() : "—"}
                </td>
                <td className="px-4 py-3 text-slate-500 text-xs">{job.worker ?? "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
