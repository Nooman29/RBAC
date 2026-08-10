import { useEffect, useState } from "react";
import client from "../api/client";

export default function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    client
      .get("/api/dashboard/summary")
      .then((res) => setSummary(res.data))
      .catch((err) => setError(err.response?.data?.detail || "Failed to load summary"));
  }, []);

  if (error) return <p className="error">{error}</p>;
  if (!summary) return <p>Loading…</p>;

  return (
    <div>
      <h2>Overview</h2>
      <div className="card-grid">
        <div className="stat-card">
          <span className="stat-value">{summary.active_sessions}</span>
          <span className="stat-label">Active Sessions</span>
        </div>
        <div className="stat-card">
          <span className="stat-value">{summary.total_users}</span>
          <span className="stat-label">Total Users</span>
        </div>
        <div className="stat-card">
          <span className="stat-value">{summary.roles_configured}</span>
          <span className="stat-label">Roles Configured</span>
        </div>
        <div className="stat-card highlight">
          <span className="stat-value">{summary.alerts_today}</span>
          <span className="stat-label">Alerts Today</span>
        </div>
      </div>
    </div>
  );
}