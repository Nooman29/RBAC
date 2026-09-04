import { useEffect, useState } from "react";
import client from "../api/client";
import {
  ResponsiveContainer, LineChart, Line, BarChart, Bar,
  XAxis, YAxis, CartesianGrid, Tooltip,
} from "recharts";
import NeedsReviewPanel from "../components/NeedsReviewPanel";

export default function Dashboard() {
  const [summary, setSummary] = useState(null);
  const [alertsData, setAlertsData] = useState([]);
  const [sessionData, setSessionData] = useState([]);
  const [error, setError] = useState("");

  useEffect(() => {
    client
      .get("/api/dashboard/summary")
      .then((res) => setSummary(res.data))
      .catch((err) => setError(err.response?.data?.detail || "Failed to load summary"));

    client
      .get("/api/dashboard/charts/alerts-over-time?days=14")
      .then((res) => setAlertsData(res.data))
      .catch(() => {});

    client
      .get("/api/dashboard/charts/session-activity?days=14")
      .then((res) => setSessionData(res.data))
      .catch(() => {});
  }, []);

  if (error) return <p className="error">{error}</p>;
  if (!summary) return <p>Loading…</p>;

  return (
    <div>
      <h2>Overview</h2>
      <NeedsReviewPanel />
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

      <div className="chart-grid">
        <div className="chart-card">
          <h3>Alerts (last 14 days)</h3>
          <ResponsiveContainer width="100%" height={250}>
            <LineChart data={alertsData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" tick={{ fontSize: 11 }} />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Line type="monotone" dataKey="alerts" stroke="#d9534f" strokeWidth={2} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="chart-card">
          <h3>Session Activity (last 14 days)</h3>
          <ResponsiveContainer width="100%" height={250}>
            <BarChart data={sessionData}>
              <CartesianGrid strokeDasharray="3 3" />
              <XAxis dataKey="date" tick={{ fontSize: 11 }} />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Bar dataKey="sessions" fill="#5b8def" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}