import { useEffect, useState } from "react";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from "recharts";
import client from "../api/client";

const COLORS = {
  "Confirmed Threat": "#d9534f",
  "False Positive": "#5b8def",
  "Authorized Exception": "#f0ad4e",
  "Unreviewed": "#999999",
};

export default function DetectionOutcomes() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    client
      .get("/api/dashboard/detection-outcomes")
      .then((res) => setData(res.data))
      .catch((err) => setError(err.response?.data?.detail || "Failed to load"));
  }, []);

  if (error) return <p className="error">{error}</p>;
  if (!data) return <p>Loading…</p>;

  const chartData = [
    { name: "Confirmed Threat", count: data.confirmed_threat },
    { name: "False Positive", count: data.false_positive },
    { name: "Authorized Exception", count: data.authorized_exception },
    { name: "Unreviewed", count: data.unreviewed },
  ];

  const reviewedTotal = data.confirmed_threat + data.false_positive + data.authorized_exception;
  const precisionProxy = reviewedTotal > 0
    ? (((data.confirmed_threat + data.authorized_exception) / reviewedTotal) * 100).toFixed(1)
    : null;

  return (
    <div>
      <h2>Detection Outcomes</h2>
      <p className="muted">
        A live breakdown of how flagged alerts have actually been dispositioned by administrators —
        a real-world evaluation of the detection pipeline, distinct from the offline model evaluation.
      </p>

      <div className="card-grid">
        <div className="stat-card">
          <span className="stat-value">{data.total_flagged}</span>
          <span className="stat-label">Total Flagged</span>
        </div>
        <div className="stat-card">
          <span className="stat-value">{data.unreviewed}</span>
          <span className="stat-label">Unreviewed</span>
        </div>
        <div className="stat-card highlight">
          <span className="stat-value">{data.unreviewed_overdue}</span>
          <span className="stat-label">Overdue Review (24h+)</span>
        </div>
        {precisionProxy !== null && (
          <div className="stat-card">
            <span className="stat-value">{precisionProxy}%</span>
            <span className="stat-label">Of Reviewed Alerts Were Genuine (Threat or Authorized)</span>
          </div>
        )}
      </div>

      <div className="chart-card" style={{ marginTop: 24 }}>
        <h3>Alerts by Verdict</h3>
        <ResponsiveContainer width="100%" height={280}>
          <BarChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="name" tick={{ fontSize: 12 }} />
            <YAxis allowDecimals={false} />
            <Tooltip />
            <Bar dataKey="count">
              {chartData.map((entry) => (
                <Cell key={entry.name} fill={COLORS[entry.name]} />
              ))}
            </Bar>
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}