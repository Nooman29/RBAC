import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import client from "../api/client";
import { parseUtc } from "../utils/date";
import { describeDetection } from "../utils/detection";

const VERDICT_LABELS = {
  confirmed_threat: "Confirmed threat",
  false_positive: "False positive",
  authorized_exception: "Authorized exception",
};

export default function Alerts() {
  const [alerts, setAlerts] = useState([]);
  const [onlyAnomalous, setOnlyAnomalous] = useState(true);
  const [includeReviewed, setIncludeReviewed] = useState(true);
  const [error, setError] = useState("");

  function load() {
    client
      .get("/api/dashboard/alerts", {
        params: { only_anomalous: onlyAnomalous, include_reviewed: includeReviewed },
      })
      .then((res) => setAlerts(res.data))
      .catch((err) => setError(err.response?.data?.detail || "Failed to load alerts"));
  }

  useEffect(load, [onlyAnomalous, includeReviewed]);

  return (
    <div>
      <h2>Anomaly Alerts</h2>
      <div className="filter-bar">
        <label>
          <input
            type="checkbox"
            checked={onlyAnomalous}
            onChange={(e) => setOnlyAnomalous(e.target.checked)}
          />
          Only flagged anomalies
        </label>
        <label>
          <input
            type="checkbox"
            checked={includeReviewed}
            onChange={(e) => setIncludeReviewed(e.target.checked)}
          />
          Include reviewed
        </label>
      </div>
      {!onlyAnomalous && (
        <p className="muted">
          Showing every scored session, including ones the detector did not flag. If one of them was
          actually malicious, open it and mark it as a confirmed threat so the system learns the pattern.
        </p>
      )}

      {error && <p className="error">{error}</p>}

      <table className="data-table">
        <thead>
          <tr>
            <th>Alert ID</th>
            <th>Username</th>
            <th>Session</th>
            <th>Score</th>
            <th>Flagged</th>
            <th>Detection</th>
            <th>Verdict</th>
            <th>Timestamp</th>
          </tr>
        </thead>
        <tbody>
          {alerts.map((a) => (
            <tr key={a.alert_id}>
              <td>
                <Link to={`/alerts/${a.alert_id}`}>{a.alert_id}</Link>
              </td>
              <td>{a.username}</td>
              <td>{a.session_id}</td>
              <td>{a.anomaly_score.toFixed(4)}</td>
              <td>{a.is_anomaly ? "⚠️ Yes" : "No"}</td>
              <td>{a.is_anomaly ? describeDetection(a.detection_reason) : "—"}</td>
              <td>{a.review_verdict ? VERDICT_LABELS[a.review_verdict] || a.review_verdict : "—"}</td>
              <td>{parseUtc(a.alert_timestamp).toLocaleString()}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {alerts.length === 0 && !error && <p>No alerts match the current filters.</p>}
    </div>
  );
}