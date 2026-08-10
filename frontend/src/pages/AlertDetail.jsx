import { useEffect, useState } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import client from "../api/client";

export default function AlertDetail() {
  const { alertId } = useParams();
  const navigate = useNavigate();
  const [alert, setAlert] = useState(null);
  const [notes, setNotes] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [justSaved, setJustSaved] = useState(false);

  function load() {
    client
      .get(`/api/dashboard/alerts/${alertId}`)
      .then((res) => {
        setAlert(res.data);
        setNotes(res.data.notes || "");
      })
      .catch((err) => setError(err.response?.data?.detail || "Failed to load alert"));
  }

  useEffect(load, [alertId]);

  async function handleMarkReviewed() {
    setSaving(true);
    setError("");
    try {
      await client.patch(`/api/dashboard/alerts/${alertId}`, {
        reviewed: true,
        notes,
      });
      setJustSaved(true);
      setTimeout(() => {
        navigate("/alerts");
      }, 700);
    } catch (err) {
        setError(err.response?.data?.detail || "Failed to save");
        setSaving(false);
    } 
  }

  if (error) return <p className="error">{error}</p>;
  if (!alert) return <p>Loading…</p>;

  return (
    <div>
      <Link to="/alerts">&larr; Back to alerts</Link>
      <h2>Alert #{alert.alert_id}</h2>

      <div className="detail-grid">
        <div>
          <strong>User:</strong> {alert.username} ({alert.role_names.join(", ") || "no role"})
        </div>
        <div>
          <strong>Session:</strong> {alert.session_id}
        </div>
        <div>
          <strong>Login time:</strong> {new Date(alert.login_time).toLocaleString()}
        </div>
        <div>
          <strong>Duration:</strong>{" "}
          {alert.session_duration ? `${Math.round(alert.session_duration)}s` : "—"}
        </div>
        <div>
          <strong>IP:</strong> {alert.access_location || "unknown"}
        </div>
        <div className={alert.is_anomaly ? "score-flagged" : "score-normal"}>
          <strong>Anomaly score:</strong> {alert.anomaly_score.toFixed(4)}{" "}
          {alert.is_anomaly ? "⚠️ Flagged" : ""}
        </div>
      </div>

      <h3>Behavioral features</h3>
      <table className="data-table">
        <tbody>
          {Object.entries(alert.features).map(([key, value]) => (
            <tr key={key}>
              <td>{key}</td>
              <td>{typeof value === "number" ? value.toFixed(3) : String(value)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h3>Review</h3>
      <textarea
        rows={4}
        value={notes}
        onChange={(e) => setNotes(e.target.value)}
        placeholder="Notes on this alert…"
      />
      <div>
        <button onClick={handleMarkReviewed} disabled={saving}>
          {alert.reviewed ? "Update review" : "Mark reviewed"}
        </button>
        {alert.reviewed && <span className="info"> Already reviewed</span>}
      </div>
    </div>
  );
}