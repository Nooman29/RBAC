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
  const [terminating, setTerminating] = useState(false);

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
      await client.patch(`/api/dashboard/alerts/${alertId}`, { reviewed: true, notes });
      setJustSaved(true);
      setTimeout(() => navigate("/alerts"), 700);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to save");
      setSaving(false);
    }
  }

  async function handleTerminate() {
    if (!window.confirm("Terminate this session? The user will be logged out immediately.")) return;
    setTerminating(true);
    setError("");
    try {
      await client.post(`/api/dashboard/sessions/${alert.session_id}/terminate`);
      load();
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to terminate session");
    } finally {
      setTerminating(false);
    }
  }

  if (error && !alert) return <p className="error">{error}</p>;
  if (!alert) return <p>Loading…</p>;

  const maxAbsShap = Math.max(1e-6, ...alert.shap_contributions.map((c) => Math.abs(c.shap_value)));

  return (
    <div>
      <Link to="/alerts">&larr; Back to alerts</Link>
      <h2>Alert #{alert.alert_id}</h2>

      <div className="detail-grid">
        <div><strong>User:</strong> {alert.username} ({alert.role_names.join(", ") || "no role"})</div>
        <div><strong>Session:</strong> {alert.session_id}</div>
        <div><strong>Login time:</strong> {new Date(alert.login_time).toLocaleString()}</div>
        <div><strong>Duration:</strong> {alert.session_duration ? `${Math.round(alert.session_duration)}s` : "—"}</div>
        <div><strong>IP:</strong> {alert.access_location || "unknown"}</div>
        <div className={alert.is_anomaly ? "score-flagged" : "score-normal"}>
          <strong>Anomaly score:</strong> {alert.anomaly_score.toFixed(4)} {alert.is_anomaly ? "⚠️ Flagged" : ""}
        </div>
      </div>

      <div className="session-status">
        {alert.session_terminated ? (
          <span className="badge badge-danger">Session terminated</span>
        ) : (
          <button className="danger-btn" onClick={handleTerminate} disabled={terminating}>
            {terminating ? "Terminating…" : "Terminate session"}
          </button>
        )}
      </div>

      {alert.shap_contributions.length > 0 && (
        <>
          <h3>Why this was flagged</h3>
          <p className="muted">
            Features ranked by how much they influenced this specific prediction — positive values pushed
            the session toward "anomalous," negative values pushed it toward "normal."
          </p>
          <div className="shap-list">
            {alert.shap_contributions.map((c) => (
              <div className="shap-row" key={c.feature}>
                <span className="shap-label">{c.feature}</span>
                <div className="shap-bar-track">
                  <div
                    className={`shap-bar ${c.shap_value >= 0 ? "shap-positive" : "shap-negative"}`}
                    style={{ width: `${(Math.abs(c.shap_value) / maxAbsShap) * 100}%` }}
                  />
                </div>
                <span className="shap-value">{c.shap_value.toFixed(3)}</span>
              </div>
            ))}
          </div>
        </>
      )}

      <h3>All behavioral features</h3>
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
      {error && <p className="error">{error}</p>}
      <textarea
        rows={4}
        value={notes}
        onChange={(e) => setNotes(e.target.value)}
        placeholder="Notes on this alert…"
      />
      <div>
        <button onClick={handleMarkReviewed} disabled={saving || justSaved}>
          {justSaved ? "Saved ✓" : saving ? "Saving…" : alert.reviewed ? "Update review" : "Mark reviewed"}
        </button>
        {justSaved && <span className="info"> Updated — returning to alerts…</span>}
      </div>
    </div>
  );
}