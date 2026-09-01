import { useEffect, useState } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import client from "../api/client";

const FEATURE_META = {
  login_hour: { label: "Login hour", describe: (raw) => `Logged in at ${Math.round(raw)}:00.` },
  is_offhours: { label: "Off-hours login", describe: (raw) => (raw ? "Logged in outside normal business hours (before 7am or after 7pm)." : "Logged in during normal business hours.") },
  is_weekend: { label: "Weekend login", describe: (raw) => (raw ? "Logged in on a weekend." : "Logged in on a weekday.") },
  session_duration_sec: { label: "Session duration", describe: (raw) => `Session lasted about ${Math.round(raw)} seconds.` },
  n_access_events: { label: "Resource accesses", describe: (raw) => `Accessed resources ${Math.round(raw)} time(s).` },
  distinct_resources: { label: "Distinct resources touched", describe: (raw) => `Touched ${Math.round(raw)} distinct resource(s).` },
  distinct_actions: { label: "Distinct action types", describe: (raw) => `Used ${Math.round(raw)} distinct action type(s).` },
  n_read: { label: "Read actions", describe: (raw) => `Performed ${Math.round(raw)} read action(s).` },
  n_write: { label: "Write actions", describe: (raw) => `Performed ${Math.round(raw)} write action(s).` },
  n_delete: { label: "Delete actions", describe: (raw) => `Performed ${Math.round(raw)} delete action(s).` },
  new_ip: { label: "Unfamiliar IP address", describe: (raw) => (raw ? "Logged in from an IP address not seen before for this user." : "Logged in from a previously-seen IP address.") },
  session_duration_sec_zscore: { label: "Session duration vs. usual", isZScore: true, baseKey: "session_duration_sec", baseLabel: "Session duration" },
  n_access_events_zscore: { label: "Access volume vs. usual", isZScore: true, baseKey: "n_access_events", baseLabel: "Access volume" },
  distinct_resources_zscore: { label: "Resource variety vs. usual", isZScore: true, baseKey: "distinct_resources", baseLabel: "Resource variety" },
  n_write_zscore: { label: "Write volume vs. usual", isZScore: true, baseKey: "n_write", baseLabel: "Write volume" },
  n_delete_zscore: { label: "Delete volume vs. usual", isZScore: true, baseKey: "n_delete", baseLabel: "Delete volume" },
};

function describeZScore(baseLabel, z, rawValue) {
  const direction = z >= 0 ? "above" : "below";
  const magnitude = Math.abs(z) > 2 ? "far" : Math.abs(z) > 1 ? "moderately" : "slightly";
  return `${baseLabel} (${Math.round(rawValue)}) was ${magnitude} ${direction} this user's typical pattern (z \u2248 ${z.toFixed(1)}).`;
}

function describeFeature(featureKey, features) {
  const meta = FEATURE_META[featureKey];
  if (!meta) return featureKey;
  if (meta.isZScore) {
    return describeZScore(meta.baseLabel, features[featureKey], features[meta.baseKey]);
  }
  return meta.describe(features[featureKey]);
}

export default function AlertDetail() {
  const { alertId } = useParams();
  const navigate = useNavigate();
  const [alert, setAlert] = useState(null);
  const [notes, setNotes] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [justSaved, setJustSaved] = useState(false);

  const [terminating, setTerminating] = useState(false);
  const [terminateMsg, setTerminateMsg] = useState("");

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

  // handle termination 
  async function handleTerminate() {
    if (!window.confirm("Terminate this session? The user will be logged out immediately if online.")) return;
    setTerminating(true);
    setTerminateMsg("");
    try {
      await client.post(`/api/dashboard/sessions/${alert.session_id}/terminate`);
      setTerminateMsg("Session terminated. The user's session has been ended.");
      load();
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to terminate session");
    } finally {
      setTerminating(false);
    }
  }

  if (error && !alert) return <p className="error">{error}</p>;

  if (error && !alert) return <p className="error">{error}</p>;
  if (!alert) return <p>Loading…</p>;

  const maxAbsShap = Math.max(1e-6, ...alert.shap_contributions.map((c) => Math.abs(c.shap_value)));
  const topForSummary = [...alert.shap_contributions]
    .filter((c) => c.shap_value > 0)
    .sort((a, b) => b.shap_value - a.shap_value)
    .slice(0, 3);

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
          <span className="badge badge-danger">Terminated by an administrator</span>
        ) : alert.session_active ? (
          <span className="badge badge-online">Online — session still active</span>
        ) : (
          <span className="badge badge-neutral">Ended normally — user logged out</span>
        )}

        {!alert.session_terminated && (
          <button className="danger" onClick={handleTerminate} disabled={terminating} style={{ marginLeft: 12 }}>
            {terminating ? "Terminating…" : "Terminate Session"}
          </button>
        )}
      </div>
      {terminateMsg && <p className="info">{terminateMsg}</p>}

      {alert.shap_contributions.length > 0 && (
        <>
          <h3>Why this was flagged</h3>
          {topForSummary.length > 0 ? (
            <p className="explanation-summary">
              {alert.is_anomaly ? "This session was flagged as anomalous. " : "This session scored close to the anomaly threshold. "}
              {topForSummary.map((c) => describeFeature(c.feature, alert.features)).join(" ")}
            </p>
          ) : (
            <p className="explanation-summary">
              No single factor stood out strongly — the score came from a combination of smaller deviations across several features.
            </p>
          )}

          <p className="muted">
            Full ranked breakdown below — bars show how much each feature pushed the score toward "anomalous" (red) versus "normal" (blue).
          </p>
          <div className="shap-list">
            {alert.shap_contributions.map((c) => (
              <div className="shap-row" key={c.feature}>
                <span className="shap-label">
                  {FEATURE_META[c.feature]?.label || c.feature}
                  <span className="shap-key">{c.feature}</span>
                </span>
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
              <td>{FEATURE_META[key]?.label || key}</td>
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