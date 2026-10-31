import { useEffect, useState } from "react";
import client from "../api/client";
import { parseUtc } from "../utils/date";
import { describeLiveRule, SEVERITY_BADGES } from "../utils/detection";
import { usePermissions } from "../context/PermissionsContext";

// The backend serves this list without writing an audit row, so polling never counts as
// the administrator's own activity in the anomaly model.
const POLL_MS = 10000;

function sessionState(a) {
  if (a.session_terminated) return <span className="badge badge-danger">Terminated</span>;
  if (a.session_active) return <span className="badge badge-online">In progress</span>;
  return <span className="badge badge-neutral">Session ended</span>;
}

function topFeatures(a) {
  const latest = a.evidence[a.evidence.length - 1] || {};
  return (latest.top_features || []).map((f) => f.feature).join(", ");
}

export default function LiveAlertsPanel() {
  const [alerts, setAlerts] = useState([]);
  const [error, setError] = useState("");
  const [busyId, setBusyId] = useState(null);
  const { can } = usePermissions();
  const canWrite = can && can("dashboard", "write");

  function load() {
    client
      .get("/api/dashboard/live-alerts")
      .then((res) => {
        setAlerts(res.data);
        setError("");
      })
      .catch((err) => setError(err.response?.data?.detail || "Failed to load live alerts"));
  }

  useEffect(() => {
    load();
    const interval = setInterval(load, POLL_MS);
    return () => clearInterval(interval);
  }, []);

  async function handleTerminate(a) {
    if (!window.confirm(`Terminate ${a.username}'s session #${a.session_id}? They will be logged out immediately.`)) return;
    setBusyId(a.live_alert_id);
    try {
      await client.post(`/api/dashboard/sessions/${a.session_id}/terminate`);
      load();
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to terminate session");
    } finally {
      setBusyId(null);
    }
  }

  async function handleDismiss(a) {
    setBusyId(a.live_alert_id);
    try {
      await client.post(`/api/dashboard/live-alerts/${a.live_alert_id}/dismiss`);
      load();
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to dismiss");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div className="panel" id="live">
      <h3>In progress: live alerts</h3>
      <p className="muted">
        Early warnings raised while a session is still active, so it can be stopped in time. The score
        taken when the session ends stays the official verdict.
      </p>
      {error && <p className="error">{error}</p>}
      {alerts.length === 0 && !error ? (
        <p className="muted">No open live alerts right now.</p>
      ) : (
        <table className="data-table">
          <thead>
            <tr>
              <th>User</th>
              <th>Rule</th>
              <th>Severity</th>
              <th>What happened</th>
              <th>Hits</th>
              <th>First seen</th>
              <th>Session</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((a) => (
              <tr key={a.live_alert_id}>
                <td>{a.username}</td>
                <td>
                  {describeLiveRule(a.rule)}
                  {a.is_learning && <span className="badge" style={{ marginLeft: 6 }}>Learning period</span>}
                </td>
                <td><span className={SEVERITY_BADGES[a.severity] || "badge"}>{a.severity}</span></td>
                <td>
                  {a.summary}
                  {a.rule === "model_provisional" && topFeatures(a) && (
                    <div className="muted">Top factors: {topFeatures(a)}</div>
                  )}
                </td>
                <td>{a.hit_count}</td>
                <td>{parseUtc(a.first_seen_at).toLocaleString()}</td>
                <td>{sessionState(a)}</td>
                <td>
                  {canWrite && a.session_active && (
                    <button className="danger-btn" onClick={() => handleTerminate(a)} disabled={busyId === a.live_alert_id}>
                      {busyId === a.live_alert_id ? "Terminating…" : "Terminate"}
                    </button>
                  )}
                  {canWrite && (
                    <button
                      className="link-btn"
                      style={{ marginLeft: 8 }}
                      onClick={() => handleDismiss(a)}
                      disabled={busyId === a.live_alert_id}
                    >
                      Dismiss
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
