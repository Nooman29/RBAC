import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import client from "../api/client";
import { parseUtc } from "../utils/date";
import { usePermissions } from "../context/PermissionsContext";
import ViewOnlyNotice from "../components/ViewOnlyNotice";

const VERDICT_LABELS = {
  confirmed_threat: "Confirmed threat",
  false_positive: "False positive",
  authorized_exception: "Authorized exception",
};

export default function Sessions() {
  const [sessions, setSessions] = useState([]);
  const [showAll, setShowAll] = useState(false);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [busyId, setBusyId] = useState(null);
  const { can } = usePermissions();
  const canWrite = can && can("dashboard", "write");

  function load() {
    client
      .get("/api/dashboard/sessions", { params: { active_only: !showAll } })
      .then((res) => setSessions(res.data))
      .catch((err) => setError(err.response?.data?.detail || "Failed to load sessions"));
  }

  useEffect(load, [showAll]);

  async function handleTerminate(sessionId) {
    if (!window.confirm("Terminate this session? The user will be logged out immediately.")) return;
    setBusyId(sessionId);
    setError("");
    setInfo("");
    try {
      await client.post(`/api/dashboard/sessions/${sessionId}/terminate`);
      load();
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to terminate session");
    } finally {
      setBusyId(null);
    }
  }

  async function handleReportThreat(s) {
    const ok = window.confirm(
      `Mark ${s.username}'s session #${s.session_id} as a confirmed threat?\n\n` +
        "The detector will remember this pattern and flag it next time this user does it, " +
        "and this session will stay out of their normal history."
    );
    if (!ok) return;
    setBusyId(s.session_id);
    setError("");
    setInfo("");
    try {
      await client.patch(`/api/dashboard/alerts/${s.alert_id}`, { review_verdict: "confirmed_threat" });
      setInfo(`Session #${s.session_id} recorded as a confirmed threat.`);
      load();
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to record the verdict");
    } finally {
      setBusyId(null);
    }
  }

  function statusLabel(s) {
    if (s.terminated) return "Terminated";
    return s.is_active ? "Online" : "Ended";
  }

  return (
    <div>
      <h2>{showAll ? "Recent Sessions" : "Active Sessions"}</h2>
      <p className="muted">
        {showAll
          ? "The latest 100 sessions with their detection result. If the detector let a malicious session through, report it so the system learns the pattern."
          : "Users currently logged in. Terminating a session logs the user out immediately and scores it for anomalies."}
      </p>
      <ViewOnlyNotice resource="dashboard" label="sessions" />
      <div className="filter-bar">
        <button className="secondary-btn" onClick={load}>Refresh</button>
        <label>
          <input type="checkbox" checked={showAll} onChange={(e) => setShowAll(e.target.checked)} />
          Include ended sessions
        </label>
      </div>
      {error && <p className="error">{error}</p>}
      {info && <p className="info">{info}</p>}

      <table className="data-table">
        <thead>
          <tr>
            <th>Username</th>
            <th>Login time</th>
            <th>IP</th>
            <th>Status</th>
            {showAll && <th>Score</th>}
            {showAll && <th>Verdict</th>}
            <th></th>
          </tr>
        </thead>
        <tbody>
          {sessions.map((s) => (
            <tr key={s.session_id}>
              <td>
                {s.username}
                {s.simulated && <span className="badge" style={{ marginLeft: 6 }}>Simulated</span>}
              </td>
              <td>{parseUtc(s.login_time).toLocaleString()}</td>
              <td>{s.access_location || "unknown"}</td>
              <td>{statusLabel(s)}</td>
              {showAll && (
                <td>
                  {s.anomaly_score !== null && s.anomaly_score !== undefined
                    ? `${s.anomaly_score.toFixed(3)}${s.is_anomaly ? " ⚠️" : ""}`
                    : "—"}
                </td>
              )}
              {showAll && (
                <td>{s.review_verdict ? VERDICT_LABELS[s.review_verdict] || s.review_verdict : "—"}</td>
              )}
              <td>
                {s.is_active && canWrite && (
                  <button
                    className="danger-btn"
                    onClick={() => handleTerminate(s.session_id)}
                    disabled={busyId === s.session_id}
                  >
                    {busyId === s.session_id ? "Terminating…" : "Terminate"}
                  </button>
                )}
                {s.alert_id && (
                  <Link to={`/alerts/${s.alert_id}`} style={{ marginLeft: 8 }}>Review</Link>
                )}
                {s.alert_id && canWrite && s.is_anomaly === false && s.review_verdict !== "confirmed_threat" && (
                  <button
                    className="link-btn danger"
                    style={{ marginLeft: 8 }}
                    onClick={() => handleReportThreat(s)}
                    disabled={busyId === s.session_id}
                  >
                    Report as threat
                  </button>
                )}
                {!s.is_active && !s.alert_id && <span className="muted">—</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {sessions.length === 0 && !error && (
        <p>{showAll ? "No sessions yet." : "No active sessions right now."}</p>
      )}
    </div>
  );
}