import { useEffect, useState } from "react";
import client from "../api/client";
import { parseUtc } from "../utils/date";

export default function Sessions() {
  const [sessions, setSessions] = useState([]);
  const [error, setError] = useState("");
  const [busyId, setBusyId] = useState(null);

  function load() {
    client
      .get("/api/dashboard/sessions", { params: { active_only: true } })
      .then((res) => setSessions(res.data))
      .catch((err) => setError(err.response?.data?.detail || "Failed to load sessions"));
  }

  useEffect(load, []);

  async function handleTerminate(sessionId) {
    if (!window.confirm("Terminate this session? The user will be logged out immediately.")) return;
    setBusyId(sessionId);
    setError("");
    try {
      await client.post(`/api/dashboard/sessions/${sessionId}/terminate`);
      load();
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to terminate session");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div>
      <h2>Active Sessions</h2>
      <p className="muted">
        Users currently logged in. Terminating a session logs the user out immediately and scores it for anomalies.
      </p>
      <button className="secondary-btn" onClick={load}>Refresh</button>
      {error && <p className="error">{error}</p>}

      <table className="data-table">
        <thead>
          <tr>
            <th>Username</th>
            <th>Login time</th>
            <th>IP</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {sessions.map((s) => (
            <tr key={s.session_id}>
              <td>{s.username}</td>
              <td>{parseUtc(s.login_time).toLocaleString()}</td>
              <td>{s.access_location || "unknown"}</td>
              <td>
                <button
                  className="danger-btn"
                  onClick={() => handleTerminate(s.session_id)}
                  disabled={busyId === s.session_id}
                >
                  {busyId === s.session_id ? "Terminating…" : "Terminate"}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {sessions.length === 0 && !error && <p>No active sessions right now.</p>}
    </div>
  );
}