import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import client from "../api/client";

export default function SimulateAttack() {
  const [users, setUsers] = useState([]);
  const [scenarios, setScenarios] = useState([]);
  const [selectedUser, setSelectedUser] = useState("");
  const [selectedScenario, setSelectedScenario] = useState("");
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    client.get("/api/users/").then((res) => setUsers(res.data)).catch(() => {});
    client
      .get("/api/dashboard/simulate-attack/scenarios")
      .then((res) => setScenarios(res.data))
      .catch((err) => setError(err.response?.data?.detail || "Failed to load scenarios"));
  }, []);

  async function handleRun() {
    if (!selectedUser || !selectedScenario) return;
    setError("");
    setResult(null);
    setRunning(true);
    try {
      const res = await client.post("/api/dashboard/simulate-attack", {
        user_id: Number(selectedUser),
        scenario: selectedScenario,
      });
      setResult(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || "Simulation failed");
    } finally {
      setRunning(false);
    }
  }

  return (
    <div>
      <h2>Simulate an Attack</h2>
      <p className="muted">
        Creates a real session with behavior matching a known insider-threat pattern, then scores it
        through the live Isolation Forest model — the same pipeline used for every real login. Nothing
        here is faked; the score and alert are genuine model output.
      </p>

      {error && <p className="error">{error}</p>}

      <div className="panel">
        <div className="inline-form">
          <select value={selectedUser} onChange={(e) => setSelectedUser(e.target.value)}>
            <option value="">Select user…</option>
            {users.map((u) => (
              <option key={u.user_id} value={u.user_id}>
                {u.username} ({u.department})
              </option>
            ))}
          </select>
          <button onClick={handleRun} disabled={!selectedUser || !selectedScenario || running}>
            {running ? "Running…" : "Run Scenario"}
          </button>
        </div>
      </div>

      <div className="scenario-cards">
        {scenarios.map((s) => (
          <label
            key={s.key}
            className={`scenario-card ${selectedScenario === s.key ? "scenario-selected" : ""}`}
          >
            <input
              type="radio"
              name="scenario"
              value={s.key}
              checked={selectedScenario === s.key}
              onChange={(e) => setSelectedScenario(e.target.value)}
            />
            <strong>{s.label}</strong>
            <p className="muted">{s.description}</p>
          </label>
        ))}
      </div>

      {result && (
        <div className={`panel result-panel ${result.is_anomaly ? "result-flagged" : "result-clear"}`}>
          <h3>{result.is_anomaly ? "⚠️ Anomaly Detected" : "No Anomaly Flagged"}</h3>
          <p>
            Scenario: <strong>{result.scenario_label}</strong>
          </p>
          <p>
            User: <strong>{result.username}</strong> — Session #{result.session_id}
          </p>
          {result.anomaly_score !== null && (
            <p>Anomaly score: <strong>{result.anomaly_score.toFixed(4)}</strong></p>
          )}
          {result.alert_id && (
            <Link to={`/alerts/${result.alert_id}`}>View full alert & SHAP explanation &rarr;</Link>
          )}
        </div>
      )}
    </div>
  );
}