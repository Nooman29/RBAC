import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import client from "../api/client";

export default function SimulateAttack() {
  const [users, setUsers] = useState([]);
  const [scenarios, setScenarios] = useState([]);
  const [selectedUser, setSelectedUser] = useState("");
  const [selectedScenario, setSelectedScenario] = useState("");
  const [demoMode, setDemoMode] = useState("isolated");
  const [running, setRunning] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [result, setResult] = useState(null);
  const [resetMessage, setResetMessage] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    client.get("/api/users/").then((res) => setUsers(res.data)).catch(() => {});
    client
      .get("/api/dashboard/simulate-attack/scenarios")
      .then((res) => setScenarios(res.data))
      .catch((err) => setError(err.response?.data?.detail || "Failed to load scenarios"));
  }, []);
  const [fullResetting, setFullResetting] = useState(false);

  async function handleFullReset() {
    if (!selectedUser) return;
    const confirmed = window.confirm(
      "This wipes ALL session history for this user — real and simulated. Use only on demo/test accounts. Continue?"
    );
    if (!confirmed) return;
    setError("");
    setFullResetting(true);
    try {
      const res = await client.delete(`/api/dashboard/simulate-attack/full-reset/${selectedUser}`);
      setResult(null);
      setResetMessage(`Full reset: wiped ${res.data.deleted_sessions} session(s) entirely for this user.`);
    } catch (err) {
      setError(err.response?.data?.detail || "Full reset failed");
    } finally {
      setFullResetting(false);
    }
  }

  async function handleRun() {
    if (!selectedUser || !selectedScenario) return;
    setError("");
    setResult(null);
    setResetMessage("");
    setRunning(true);
    try {
      const res = await client.post("/api/dashboard/simulate-attack", {
        user_id: Number(selectedUser),
        scenario: selectedScenario,
        demo_mode: demoMode,
      });
      setResult(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || "Simulation failed");
    } finally {
      setRunning(false);
    }
  }

  async function handleReset() {
    if (!selectedUser) return;
    setError("");
    setResetting(true);
    try {
      const res = await client.delete(`/api/dashboard/simulate-attack/reset/${selectedUser}`);
      setResult(null);
      setResetMessage(
        res.data.deleted_sessions > 0
          ? `Cleared ${res.data.deleted_sessions} simulated session(s) and their alerts. This user's baseline is back to their real history only.`
          : "No simulated sessions found for this user — nothing to clear."
      );
    } catch (err) {
      setError(err.response?.data?.detail || "Reset failed");
    } finally {
      setResetting(false);
    }
  }

  const showDriftNudge =
    result && !result.injected && demoMode === "naive" && result.is_anomaly === false;

  return (
    <div>
      <h2>Simulate an Attack</h2>
      <p className="muted">
        Simulates realistic suspicious behavior — login timing, resources accessed, and actions taken —
        then scores it through the live anomaly detection model, exactly like a real session. Nothing
        here is faked; the score and alert you see are genuine model output.
      </p>

      {error && <p className="error">{error}</p>}
      {resetMessage && <p className="info">{resetMessage}</p>}

      <div className="panel">
        <h3>Baseline Mode</h3>
        <p className="muted">
          Controls whether repeated simulations count toward this user's "normal" behavior baseline.
        </p>
        <label className="mode-option">
          <input
            type="radio"
            name="demoMode"
            value="isolated"
            checked={demoMode === "isolated"}
            onChange={() => setDemoMode("isolated")}
          />
          <strong>Isolated (production behavior)</strong>
          <p className="muted">
            Simulated sessions never affect the user's baseline. Running the same scenario repeatedly
            produces a consistent result every time.
          </p>
        </label>
        <label className="mode-option">
          <input
            type="radio"
            name="demoMode"
            value="naive"
            checked={demoMode === "naive"}
            onChange={() => setDemoMode("naive")}
          />
          <strong>Naive (demonstration only)</strong>
          <p className="muted">
            Simulated sessions ARE folded into the baseline. Run the same scenario on the same user
            twice in a row and watch the second attempt score lower — the model starts treating the
            repeated behavior as normal for that user.
          </p>
        </label>
      </div>

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

        <div className="reset-row">
          <button
            onClick={handleFullReset}
            disabled={!selectedUser || fullResetting}
            className="danger reset-btn"
          >
            {fullResetting ? "Wiping…" : "Full reset (wipe ALL history)"}
          </button>
          <button
            onClick={handleReset}
            disabled={!selectedUser || resetting}
            className="secondary reset-btn"
          >
            {resetting ? "Clearing…" : "Clear simulated history for this user"}
          </button>
          <span className="muted reset-hint">
            Removes all past simulated sessions for the selected user, restoring their baseline to
            real activity only. Do this before switching from Naive back to Isolated mode.
          </span>
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
            Scenario: <strong>{result.scenario_label}</strong> ({result.demo_mode} mode)
          </p>
          <p>
            User: <strong>{result.username}</strong> — Session #{result.session_id}
          </p>
          {result.anomaly_score !== null && (
            <p>Anomaly score: <strong>{result.anomaly_score.toFixed(4)}</strong></p>
          )}

          {result.is_anomaly && (
            <p>
              Detection method:{" "}
              <strong>
                {result.detection_reason === "repeat_pattern_override"
                  ? "Repeated suspicious pattern (rule-based override)"
                  : "Statistical anomaly (ML model)"}
              </strong>
            </p>
          )} 
            
          {result.alert_id && (
            <Link to={`/alerts/${result.alert_id}`}>View full alert & SHAP explanation &rarr;</Link>
          )}

          {showDriftNudge && (
            <div className="drift-nudge">
              <strong>This is the baseline drift in action.</strong>
              <p>
                In Naive mode, this repeated attack got folded into the user's "normal" baseline from
                an earlier run, so the model no longer sees it as unusual. Click "Clear simulated
                history" above, then switch to Isolated mode and run it again — it will flag
                consistently because simulated sessions never touch the baseline in that mode.
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}