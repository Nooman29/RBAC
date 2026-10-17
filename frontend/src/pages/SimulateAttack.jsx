import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import client from "../api/client";
import { usePermissions } from "../context/PermissionsContext";
import { describeDetection, describeSignature } from "../utils/detection";

export default function SimulateAttack() {
  const { can, loaded } = usePermissions();
  const [users, setUsers] = useState([]);
  const [scenarios, setScenarios] = useState([]);
  const [selectedUser, setSelectedUser] = useState("");
  const [selectedScenario, setSelectedScenario] = useState("");
  const [running, setRunning] = useState(false);
  const [resetting, setResetting] = useState(false);
  const [fullResetting, setFullResetting] = useState(false);
  const [marking, setMarking] = useState(false);
  const [marked, setMarked] = useState(false);
  const [result, setResult] = useState(null);
  const [resetMessage, setResetMessage] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (!loaded || !(can && can("dashboard", "write"))) return;
    client.get("/api/users/").then((res) => setUsers(res.data)).catch(() => {});
    client
      .get("/api/dashboard/simulate-attack/scenarios")
      .then((res) => setScenarios(res.data))
      .catch((err) => setError(err.response?.data?.detail || "Failed to load scenarios"));
  }, [loaded]);

  async function handleRun() {
    if (!selectedUser || !selectedScenario) return;
    setError("");
    setResult(null);
    setMarked(false);
    setResetMessage("");
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

  async function handleMarkThreat() {
    if (!result?.alert_id) return;
    setError("");
    setMarking(true);
    try {
      await client.patch(`/api/dashboard/alerts/${result.alert_id}`, {
        review_verdict: "confirmed_threat",
        notes: "Reported as a real threat from the attack simulation page.",
      });
      setMarked(true);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to record the verdict");
    } finally {
      setMarking(false);
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
          ? `Cleared ${res.data.deleted_sessions} simulated session(s) and their alerts.`
          : "No simulated sessions found for this user — nothing to clear."
      );
    } catch (err) {
      setError(err.response?.data?.detail || "Reset failed");
    } finally {
      setResetting(false);
    }
  }

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

  if (loaded && !(can && can("dashboard", "write"))) {
    return (
      <div>
        <h2>Simulate an Attack</h2>
        <p className="muted">This feature requires dashboard write access, which your role does not have.</p>
      </div>
    );
  }

  const signatureText = result ? describeSignature(result.pattern_signature) : "";

  return (
    <div>
      <h2>Simulate an Attack</h2>
      <p className="muted">
        Simulates realistic suspicious behavior — login timing, resources accessed, and actions taken —
        then scores it through the live anomaly detection model, exactly like a real session. Nothing
        here is faked; the score and alert you see are genuine model output.
      </p>

      <div className="panel">
        <h3>How the feedback loop works</h3>
        <ol>
          <li>Run a scenario for a user. The detector scores it.</li>
          <li>
            If it is <strong>not flagged</strong> but it was really an attack, mark it as a threat.
            The system remembers the pattern and keeps that session out of the user's normal history.
          </li>
          <li>Run the same scenario again: it is now flagged, because it matches a confirmed threat.</li>
        </ol>
        <p className="muted">
          Simulated sessions never count toward a user's baseline. If you later decide the behavior was
          fine, set the verdict to False Positive on the alert and it stops being flagged.
        </p>
      </div>

      {error && <p className="error">{error}</p>}
      {resetMessage && <p className="info">{resetMessage}</p>}

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
          <button onClick={handleReset} disabled={!selectedUser || resetting} className="secondary reset-btn">
            {resetting ? "Clearing…" : "Clear simulated history"}
          </button>
          <button onClick={handleFullReset} disabled={!selectedUser || fullResetting} className="danger reset-btn">
            {fullResetting ? "Wiping…" : "Full reset (wipe ALL history)"}
          </button>
          <span className="muted reset-hint">
            "Clear simulated" removes only test sessions and their verdicts. "Full reset" wipes everything for this user, including real history.
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
          <p>Scenario: <strong>{result.scenario_label}</strong></p>
          <p>User: <strong>{result.username}</strong> — Session #{result.session_id}</p>
          {result.anomaly_score !== null && result.anomaly_score !== undefined && (
            <p>Anomaly score: <strong>{result.anomaly_score.toFixed(4)}</strong></p>
          )}
          {result.is_anomaly && (
            <p>
              Detection method: <strong>{describeDetection(result.detection_reason)}</strong>
            </p>
          )}
          {signatureText && <p className="muted">Behavior recorded: {signatureText}.</p>}
          {result.alert_id && (
            <Link to={`/alerts/${result.alert_id}`}>View full alert & SHAP explanation &rarr;</Link>
          )}

          {!result.is_anomaly && result.alert_id && (
            <div className="drift-nudge">
              <strong>Was this actually an attack?</strong>
              <p>
                The detector let this session through. If it was malicious, report it: the system will
                remember this pattern and flag it the next time this user does it.
              </p>
              {marked ? (
                <p className="info">
                  Recorded as a confirmed threat. Run the same scenario again for this user — it will now be flagged.
                </p>
              ) : (
                <button onClick={handleMarkThreat} disabled={marking}>
                  {marking ? "Recording…" : "Mark as a real threat"}
                </button>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}