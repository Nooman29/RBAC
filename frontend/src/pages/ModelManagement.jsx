import { useEffect, useState } from "react";
import client from "../api/client";
import { usePermissions } from "../context/PermissionsContext";

const STATUS_BADGE = {
  live: { cls: "badge-online", label: "Live" },
  previous: { cls: "badge-neutral", label: "Previous" },
  candidate: { cls: "badge-neutral", label: "Passed, not live" },
  rejected: { cls: "badge-danger", label: "Rejected" },
};

const DRIFT_TEXT = {
  stable: "Stable: recent sessions look like the training data.",
  drifting: "Drifting: recent behaviour no longer matches the training data.",
  insufficient_data: "Not enough sessions scored since this model went live to judge drift yet.",
  no_model: "No model is live yet.",
};

const CHECK_LABELS = {
  enough_data: "Enough training data",
  scores_vary: "Model separates sessions",
  recent_false_alarms: "False alarms on recent normal sessions",
  known_attacks: "Still catches known attacks",
  imported: "Imported",
};

const pct = (v) => (v == null ? "—" : `${(v * 100).toFixed(1)}%`);
const when = (ts) => (ts ? new Date(ts).toLocaleString() : "—");

function Checks({ checks }) {
  return (
    <ul style={{ margin: 0, paddingLeft: 18 }}>
      {checks.map((c) => (
        <li key={c.name}>
          <strong>{c.skipped ? "Skipped" : c.passed ? "Pass" : "Fail"}</strong>{" "}
          {CHECK_LABELS[c.name] || c.name}: <span className="muted">{c.detail}</span>
        </li>
      ))}
    </ul>
  );
}

export default function ModelManagement() {
  const { can } = usePermissions();
  const [data, setData] = useState(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [openVersion, setOpenVersion] = useState(null);

  function load() {
    client
      .get("/api/model/status")
      .then((res) => setData(res.data))
      .catch((err) => setError(err.response?.data?.detail || "Failed to load model status"));
  }

  useEffect(load, []);

  async function retrain() {
    setBusy(true);
    setError("");
    setMessage("");
    try {
      const res = await client.post("/api/model/retrain");
      setMessage(
        res.data.status === "live"
          ? `Version ${res.data.version_id} passed every check and is now live.`
          : `Version ${res.data.version_id} failed a check and was NOT put live. The current model is unchanged.`
      );
      setOpenVersion(res.data.version_id);
      load();
    } catch (err) {
      setError(err.response?.data?.detail || "Retraining failed");
    } finally {
      setBusy(false);
    }
  }

  async function promote(versionId) {
    if (!window.confirm(`Put version ${versionId} live? The current model will be replaced immediately.`)) return;
    setBusy(true);
    setError("");
    setMessage("");
    try {
      await client.post(`/api/model/versions/${versionId}/promote`);
      setMessage(`Version ${versionId} is now live.`);
      load();
    } catch (err) {
      setError(err.response?.data?.detail || "Promotion failed");
    } finally {
      setBusy(false);
    }
  }

  if (error && !data) return <p className="error">{error}</p>;
  if (!data) return <p>Loading…</p>;

  const canManage = can && can("dashboard", "write");
  const cur = data.current;
  const m = cur?.metrics || {};
  const drift = data.drift || {};

  return (
    <div>
      <h2>Detection Model</h2>
      <p className="muted">
        Every training run is kept as a version. A new version only goes live if it passes its checks, and any
        earlier version can be put back live (rollback). Drift compares the sessions scored since the live model
        went live with the sessions it was trained on.
      </p>

      <div className="card-grid">
        <div className="stat-card">
          <span className="stat-value" style={{ fontSize: 18 }}>{cur ? cur.version_id : "none"}</span>
          <span className="stat-label">Live version</span>
        </div>
        <div className="stat-card">
          <span className="stat-value">{m.n_sessions ?? "—"}</span>
          <span className="stat-label">Training sessions</span>
        </div>
        <div className="stat-card">
          <span className="stat-value">{m.threshold != null ? m.threshold.toFixed(4) : "—"}</span>
          <span className="stat-label">Standard threshold (p95)</span>
        </div>
        <div className={`stat-card${drift.status === "drifting" ? " highlight" : ""}`}>
          <span className="stat-value" style={{ fontSize: 18, textTransform: "capitalize" }}>
            {(drift.status || "—").replace("_", " ")}
          </span>
          <span className="stat-label">Drift</span>
        </div>
      </div>

      <div className={drift.retrain_recommended ? "drift-nudge" : ""} style={{ marginTop: 16 }}>
        <strong>{DRIFT_TEXT[drift.status] || ""}</strong>
        {drift.n_recent != null && (
          <p className="muted">
            {drift.n_recent} session(s) scored since {cur ? when(cur.promoted_at) : "—"}. Flagged by the model:{" "}
            {pct(drift.recent_flag_rate)} (about {pct(drift.expected_flag_rate)} expected). Average score shift:{" "}
            {drift.mean_shift != null ? `${drift.mean_shift > 0 ? "+" : ""}${drift.mean_shift} sd` : "—"}. Model age:{" "}
            {drift.age_days ?? "—"} days.
          </p>
        )}
        {drift.reasons?.length > 0 && (
          <ul>{drift.reasons.map((r) => <li key={r}>{r}</li>)}</ul>
        )}
        {drift.retrain_recommended && (
          <p><strong>Retraining recommended:</strong> {drift.recommend_reasons.join("; ")}.</p>
        )}
      </div>

      <p className="muted" style={{ marginTop: 12 }}>
        Schedule:{" "}
        {data.schedule.auto_retrain
          ? `automatic retraining every ${data.schedule.interval_days} days (checked every ${data.schedule.check_hours} h). A scheduled version still has to pass the checks before it goes live.`
          : "automatic retraining is off; retrain by hand."}{" "}
        Drift on its own never retrains automatically, because drifting behaviour could be an attack.
      </p>

      {error && <p className="error">{error}</p>}
      {message && <p className="info">{message}</p>}
      {canManage && (
        <button className="ds-btn ds-btn-primary" onClick={retrain} disabled={busy || data.retrain_in_progress}>
          {busy || data.retrain_in_progress ? "Working…" : "Retrain now"}
        </button>
      )}

      <h3 style={{ marginTop: 24 }}>Versions</h3>
      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th>Version</th>
              <th>Status</th>
              <th>Trained</th>
              <th>By</th>
              <th>Sessions</th>
              <th>Recent false alarms</th>
              <th>Known attacks caught</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {data.versions.map((v) => {
              const badge = STATUS_BADGE[v.status] || { cls: "badge-neutral", label: v.status };
              const vm = v.metrics || {};
              const open = openVersion === v.version_id;
              return [
                <tr key={v.version_id}>
                  <td>
                    <button className="ds-btn ds-btn-sm" onClick={() => setOpenVersion(open ? null : v.version_id)}>
                      {open ? "▾" : "▸"} {v.version_id}
                    </button>
                  </td>
                  <td><span className={`badge ${badge.cls}`}>{badge.label}</span></td>
                  <td>{when(v.created_at)}</td>
                  <td>{v.triggered_by}</td>
                  <td>{vm.n_sessions ?? "—"}</td>
                  <td>{pct(vm.holdout_flag_rate)}</td>
                  <td>{pct(vm.known_bad_caught_new)}</td>
                  <td>
                    {canManage && v.passed && v.status !== "live" && (
                      <button className="ds-btn ds-btn-sm ds-btn-primary" onClick={() => promote(v.version_id)} disabled={busy}>
                        {v.status === "previous" ? "Roll back to this" : "Put live"}
                      </button>
                    )}
                  </td>
                </tr>,
                open && (
                  <tr key={`${v.version_id}-checks`}>
                    <td colSpan={8}>
                      <Checks checks={v.checks || []} />
                    </td>
                  </tr>
                ),
              ];
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}