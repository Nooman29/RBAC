import { useEffect, useState } from "react";
import { useParams, Link, useNavigate } from "react-router-dom";
import client from "../api/client";
import { parseUtc } from "../utils/date";
import { describeDetection, describeSignature, describeLiveRule, SEVERITY_BADGES } from "../utils/detection";
import { usePermissions } from "../context/PermissionsContext";
import ViewOnlyNotice from "../components/ViewOnlyNotice";

const FEATURE_META = {
  login_hour: { label: "Login hour (local time)", describe: (raw) => `Logged in at ${Math.round(raw)}:00 local time (Nairobi).` },
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

const TIER_LABELS = {
  high: "high-privilege tier, stricter",
  standard: "standard tier",
  low: "low-risk tier, looser",
};

const VERDICT_LABELS = {
  confirmed_threat: "Confirmed Threat",
  false_positive: "False Positive",
  authorized_exception: "Authorized Exception",
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
  const [verdict, setVerdict] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);
  const [justSaved, setJustSaved] = useState(false);
  const [savedMsg, setSavedMsg] = useState("");
  const [terminating, setTerminating] = useState(false);
  const [terminateMsg, setTerminateMsg] = useState("");
  const { can } = usePermissions();

  function load() {
    client
      .get(`/api/dashboard/alerts/${alertId}`)
      .then((res) => {
        setAlert(res.data);
        setNotes(res.data.notes || "");
        setVerdict(res.data.review_verdict || "");
      })
      .catch((err) => setError(err.response?.data?.detail || "Failed to load alert"));
  }

  useEffect(load, [alertId]);

  async function handleSaveVerdict() {
    if (!verdict) {
      setError("Select a verdict before saving.");
      return;
    }
    setSaving(true);
    setError("");
    setSavedMsg("");
    try {
      await client.patch(`/api/dashboard/alerts/${alertId}`, { review_verdict: verdict, notes });
      if (alert.is_anomaly) {
        setJustSaved(true);
        setTimeout(() => navigate("/alerts"), 700);
      } else {
        setSavedMsg(
          verdict === "confirmed_threat"
            ? "Saved. The system will remember this pattern and flag it next time this user does it."
            : "Saved."
        );
        setSaving(false);
        load();
      }
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to save");
      setSaving(false);
    }
  }

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
  if (!alert) return <p>Loading…</p>;

  const canReview = can && can("dashboard", "write");
  const patternText = describeSignature(alert.pattern_signature);
  const maxAbsShap = Math.max(1e-6, ...alert.shap_contributions.map((c) => Math.abs(c.shap_value)));
  const topForSummary = [...alert.shap_contributions]
    .filter((c) => c.shap_value > 0)
    .sort((a, b) => b.shap_value - a.shap_value)
    .slice(0, 3);

  return (
    <div>
      <Link to="/alerts" className="ds-btn ds-btn-sm ds-back">&larr; Back to alerts</Link>
      <h2>
        Alert #{alert.alert_id}
        {alert.is_overdue && <span className="badge badge-overdue" style={{ marginLeft: 10 }}>Overdue Review</span>}
      </h2>

      <div className="detail-grid">
        <div><strong>User:</strong> {alert.username} ({alert.role_names.join(", ") || "no role"})</div>
        <div><strong>Session:</strong> {alert.session_id}</div>
        <div><strong>Login time:</strong> {parseUtc(alert.login_time).toLocaleString()}</div>
        <div><strong>Duration:</strong> {alert.session_duration ? `${Math.round(alert.session_duration)}s` : "—"}</div>
        <div><strong>IP:</strong> {alert.access_location || "unknown"}</div>
        <div className={alert.is_anomaly ? "score-flagged" : "score-normal"}>
          <strong>Anomaly score:</strong> {alert.anomaly_score.toFixed(4)} {alert.is_anomaly ? "⚠️ Flagged" : ""}
        </div>
        <div>
          <strong>Threshold:</strong>{" "}
          {alert.threshold_used != null
            ? `${alert.threshold_used.toFixed(4)} (${TIER_LABELS[alert.risk_tier] || alert.risk_tier || "standard tier"})`
            : "not recorded (scored before per-role thresholds were added)"}
        </div>
        <div>
          <strong>Detection method:</strong>{" "}
          {alert.is_anomaly ? describeDetection(alert.detection_reason) : "Not flagged by the detector"}
        </div>
        {patternText && <div><strong>Behavior pattern:</strong> {patternText}</div>}
      </div>

      {alert.is_learning && (
        <div className="drift-nudge">
          <strong>Learning period</strong>
          <p>
            This user had only {alert.prior_sessions ?? 0} earlier session(s) when this one was scored, so their
            personal baseline was not ready yet. The "vs. usual" comparisons were neutral, and the score rests on
            the raw behaviour (time of day, location, activity volume) and on earlier verdicts.
          </p>
        </div>
      )}

      <div className="session-status">
        {alert.session_terminated ? (
          <span className="badge badge-danger">Terminated by an administrator</span>
        ) : alert.session_active ? (
          <span className="badge badge-online">Online — session still active</span>
        ) : (
          <span className="badge badge-neutral">Ended normally — user logged out</span>
        )}

        {alert.session_active && canReview && (
          <button className="ds-btn ds-btn-danger" onClick={handleTerminate} disabled={terminating} style={{ marginLeft: 12 }}>
            {terminating ? "Terminating…" : "Terminate Session"}
          </button>
        )}
      </div>
      {terminateMsg && <p className="info">{terminateMsg}</p>}

      {(alert.live_score || alert.live_alerts.length > 0) && (
        <>
          <h3>Live detection during this session</h3>
          <p className="muted">
            Early warnings raised while the session was still active. The anomaly score above, taken when
            the session ended, is the official verdict.
          </p>
          {alert.live_score && (
            <div className="detail-grid">
              <div className={alert.live_score.flagged ? "score-flagged" : "score-normal"}>
                <strong>Provisional model score:</strong> {alert.live_score.anomaly_score.toFixed(4)}
                {alert.live_score.flagged ? " ⚠️ Above threshold" : ""}
              </div>
              <div><strong>Highest provisional score:</strong> {alert.live_score.peak_score.toFixed(4)}</div>
              <div><strong>Final score (official):</strong> {alert.anomaly_score.toFixed(4)}</div>
              <div><strong>Threshold:</strong> {alert.live_score.threshold_used.toFixed(4)} ({TIER_LABELS[alert.live_score.risk_tier] || alert.live_score.risk_tier})</div>
              <div>
                <strong>Last scored:</strong> after {alert.live_score.n_events} action(s),{" "}
                {Math.round(alert.live_score.elapsed_sec / 60)} min into the session
              </div>
            </div>
          )}
          {alert.live_alerts.length > 0 && (
            <table className="data-table">
              <thead>
                <tr>
                  <th>Rule</th>
                  <th>Severity</th>
                  <th>What happened</th>
                  <th>Hits</th>
                  <th>First seen</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {alert.live_alerts.map((a) => (
                  <tr key={a.live_alert_id}>
                    <td>{describeLiveRule(a.rule)}</td>
                    <td><span className={SEVERITY_BADGES[a.severity] || "badge"}>{a.severity}</span></td>
                    <td>{a.summary}</td>
                    <td>{a.hit_count}</td>
                    <td>{parseUtc(a.first_seen_at).toLocaleString()}</td>
                    <td>{a.status}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}

      {alert.shap_contributions.length > 0 && (
        <>
          <h3>{alert.is_anomaly ? "Why this was flagged" : "How this session was scored"}</h3>
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
      <ViewOnlyNotice resource="dashboard" label="alert review" />
      {canReview ? (
        <>
          {!alert.is_anomaly && !alert.review_verdict && (
            <div className="drift-nudge">
              <strong>This session was not flagged.</strong>
              <p>
                If it was actually malicious, choose "Confirmed Threat". The system will remember this
                pattern and flag it the next time this user does it, and this session will stay out of
                their normal history.
              </p>
            </div>
          )}
          {alert.review_verdict && (
            <p className="info">Current verdict: <strong>{VERDICT_LABELS[alert.review_verdict]}</strong></p>
          )}
          <p className="muted">
            Your verdict teaches the detector. Confirming a threat keeps the session out of this user's
            baseline and makes the same behavior flag in future. Marking it a false positive or an
            authorized exception (e.g. an approved maintenance window) lets it count as legitimate
            history and stops the pattern from being flagged.
          </p>
          <div className="verdict-options">
            <label className={`verdict-option ${verdict === "confirmed_threat" ? "verdict-selected" : ""}`}>
              <input type="radio" name="verdict" value="confirmed_threat" checked={verdict === "confirmed_threat"} onChange={(e) => setVerdict(e.target.value)} />
              <strong>Confirmed Threat</strong>
              <p className="muted">
                {alert.is_anomaly
                  ? "This genuinely looks malicious or unauthorized. Stays excluded from this user's baseline and flags the pattern next time."
                  : "The detector missed this. The pattern is remembered and flagged next time; the session stays out of this user's baseline."}
              </p>
            </label>
            <label className={`verdict-option ${verdict === "false_positive" ? "verdict-selected" : ""}`}>
              <input type="radio" name="verdict" value="false_positive" checked={verdict === "false_positive"} onChange={(e) => setVerdict(e.target.value)} />
              <strong>False Positive</strong>
              <p className="muted">This was actually normal behavior for this user. Will count toward their baseline going forward.</p>
            </label>
            <label className={`verdict-option ${verdict === "authorized_exception" ? "verdict-selected" : ""}`}>
              <input type="radio" name="verdict" value="authorized_exception" checked={verdict === "authorized_exception"} onChange={(e) => setVerdict(e.target.value)} />
              <strong>Authorized Exception</strong>
              <p className="muted">Unusual, but approved (e.g. a scheduled maintenance window). Will count toward their baseline going forward.</p>
            </label>
          </div>
          <textarea
            rows={4}
            value={notes}
            onChange={(e) => setNotes(e.target.value)}
            placeholder="Notes on this alert…"
          />
          <div>
            <button className="ds-btn ds-btn-primary" onClick={handleSaveVerdict} disabled={saving || justSaved}>
              {justSaved ? "Saved ✓" : saving ? "Saving…" : "Save Verdict"}
            </button>
            {justSaved && <span className="info"> Updated — returning to alerts…</span>}
          </div>
          {savedMsg && <p className="info">{savedMsg}</p>}
        </>
      ) : (
        alert.review_verdict && (
          <p className="info">Verdict: <strong>{VERDICT_LABELS[alert.review_verdict]}</strong>{alert.notes ? ` — ${alert.notes}` : ""}</p>
        )
      )}
    </div>
  );
}