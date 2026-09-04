import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import client from "../api/client";
import { parseUtc } from "../utils/date";
import { usePermissions } from "../context/PermissionsContext";

export default function NeedsReviewPanel() {
  const { can, loaded } = usePermissions();
  const [alerts, setAlerts] = useState(null);

  useEffect(() => {
    if (!loaded || !can || !can("dashboard", "read")) return;
    client
      .get("/api/dashboard/alerts", { params: { only_anomalous: true, include_reviewed: false } })
      .then((res) => setAlerts(res.data))
      .catch(() => setAlerts(null));
  }, [loaded]);

  if (!loaded || !can || !can("dashboard", "read")) return null;
  if (alerts === null) return null;

  const overdue = alerts.filter((a) => a.is_overdue);
  const rest = alerts.filter((a) => !a.is_overdue);
  const ordered = [...overdue, ...rest].slice(0, 6);

  return (
    <div className="panel needs-review-panel">
      <h3>Needs Your Review</h3>
      {alerts.length === 0 ? (
        <p className="muted">All caught up — no unreviewed anomalies.</p>
      ) : (
        <>
          <p className="muted">
            {alerts.length} unreviewed alert{alerts.length === 1 ? "" : "s"}
            {overdue.length > 0 && `, ${overdue.length} overdue`}
          </p>
          <ul className="needs-review-list">
            {ordered.map((a) => (
              <li key={a.alert_id} className={a.is_overdue ? "review-overdue" : ""}>
                <Link to={`/alerts/${a.alert_id}`}>
                  {a.is_overdue && "⚠️ "}
                  Alert #{a.alert_id} — {a.username} — score {a.anomaly_score.toFixed(3)}
                </Link>{" "}
                <span className="muted">({parseUtc(a.alert_timestamp).toLocaleString()})</span>
              </li>
            ))}
          </ul>
          {alerts.length > 6 && <Link to="/alerts">View all unreviewed alerts →</Link>}
        </>
      )}
    </div>
  );
}