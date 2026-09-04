import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import client from "../api/client";
import { parseUtc } from "../utils/date";
import { usePermissions } from "../context/PermissionsContext";

export default function NeedsReviewPanel() {
  const { can, loaded } = usePermissions();
  const [alerts, setAlerts] = useState(null);

  useEffect(() => {
    if (!loaded || !can || !can("dashboard", "write")) return;
    client
      .get("/api/dashboard/alerts", { params: { only_anomalous: true, include_reviewed: false } })
      .then((res) => setAlerts(res.data))
      .catch(() => setAlerts(null));
  }, [loaded]);

  if (!loaded || !can || !can("dashboard", "write")) return null;
  if (alerts === null) return null;

  const overdue = alerts.filter((a) => a.is_overdue);
  const rest = alerts.filter((a) => !a.is_overdue);
  const ordered = [...overdue, ...rest].slice(0, 6);

  return (
    <div className="needs-review-card">
      <div className="needs-review-header">
        <h3>Needs Your Review</h3>
        {alerts.length > 0 && (
          <span className="needs-review-count">{alerts.length}</span>
        )}
      </div>

      {alerts.length === 0 ? (
        <p className="needs-review-empty">✓ All caught up — no unreviewed anomalies.</p>
      ) : (
        <>
          {overdue.length > 0 && (
            <p className="needs-review-subtext">{overdue.length} overdue for review</p>
          )}
          <div className="needs-review-items">
            {ordered.map((a) => (
              <Link key={a.alert_id} to={`/alerts/${a.alert_id}`} className={`needs-review-item ${a.is_overdue ? "overdue" : ""}`}>
                <div className="needs-review-item-main">
                  <span className="needs-review-alert-id">Alert #{a.alert_id}</span>
                  <span className="needs-review-user">{a.username}</span>
                  {a.is_overdue && <span className="needs-review-badge">Overdue</span>}
                </div>
                <div className="needs-review-item-sub">
                  <span>Score {a.anomaly_score.toFixed(3)}</span>
                  <span>{parseUtc(a.alert_timestamp).toLocaleString()}</span>
                </div>
              </Link>
            ))}
          </div>
          {alerts.length > 6 && (
            <Link to="/alerts" className="needs-review-viewall">View all {alerts.length} unreviewed alerts →</Link>
          )}
        </>
      )}
    </div>
  );
}