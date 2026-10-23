import { useEffect, useState } from "react";
import client from "../api/client";

const ACTIONS = ["read", "write", "approve", "export"];

const RESOURCE_LABELS = {
  dashboard: "Security dashboard (sessions, alerts, audit log)",
  user: "User accounts",
  role: "Roles and permissions",
  service_client: "Integration clients",
  beneficiary: "Student Beneficiary Management",
  attendance: "Meal Attendance & Tracking",
  payment: "School Feeding Payments",
  supply: "Supply Chain Management",
  logistics: "Logistics Tracking",
  analytics: "Analytics Dashboard",
  fraud: "Fraud Detection",
  sync: "Offline Data Sync",
  sms: "SMS Notifications",
};

// Resources managed inside this console; everything else lives in the DSFS module apps.
const CONSOLE_RESOURCES = new Set(["dashboard", "user", "role", "service_client"]);

const TIER_TEXT = {
  high: "High-privilege: your sessions are checked against a stricter anomaly threshold.",
  standard: "Standard: your sessions are checked against the default anomaly threshold.",
  low: "Low-risk: read-only access to your own records, so a slightly looser threshold applies.",
};

function AccessTable({ rows }) {
  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Area</th>
          {ACTIONS.map((a) => (
            <th key={a} style={{ textTransform: "capitalize", textAlign: "center" }}>{a}</th>
          ))}
        </tr>
      </thead>
      <tbody>
        {rows.map((r) => (
          <tr key={r.resource_name}>
            <td>
              {RESOURCE_LABELS[r.resource_name] || r.resource_name}
              <span className="shap-key" style={{ marginLeft: 8 }}>{r.resource_name}</span>
            </td>
            {ACTIONS.map((a) => (
              <td key={a} style={{ textAlign: "center" }}>{r.actions.includes(a) ? "✓" : "—"}</td>
            ))}
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export default function MyAccess() {
  const [data, setData] = useState(null);
  const [error, setError] = useState("");

  useEffect(() => {
    client
      .get("/api/auth/my-access")
      .then((res) => setData(res.data))
      .catch((err) => setError(err.response?.data?.detail || "Failed to load your access"));
  }, []);

  if (error) return <p className="error">{error}</p>;
  if (!data) return <p>Loading…</p>;

  const consoleRows = data.resources.filter((r) => CONSOLE_RESOURCES.has(r.resource_name));
  const moduleRows = data.resources.filter((r) => !CONSOLE_RESOURCES.has(r.resource_name));
  const where =
    data.scope === "school" ? data.school_id :
    data.scope === "organization" ? data.organization_id :
    data.scope === "department" ? data.department : null;

  return (
    <div>
      <h2>My Access</h2>
      <p className="muted">
        What your account is allowed to do across the Digital School Feeding System. These rules are
        enforced by this RBAC service every time you, or a module app acting for you, requests data.
      </p>

      <div className="detail-grid">
        <div><strong>User:</strong> {data.username}</div>
        <div><strong>Role(s):</strong> {data.role_names.join(", ") || "no role"}</div>
        <div>
          <strong>Data scope:</strong> {data.scope_label}
          {where ? ` (${where})` : ""}
        </div>
        <div><strong>Risk tier:</strong> {TIER_TEXT[data.risk_tier] || data.risk_tier}</div>
      </div>

      {(data.scope === "school" && !data.school_id) || (data.scope === "organization" && !data.organization_id) ? (
        <p className="error">
          Your role is scoped to a {data.scope === "school" ? "school" : "organisation"}, but none is set on your
          account, so you can only see your own records. Ask an administrator to assign one.
        </p>
      ) : null}

      <h3>DSFS modules</h3>
      {moduleRows.length > 0 ? (
        <>
          <p className="muted">You use these in the module apps (attendance, payments, supply chain and so on).</p>
          <AccessTable rows={moduleRows} />
        </>
      ) : (
        <p className="muted">Your role has no module permissions.</p>
      )}

      <h3>This console</h3>
      {consoleRows.length > 0 ? (
        <AccessTable rows={consoleRows} />
      ) : (
        <p className="muted">
          Your role does not include the security dashboard or user administration, so this console only shows
          your access and your Face ID setup.
        </p>
      )}
    </div>
  );
}
