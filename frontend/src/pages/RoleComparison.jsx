import { useEffect, useState } from "react";
import client from "../api/client";

export default function RoleComparison() {
  const [roles, setRoles] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function load() {
      try {
        const listRes = await client.get("/api/roles/");
        const details = await Promise.all(
          listRes.data.map((r) => client.get(`/api/roles/${r.role_id}`).then((res) => res.data))
        );
        setRoles(details);
      } catch (err) {
        setError(err.response?.data?.detail || "Failed to load roles");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  if (loading) return <p>Loading…</p>;
  if (error) return <p className="error">{error}</p>;

  // Build the full set of resource:action pairs across all roles
  const permissionKeys = new Set();
  roles.forEach((role) =>
    role.permissions.forEach((p) => permissionKeys.add(`${p.resource_name}:${p.action_type}`))
  );
  const sortedKeys = [...permissionKeys].sort();

  function hasPermission(role, key) {
    return role.permissions.some((p) => `${p.resource_name}:${p.action_type}` === key);
  }

  return (
    <div>
      <h2>Role Comparison</h2>
      <p className="muted">
        A live view of the principle of least privilege: exactly which actions each role can perform.
      </p>

      <table className="data-table matrix-table">
        <thead>
          <tr>
            <th>Permission</th>
            {roles.map((role) => (
              <th key={role.role_id}>{role.role_name}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sortedKeys.map((key) => (
            <tr key={key}>
              <td>{key}</td>
              {roles.map((role) => (
                <td key={role.role_id} className="matrix-cell">
                  {hasPermission(role, key) ? (
                    <span className="matrix-yes">✓</span>
                  ) : (
                    <span className="matrix-no">—</span>
                  )}
                </td>
              ))}
            </tr>
          ))}
          {sortedKeys.length === 0 && (
            <tr>
              <td colSpan={roles.length + 1} className="muted">
                No permissions have been granted to any role yet.
              </td>
            </tr>
          )}
        </tbody>
      </table>

      <div className="panel">
        <h3>What each role can do</h3>
        {roles.map((role) => (
          <div key={role.role_id} className="role-summary-card">
            <strong>{role.role_name}</strong>
            <p className="muted">{role.description}</p>
            {role.permissions.length === 0 ? (
              <p className="matrix-no">No administrative access — cannot reach the dashboard, roles, or users pages.</p>
            ) : (
              <ul>
                {role.permissions.map((p) => (
                  <li key={p.permission_id}>
                    {p.action_type} on {p.resource_name}
                  </li>
                ))}
              </ul>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}