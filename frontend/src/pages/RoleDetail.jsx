import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import client from "../api/client";
import { usePermissions } from "../context/PermissionsContext";
import ViewOnlyNotice from "../components/ViewOnlyNotice";

const RESOURCES = ["dashboard", "role", "user"];

export default function RoleDetail() {
  const { roleId } = useParams();
  const { can } = usePermissions();
  const [role, setRole] = useState(null);
  const [error, setError] = useState("");
  const [newPerm, setNewPerm] = useState({ resource_name: RESOURCES[0], action_type: "read" });

  function load() {
    client
      .get(`/api/roles/${roleId}`)
      .then((res) => setRole(res.data))
      .catch((err) => setError(err.response?.data?.detail || "Failed to load role"));
  }

  useEffect(load, [roleId]);

  async function handleGrant(e) {
    e.preventDefault();
    setError("");
    try {
      await client.post(`/api/roles/${roleId}/permissions`, null, {
        params: { resource_name: newPerm.resource_name, action_type: newPerm.action_type },
      });
      setNewPerm({ resource_name: RESOURCES[0], action_type: "read" });
      load();
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to grant permission");
    }
  }

  async function handleRevoke(permissionId) {
    setError("");
    try {
      await client.delete(`/api/roles/${roleId}/permissions/${permissionId}`);
      load();
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to revoke permission");
    }
  }

  if (error && !role) return <p className="error">{error}</p>;
  if (!role) return <p>Loading…</p>;

  const canWrite = can && can("role", "write");

  return (
    <div>
      <Link to="/roles">&larr; Back to roles</Link>
      <h2>{role.role_name}</h2>
      <p className="muted">{role.description}</p>

      {error && <p className="error">{error}</p>}
      <ViewOnlyNotice resource="role" label="this role's permissions" />

      <h3>Permissions</h3>
      <table className="data-table">
        <thead>
          <tr>
            <th>Resource</th>
            <th>Action</th>
            {canWrite && <th></th>}
          </tr>
        </thead>
        <tbody>
          {role.permissions.map((p) => (
            <tr key={p.permission_id}>
              <td>{p.resource_name}</td>
              <td>{p.action_type}</td>
              {canWrite && (
                <td>
                  <button className="link-btn" onClick={() => handleRevoke(p.permission_id)}>
                    Revoke
                  </button>
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
      {role.permissions.length === 0 && (
        <p className="muted">No permissions granted — this role has no administrative access.</p>
      )}

      {canWrite && (
        <div className="panel">
          <h3>Grant permission</h3>
          <form className="inline-form" onSubmit={handleGrant}>
            <select
              value={newPerm.resource_name}
              onChange={(e) => setNewPerm({ ...newPerm, resource_name: e.target.value })}
            >
              {RESOURCES.map((r) => (
                <option key={r} value={r}>{r}</option>
              ))}
            </select>
            <select
              value={newPerm.action_type}
              onChange={(e) => setNewPerm({ ...newPerm, action_type: e.target.value })}
            >
              <option value="read">read</option>
              <option value="write">write</option>
              <option value="delete">delete</option>
            </select>
            <button type="submit">Grant</button>
          </form>
        </div>
      )}
    </div>
  );
}