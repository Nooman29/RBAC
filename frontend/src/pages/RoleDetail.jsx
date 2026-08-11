import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import client from "../api/client";

export default function RoleDetail() {
  const { roleId } = useParams();
  const [role, setRole] = useState(null);
  const [allPermissions, setAllPermissions] = useState([]);
  const [error, setError] = useState("");
  const [newPerm, setNewPerm] = useState({ resource_name: "", action_type: "read" });

  function load() {
    client
      .get(`/api/roles/${roleId}`)
      .then((res) => setRole(res.data))
      .catch((err) => setError(err.response?.data?.detail || "Failed to load role"));
    client.get("/api/roles/permissions").then((res) => setAllPermissions(res.data)).catch(() => {});
  }

  useEffect(load, [roleId]);

  async function handleGrant(e) {
    e.preventDefault();
    setError("");
    try {
      await client.post(`/api/roles/${roleId}/permissions`, null, {
        params: { resource_name: newPerm.resource_name, action_type: newPerm.action_type },
      });
      setNewPerm({ resource_name: "", action_type: "read" });
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

  const existingResources = [...new Set(allPermissions.map((p) => p.resource_name))];

  return (
    <div>
      <Link to="/roles">&larr; Back to roles</Link>
      <h2>{role.role_name}</h2>
      <p className="muted">{role.description}</p>

      {error && <p className="error">{error}</p>}

      <h3>Permissions</h3>
      <table className="data-table">
        <thead>
          <tr>
            <th>Resource</th>
            <th>Action</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {role.permissions.map((p) => (
            <tr key={p.permission_id}>
              <td>{p.resource_name}</td>
              <td>{p.action_type}</td>
              <td>
                <button className="link-btn" onClick={() => handleRevoke(p.permission_id)}>
                  Revoke
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {role.permissions.length === 0 && (
        <p className="muted">No permissions granted — this role has no administrative access.</p>
      )}

      <div className="panel">
        <h3>Grant permission</h3>
        <form className="inline-form" onSubmit={handleGrant}>
          <input
            list="known-resources"
            placeholder="Resource (e.g. dashboard)"
            value={newPerm.resource_name}
            onChange={(e) => setNewPerm({ ...newPerm, resource_name: e.target.value })}
            required
          />
          <datalist id="known-resources">
            {existingResources.map((r) => (
              <option key={r} value={r} />
            ))}
          </datalist>
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
    </div>
  );
}