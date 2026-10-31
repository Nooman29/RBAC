import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import client from "../api/client";
import { usePermissions } from "../context/PermissionsContext";
import ViewOnlyNotice from "../components/ViewOnlyNotice";

// Why a role cannot be deleted (shown as the disabled button's tooltip), or null if it can.
function deleteBlockedReason(role) {
  if (role.is_builtin) return "Built-in role: it cannot be deleted.";
  if (role.user_count > 0) return `${role.user_count} user(s) still hold this role. Assign them another role first.`;
  return null;
}

export default function Roles() {
  const { can } = usePermissions();
  const [roles, setRoles] = useState([]);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [newRole, setNewRole] = useState({ role_name: "", description: "" });
  const [creating, setCreating] = useState(false);
  const [busyId, setBusyId] = useState(null);
  const canWrite = can && can("role", "write");

  function load() {
    client
      .get("/api/roles/")
      .then((res) => setRoles(res.data))
      .catch((err) => setError(err.response?.data?.detail || "Failed to load roles"));
  }

  useEffect(load, []);

  async function handleCreateRole(e) {
    e.preventDefault();
    setError("");
    setInfo("");
    setCreating(true);
    try {
      await client.post("/api/roles/", null, {
        params: { role_name: newRole.role_name, description: newRole.description },
      });
      setNewRole({ role_name: "", description: "" });
      load();
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to create role");
    } finally {
      setCreating(false);
    }
  }

  async function handleDeleteRole(role) {
    if (!window.confirm(`Delete the role '${role.role_name}'? This cannot be undone.`)) return;
    setError("");
    setInfo("");
    setBusyId(role.role_id);
    try {
      await client.delete(`/api/roles/${role.role_id}`);
      setInfo(`Role '${role.role_name}' deleted.`);
      load();
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to delete role");
    } finally {
      setBusyId(null);
    }
  }

  return (
    <div>
      <h2>Roles</h2>
      {error && <p className="error">{error}</p>}
      {info && <p className="info">{info}</p>}
      <ViewOnlyNotice resource="role" label="role management" />

      {canWrite && (
        <div className="panel">
          <h3>Create role</h3>
          <form className="inline-form" onSubmit={handleCreateRole}>
            <input
              placeholder="Role name"
              value={newRole.role_name}
              onChange={(e) => setNewRole({ ...newRole, role_name: e.target.value })}
              required
            />
            <input
              placeholder="Description"
              value={newRole.description}
              onChange={(e) => setNewRole({ ...newRole, description: e.target.value })}
            />
            <button type="submit" className="ds-btn ds-btn-primary" disabled={creating}>
              {creating ? "Creating…" : "Create"}
            </button>
          </form>
        </div>
      )}

      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th>Role</th>
              <th>Description</th>
              <th>Users</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {roles.map((r) => {
              const blocked = deleteBlockedReason(r);
              return (
                <tr key={r.role_id}>
                  <td className="wrap-anywhere">
                    {r.role_name}
                    {r.is_builtin && <span className="badge badge-neutral" style={{ marginLeft: 6 }}>Built-in</span>}
                  </td>
                  <td className="wrap-anywhere">{r.description}</td>
                  <td>{r.user_count}</td>
                  <td>
                    <span className="ds-actions">
                      <Link to={`/roles/${r.role_id}`} className="ds-btn ds-btn-sm">View</Link>
                      {canWrite && (
                        // The tooltip sits on a wrapper: disabled buttons do not show one in every browser.
                        <span title={blocked || `Delete ${r.role_name}`}>
                          <button
                            className="ds-btn ds-btn-sm ds-btn-danger"
                            onClick={() => handleDeleteRole(r)}
                            disabled={Boolean(blocked) || busyId === r.role_id}
                          >
                            {busyId === r.role_id ? "Deleting…" : "Delete"}
                          </button>
                        </span>
                      )}
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
