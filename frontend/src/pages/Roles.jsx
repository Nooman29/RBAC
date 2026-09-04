import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import client from "../api/client";
import { usePermissions } from "../context/PermissionsContext";
import ViewOnlyNotice from "../components/ViewOnlyNotice";

export default function Roles() {
  const { can } = usePermissions();
  const [roles, setRoles] = useState([]);
  const [error, setError] = useState("");
  const [newRole, setNewRole] = useState({ role_name: "", description: "" });
  const [creating, setCreating] = useState(false);

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

  return (
    <div>
      <h2>Roles</h2>
      {error && <p className="error">{error}</p>}
      <ViewOnlyNotice resource="role" label="role management" />

      {can && can("role", "write") && (
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
            <button type="submit" disabled={creating}>
              {creating ? "Creating…" : "Create"}
            </button>
          </form>
        </div>
      )}

      <table className="data-table">
        <thead>
          <tr>
            <th>Role</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          {roles.map((r) => (
            <tr key={r.role_id}>
              <td>
                <Link to={`/roles/${r.role_id}`}>{r.role_name}</Link>
              </td>
              <td>{r.description}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}