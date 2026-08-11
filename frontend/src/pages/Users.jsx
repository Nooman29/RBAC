import { useEffect, useState } from "react";
import client from "../api/client";

export default function Users() {
  const [users, setUsers] = useState([]);
  const [roles, setRoles] = useState([]);
  const [error, setError] = useState("");
  const [newUser, setNewUser] = useState({ username: "", email: "", password: "" });
  const [creating, setCreating] = useState(false);

  function loadUsers() {
    client
      .get("/api/users/")
      .then((res) => setUsers(res.data))
      .catch((err) => setError(err.response?.data?.detail || "Failed to load users"));
  }

  function loadRoles() {
    client.get("/api/roles/").then((res) => setRoles(res.data)).catch(() => {});
  }

  useEffect(() => {
    loadUsers();
    loadRoles();
  }, []);

  async function handleAssignRole(userId, roleId) {
    if (!roleId) return;
    setError("");
    try {
      await client.post(`/api/users/${userId}/roles/${roleId}`);
      loadUsers();
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to assign role");
    }
  }

  async function handleRemoveRole(userId, roleId) {
    setError("");
    try {
      await client.delete(`/api/users/${userId}/roles/${roleId}`);
      loadUsers();
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to remove role");
    }
  }

  async function handleCreateUser(e) {
    e.preventDefault();
    setError("");
    setCreating(true);
    try {
      await client.post("/api/users/", { ...newUser, role_ids: [] });
      setNewUser({ username: "", email: "", password: "" });
      loadUsers();
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to create user");
    } finally {
      setCreating(false);
    }
  }

  return (
    <div>
      <h2>Users</h2>
      {error && <p className="error">{error}</p>}

      <div className="panel">
        <h3>Create user</h3>
        <form className="inline-form" onSubmit={handleCreateUser}>
          <input
            placeholder="Username"
            value={newUser.username}
            onChange={(e) => setNewUser({ ...newUser, username: e.target.value })}
            required
          />
          <input
            placeholder="Email"
            type="email"
            value={newUser.email}
            onChange={(e) => setNewUser({ ...newUser, email: e.target.value })}
            required
          />
          <input
            placeholder="Password"
            type="password"
            value={newUser.password}
            onChange={(e) => setNewUser({ ...newUser, password: e.target.value })}
            required
          />
          <button type="submit" disabled={creating}>
            {creating ? "Creating…" : "Create"}
          </button>
        </form>
      </div>

      <table className="data-table">
        <thead>
          <tr>
            <th>Username</th>
            <th>Email</th>
            <th>Roles</th>
            <th>Assign role</th>
          </tr>
        </thead>
        <tbody>
          {users.map((u) => (
            <tr key={u.user_id}>
              <td>{u.username}</td>
              <td>{u.email}</td>
              <td>
                {u.roles.length === 0 && <span className="muted">no roles</span>}
                {u.roles.map((r) => (
                  <span key={r.role_id} className="badge">
                    {r.role_name}
                    <button
                      className="badge-remove"
                      title={`Remove ${r.role_name}`}
                      onClick={() => handleRemoveRole(u.user_id, r.role_id)}
                    >
                      ×
                    </button>
                  </span>
                ))}
              </td>
              <td>
                <RoleAssignSelect roles={roles} onAssign={(roleId) => handleAssignRole(u.user_id, roleId)} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RoleAssignSelect({ roles, onAssign }) {
  const [selected, setSelected] = useState("");
  return (
    <div className="inline-form">
      <select value={selected} onChange={(e) => setSelected(e.target.value)}>
        <option value="">Select role…</option>
        {roles.map((r) => (
          <option key={r.role_id} value={r.role_id}>
            {r.role_name}
          </option>
        ))}
      </select>
      <button
        onClick={() => {
          onAssign(selected);
          setSelected("");
        }}
        disabled={!selected}
      >
        Add
      </button>
    </div>
  );
}