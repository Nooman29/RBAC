import { useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext";
import client from "../api/client";

const DEPARTMENTS = ["IT", "Finance", "HR", "Operations", "Executive", "Unassigned"];

export default function Users() {
  const [users, setUsers] = useState([]);
  const [roles, setRoles] = useState([]);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [newUser, setNewUser] = useState({ username: "", email: "", department: "IT", role_id: "" });
  const [creating, setCreating] = useState(false);
  const [currentUser, setCurrentUser] = useState(null);
  const { fetchMe } = useAuth();

  function loadUsers() {
    client
      .get("/api/users/")
      .then((res) => setUsers(res.data))
      .catch((err) => setError(err.response?.data?.detail || "Failed to load users"));
  }

  function loadRoles() {
    client
      .get("/api/roles/")
      .then((res) => setRoles(res.data))
      .catch((err) => setError(err.response?.data?.detail || "Failed to load roles — role selection may be unavailable."));
  }

  useEffect(() => {
    loadUsers();
    loadRoles();
    fetchMe().then((me) => setCurrentUser(me)).catch(() => {});
  }, []);

  const isAdmin = currentUser?.roles?.some((r) => r.role_name === "Administrator");

  function isLastAdmin(user) {
    const isAdminUser = user.roles.some((r) => r.role_name === "Administrator");
    if (!isAdminUser) return false;
    const adminCount = users.filter((u) => u.roles.some((r) => r.role_name === "Administrator")).length;
    return adminCount <= 1;
  }

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
    setInfo("");

    if (!newUser.role_id) {
      setError("Please select a role for the new user.");
      return;
    }

    setCreating(true);
    try {
      await client.post("/api/users/", {
        username: newUser.username,
        email: newUser.email,
        department: newUser.department,
        role_ids: [Number(newUser.role_id)],
      });
      setNewUser({ username: "", email: "", department: "IT", role_id: "" });
      setInfo("User created — a setup email has been sent to activate their account.");
      loadUsers();
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to create user");
    } finally {
      setCreating(false);
    }
  }

  async function handleResendSetup(userId) {
    setError("");
    setInfo("");
    try {
      await client.post(`/api/users/${userId}/resend-setup-email`);
      setInfo("Setup email resent.");
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to resend setup email");
    }
  }

  async function handleChangeDepartment(userId, department) {
    setError("");
    try {
      await client.patch(`/api/users/${userId}/department`, { department });
      loadUsers();
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to change department");
    }
  }

  async function handleDeleteUser(user) {
    setError("");
    const confirmed = window.confirm(`Delete user '${user.username}'? This cannot be undone.`);
    if (!confirmed) return;
    try {
      await client.delete(`/api/users/${user.user_id}`);
      loadUsers();
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to delete user");
    }
  }

  return (
    <div>
      <h2>Users</h2>
      {!isAdmin && currentUser && (
        <p className="muted">Showing users in your department ({currentUser.department}) only.</p>
      )}
      {error && <p className="error">{error}</p>}
      {info && <p className="info">{info}</p>}

      <div className="panel">
        <h3>Create user</h3>
        <p className="muted">
          The new user will receive an email to set their own password and enroll sign-in verification.
          A role is required.
        </p>
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
          <select
            value={newUser.department}
            onChange={(e) => setNewUser({ ...newUser, department: e.target.value })}
          >
            {DEPARTMENTS.filter((d) => d !== "Unassigned").map((d) => (
              <option key={d} value={d}>{d}</option>
            ))}
          </select>
          <select
            value={newUser.role_id}
            onChange={(e) => setNewUser({ ...newUser, role_id: e.target.value })}
            required
          >
            <option value="">Select role… (required)</option>
            {roles.map((r) => (
              <option key={r.role_id} value={r.role_id}>{r.role_name}</option>
            ))}
          </select>
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
            <th>Department</th>
            <th>Status</th>
            <th>Roles</th>
            <th>Assign role</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {users.map((u) => {
            const isSelf = u.user_id === currentUser?.user_id;
            const lastAdmin = isLastAdmin(u);
            const assignedRoleIds = new Set(u.roles.map((r) => r.role_id));
            const availableToAssign = roles.filter((r) => !assignedRoleIds.has(r.role_id));

            return (
              <tr key={u.user_id}>
                <td>
                  {u.username}
                  {isSelf && <span className="badge self-badge">You</span>}
                </td>
                <td>{u.email}</td>
                <td>
                  {isAdmin ? (
                    <select
                      value={u.department}
                      onChange={(e) => handleChangeDepartment(u.user_id, e.target.value)}
                    >
                      {DEPARTMENTS.map((d) => (
                        <option key={d} value={d}>{d}</option>
                      ))}
                    </select>
                  ) : (
                    u.department
                  )}
                </td>
                <td>
                  {u.password_set ? (
                    <span className="status-active">Active</span>
                  ) : (
                    <>
                      <span className="status-pending">Setup pending</span>
                      <button className="link-btn" onClick={() => handleResendSetup(u.user_id)}>
                        Resend email
                      </button>
                    </>
                  )}
                </td>
                <td>
                  {u.roles.length === 0 ? (
                    <span className="badge badge-warning">No roles assigned</span>
                  ) : (
                    u.roles.map((r) => {
                      const blockRoleRemoval = r.role_name === "Administrator" && (isSelf || lastAdmin);
                      return (
                        <span key={r.role_id} className="badge">
                          {r.role_name}
                          {!blockRoleRemoval && (
                            <button
                              className="badge-remove"
                              title={`Remove ${r.role_name}`}
                              onClick={() => handleRemoveRole(u.user_id, r.role_id)}
                            >
                              ×
                            </button>
                          )}
                        </span>
                      );
                    })
                  )}
                </td>
                <td>
                  <RoleAssignSelect
                    roles={availableToAssign}
                    onAssign={(roleId) => handleAssignRole(u.user_id, roleId)}
                  />
                </td>
                <td>
                  {isSelf ? (
                    <span className="muted">Protected</span>
                  ) : lastAdmin ? (
                    <span className="muted">Protected</span>
                  ) : (
                    <button className="link-btn danger" onClick={() => handleDeleteUser(u)}>
                      Delete
                    </button>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function RoleAssignSelect({ roles, onAssign }) {
  const [selected, setSelected] = useState("");

  if (roles.length === 0) {
    return <span className="muted">All roles assigned</span>;
  }

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