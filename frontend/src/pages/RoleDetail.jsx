import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import client from "../api/client";
import { usePermissions } from "../context/PermissionsContext";
import ViewOnlyNotice from "../components/ViewOnlyNotice";

export default function RoleDetail() {
  const { roleId } = useParams();
  const { can } = usePermissions();
  const [role, setRole] = useState(null);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [catalog, setCatalog] = useState({ resources: [], actions: [] });
  const [newPerm, setNewPerm] = useState({ resource_name: "", action_type: "" });
  const [busyId, setBusyId] = useState(null);

  function load() {
    client
      .get(`/api/roles/${roleId}`)
      .then((res) => setRole(res.data))
      .catch((err) => setError(err.response?.data?.detail || "Failed to load role"));
  }

  useEffect(load, [roleId]);

  // The resources and actions a permission can name, from the backend's catalog.
  useEffect(() => {
    client
      .get("/api/roles/catalog")
      .then((res) => {
        setCatalog(res.data);
        setNewPerm({ resource_name: res.data.resources[0] || "", action_type: res.data.actions[0] || "" });
      })
      .catch(() => {});
  }, []);

  async function handleGrant(e) {
    e.preventDefault();
    setError("");
    setInfo("");
    try {
      await client.post(`/api/roles/${roleId}/permissions`, null, {
        params: { resource_name: newPerm.resource_name, action_type: newPerm.action_type },
      });
      setInfo(`Granted ${newPerm.action_type} on ${newPerm.resource_name}.`);
      load();
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to grant permission");
    }
  }

  async function handleRevoke(p) {
    const ok = window.confirm(
      `Revoke ${p.action_type} on ${p.resource_name} from ${role.role_name}?\n\n` +
        "Users with this role lose it on their next request."
    );
    if (!ok) return;
    setError("");
    setInfo("");
    setBusyId(p.permission_id);
    try {
      await client.delete(`/api/roles/${roleId}/permissions/${p.permission_id}`);
      setInfo(`Revoked ${p.action_type} on ${p.resource_name}.`);
      load();
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to revoke permission");
    } finally {
      setBusyId(null);
    }
  }

  if (error && !role) return <p className="error">{error}</p>;
  if (!role) return <p>Loading…</p>;

  const canWrite = can && can("role", "write");

  return (
    <div>
      <Link to="/roles" className="ds-btn ds-btn-sm ds-back">&larr; Back to roles</Link>
      <h2 className="wrap-anywhere">{role.role_name}</h2>
      <p className="muted wrap-anywhere">{role.description}</p>

      {error && <p className="error">{error}</p>}
      {info && <p className="info">{info}</p>}
      <ViewOnlyNotice resource="role" label="this role's permissions" />

      <h3>Permissions</h3>
      <div className="table-scroll">
        <table className="data-table">
          <thead>
            <tr>
              <th>Resource</th>
              <th>Action</th>
              {canWrite && <th>Remove</th>}
            </tr>
          </thead>
          <tbody>
            {role.permissions.map((p) => (
              <tr key={p.permission_id}>
                <td>{p.resource_name}</td>
                <td>{p.action_type}</td>
                {canWrite && (
                  <td>
                    <button
                      className="ds-btn ds-btn-sm ds-btn-danger"
                      onClick={() => handleRevoke(p)}
                      disabled={busyId === p.permission_id}
                    >
                      {busyId === p.permission_id ? "Revoking…" : "Revoke"}
                    </button>
                  </td>
                )}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
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
              {catalog.resources.map((r) => (
                <option key={r} value={r}>{r}</option>
              ))}
            </select>
            <select
              value={newPerm.action_type}
              onChange={(e) => setNewPerm({ ...newPerm, action_type: e.target.value })}
            >
              {catalog.actions.map((a) => (
                <option key={a} value={a}>{a}</option>
              ))}
            </select>
            <button type="submit" className="ds-btn ds-btn-primary" disabled={!newPerm.resource_name || !newPerm.action_type}>Grant</button>
          </form>
        </div>
      )}
    </div>
  );
}
