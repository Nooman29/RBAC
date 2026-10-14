import { useCallback, useEffect, useState } from "react";
import api from "../api/client";
import { usePermissions } from "../context/PermissionsContext";

const PAGE = 50;

// Backend timestamps are naive UTC; append Z so the browser doesn't read them as local time.
function fmt(ts) {
  if (!ts) return "—";
  const s = String(ts);
  const d = new Date(/(Z|[+-]\d{2}:?\d{2})$/.test(s) ? s : s + "Z");
  return isNaN(d) ? "—" : d.toLocaleString();
}

function errText(err, fallback) {
  const detail = err?.response?.data?.detail;
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) return detail.map((d) => d.msg).join("; ");
  return fallback;
}

function contextText(ctx) {
  if (!ctx) return "";
  return Object.entries(ctx).map(([k, v]) => `${k}=${v}`).join(", ");
}

function ScopePicker({ scopes, value, onChange }) {
  function toggle(scope) {
    onChange(value.includes(scope) ? value.filter((s) => s !== scope) : [...value, scope]);
  }
  return (
    <div className="ds-scope-grid">
      {scopes.map((s) => (
        <label key={s.scope} className={`ds-scope-opt${value.includes(s.scope) ? " on" : ""}`}>
          <input type="checkbox" checked={value.includes(s.scope)} onChange={() => toggle(s.scope)} />
          <span>
            <strong className="ds-mono">{s.scope}</strong>
            <br />
            <span className="muted">{s.description}</span>
          </span>
        </label>
      ))}
    </div>
  );
}

function SecretPanel({ reveal, onDismiss }) {
  const [copied, setCopied] = useState("");

  async function copy(label, text) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(label);
      setTimeout(() => setCopied(""), 1500);
    } catch {
      setCopied("failed");
    }
  }

  return (
    <div className="ds-secret">
      <h3>
        {reveal.rotated ? "New secret generated" : "Service client created"}: {reveal.name}
      </h3>
      <p className="muted">
        Copy the secret now. Only a hash is stored, so it cannot be shown again. Give it to the module's
        developer to keep on their server, never in browser code.
      </p>
      <strong>Client ID (X-Client-Id)</strong>
      <div className="ds-secret-row">
        <code>{reveal.client_id}</code>
        <button className="ds-btn ds-btn-sm" onClick={() => copy("id", reveal.client_id)}>
          {copied === "id" ? "Copied" : "Copy"}
        </button>
      </div>
      <strong>Secret (X-Client-Secret)</strong>
      <div className="ds-secret-row">
        <code>{reveal.secret}</code>
        <button className="ds-btn ds-btn-sm" onClick={() => copy("secret", reveal.secret)}>
          {copied === "secret" ? "Copied" : "Copy"}
        </button>
      </div>
      {copied === "failed" && <p className="error">Copy failed. Select the text and copy it manually.</p>}
      <button className="ds-btn" onClick={onDismiss}>I have saved it, dismiss</button>
    </div>
  );
}

function EditModal({ target, scopes, onClose, onSaved, setError }) {
  const [description, setDescription] = useState(target.description || "");
  const [value, setValue] = useState(target.scopes);
  const [saving, setSaving] = useState(false);

  async function save() {
    if (value.length === 0) {
      setError("A service client needs at least one scope.");
      return;
    }
    setSaving(true);
    try {
      await api.patch(`/api/service-clients/${target.id}`, {
        description: description.trim() || null,
        scopes: value,
      });
      onSaved();
      onClose();
    } catch (err) {
      setError(errText(err, "Failed to update service client"));
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="ds-modal-backdrop" onClick={onClose}>
      <div className="ds-modal" onClick={(e) => e.stopPropagation()}>
        <h3>Edit {target.name}</h3>
        <div className="ds-field">
          <label>Description</label>
          <input className="ds-input" value={description} onChange={(e) => setDescription(e.target.value)} />
        </div>
        <label className="muted">Scopes</label>
        <ScopePicker scopes={scopes} value={value} onChange={setValue} />
        <div className="ds-modal-actions">
          <button className="ds-btn" onClick={onClose}>Cancel</button>
          <button className="ds-btn ds-btn-primary" onClick={save} disabled={saving}>
            {saving ? "Saving…" : "Save"}
          </button>
        </div>
      </div>
    </div>
  );
}

function ClientsTab({ clients, scopes, canWrite, reload, setError, setInfo }) {
  const [form, setForm] = useState({ name: "", description: "", scopes: [] });
  const [creating, setCreating] = useState(false);
  const [reveal, setReveal] = useState(null);
  const [editing, setEditing] = useState(null);

  async function handleCreate(e) {
    e.preventDefault();
    setError("");
    setInfo("");
    setCreating(true);
    try {
      const res = await api.post("/api/service-clients/", {
        name: form.name.trim(),
        description: form.description.trim() || null,
        scopes: form.scopes,
      });
      setReveal({ name: res.data.name, client_id: res.data.client_id, secret: res.data.client_secret });
      setForm({ name: "", description: "", scopes: [] });
      reload();
    } catch (err) {
      setError(errText(err, "Failed to create service client"));
    } finally {
      setCreating(false);
    }
  }

  async function handleRotate(c) {
    if (!window.confirm(`Generate a new secret for '${c.name}'? The old secret stops working immediately.`)) return;
    setError("");
    try {
      const res = await api.post(`/api/service-clients/${c.id}/rotate-secret`);
      setReveal({ name: c.name, client_id: res.data.client_id, secret: res.data.client_secret, rotated: true });
      reload();
    } catch (err) {
      setError(errText(err, "Failed to rotate secret"));
    }
  }

  async function handleToggle(c) {
    setError("");
    try {
      await api.patch(`/api/service-clients/${c.id}`, { is_active: !c.is_active });
      reload();
    } catch (err) {
      setError(errText(err, "Failed to update service client"));
    }
  }

  async function handleDelete(c) {
    if (!window.confirm(`Delete '${c.name}'? The module will lose access immediately. Its audit history is kept.`)) return;
    setError("");
    try {
      await api.delete(`/api/service-clients/${c.id}`);
      setInfo(`Service client '${c.name}' deleted.`);
      reload();
    } catch (err) {
      setError(errText(err, "Failed to delete service client"));
    }
  }

  return (
    <div>
      {reveal && <SecretPanel reveal={reveal} onDismiss={() => setReveal(null)} />}

      {canWrite && (
        <form className="ds-card" onSubmit={handleCreate}>
          <h3>Register a module</h3>
          <p className="muted">
            Each module (payments, attendance, logistics…) gets its own credentials and only the scopes it needs.
          </p>
          <div className="ds-field">
            <label>Name</label>
            <input
              className="ds-input"
              placeholder="e.g. Payments module"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              minLength={3}
              required
            />
          </div>
          <div className="ds-field">
            <label>Description (optional)</label>
            <input
              className="ds-input"
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />
          </div>
          <label className="muted">Scopes</label>
          <ScopePicker scopes={scopes} value={form.scopes} onChange={(v) => setForm({ ...form, scopes: v })} />
          <button className="ds-btn ds-btn-primary" type="submit" disabled={creating || form.scopes.length === 0}>
            {creating ? "Creating…" : "Create service client"}
          </button>
        </form>
      )}

      <div className="ds-card">
        <h3>Registered modules</h3>
        {clients.length === 0 ? (
          <div className="ds-empty">No service clients yet.</div>
        ) : (
          <div className="ds-table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Client ID</th>
                  <th>Scopes</th>
                  <th>Status</th>
                  <th>Last used</th>
                  {canWrite && <th></th>}
                </tr>
              </thead>
              <tbody>
                {clients.map((c) => (
                  <tr key={c.id}>
                    <td>
                      <strong>{c.name}</strong>
                      {c.description && <div className="muted">{c.description}</div>}
                    </td>
                    <td className="ds-mono">{c.client_id}</td>
                    <td>{c.scopes.map((s) => <span key={s} className="ds-chip">{s}</span>)}</td>
                    <td>
                      <span className={`ds-pill ${c.is_active ? "ds-pill-ok" : "ds-pill-off"}`}>
                        {c.is_active ? "Active" : "Disabled"}
                      </span>
                    </td>
                    <td>{fmt(c.last_used_at)}</td>
                    {canWrite && (
                      <td>
                        <div className="ds-row-actions">
                          <button className="ds-btn ds-btn-sm" onClick={() => setEditing(c)}>Edit</button>
                          <button className="ds-btn ds-btn-sm" onClick={() => handleRotate(c)}>Rotate secret</button>
                          <button className="ds-btn ds-btn-sm" onClick={() => handleToggle(c)}>
                            {c.is_active ? "Disable" : "Enable"}
                          </button>
                          <button className="ds-btn ds-btn-sm ds-btn-danger" onClick={() => handleDelete(c)}>
                            Delete
                          </button>
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {editing && (
        <EditModal
          target={editing}
          scopes={scopes}
          onClose={() => setEditing(null)}
          onSaved={reload}
          setError={setError}
        />
      )}
    </div>
  );
}

function Pager({ offset, pageSize, count, total, onChange }) {
  const to = offset + count;
  const noMore = total != null ? to >= total : count < pageSize;
  return (
    <div className="ds-pager">
      <button className="ds-btn ds-btn-sm" disabled={offset === 0} onClick={() => onChange(Math.max(0, offset - pageSize))}>
        Newer
      </button>
      <span>
        {count ? `${offset + 1}–${to}` : "No results"}
        {total != null ? ` of ${total}` : ""}
      </span>
      <button className="ds-btn ds-btn-sm" disabled={noMore} onClick={() => onChange(offset + pageSize)}>
        Older
      </button>
    </div>
  );
}

function AuditTab({ clients, setError }) {
  const [rows, setRows] = useState([]);
  const [offset, setOffset] = useState(0);
  const [clientId, setClientId] = useState("");
  const [result, setResult] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    api
      .get("/api/service-clients/audit", {
        params: {
          limit: PAGE,
          offset,
          service_client_id: clientId || undefined,
          allowed: result === "" ? undefined : result === "allowed",
        },
      })
      .then((res) => setRows(res.data))
      .catch((err) => setError(errText(err, "Failed to load the authorization audit")))
      .finally(() => setLoading(false));
  }, [offset, clientId, result]);

  return (
    <div className="ds-card">
      <h3>Authorization decisions</h3>
      <p className="muted">Every permission check a module made on behalf of a user, including denials.</p>
      <div className="ds-filters">
        <select className="ds-select" value={clientId} onChange={(e) => { setOffset(0); setClientId(e.target.value); }}>
          <option value="">All modules</option>
          {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
        <select className="ds-select" value={result} onChange={(e) => { setOffset(0); setResult(e.target.value); }}>
          <option value="">Allowed and denied</option>
          <option value="allowed">Allowed only</option>
          <option value="denied">Denied only</option>
        </select>
      </div>
      {loading ? (
        <div className="ds-empty">Loading…</div>
      ) : rows.length === 0 ? (
        <div className="ds-empty">No decisions recorded yet.</div>
      ) : (
        <div className="ds-table-wrap">
          <table className="data-table">
            <thead>
              <tr><th>Time</th><th>Module</th><th>User</th><th>Request</th><th>Decision</th><th>Reason</th><th>Context</th></tr>
            </thead>
            <tbody>
              {rows.map((r) => (
                <tr key={r.id}>
                  <td>{fmt(r.created_at)}</td>
                  <td>{r.client_name || <span className="muted">(deleted)</span>}</td>
                  <td>{r.user_id ?? "—"}</td>
                  <td className="ds-mono">{r.resource_name}:{r.action_type}</td>
                  <td>
                    <span className={`ds-pill ${r.allowed ? "ds-pill-ok" : "ds-pill-bad"}`}>
                      {r.allowed ? "Allowed" : "Denied"}
                    </span>
                  </td>
                  <td className="ds-mono">{r.reason}</td>
                  <td className="ds-mono">{contextText(r.context)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Pager offset={offset} pageSize={PAGE} count={rows.length} total={null} onChange={setOffset} />
    </div>
  );
}

function EventsTab({ clients, setError }) {
  const [data, setData] = useState({ items: [], total: 0 });
  const [offset, setOffset] = useState(0);
  const [clientId, setClientId] = useState("");
  const [onlyDenied, setOnlyDenied] = useState(false);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    setLoading(true);
    api
      .get("/api/module-events/", {
        params: {
          limit: PAGE,
          offset,
          service_client_id: clientId || undefined,
          permitted: onlyDenied ? false : undefined,
        },
      })
      .then((res) => setData(res.data))
      .catch((err) => setError(errText(err, "Failed to load reported events")))
      .finally(() => setLoading(false));
  }, [offset, clientId, onlyDenied]);

  return (
    <div className="ds-card">
      <h3>Reported events</h3>
      <p className="muted">
        Activity that modules report about users. It joins the user's session and is scored for anomalies
        when the session ends. "Not permitted" means the user did something their role does not allow.
      </p>
      <div className="ds-filters">
        {clients.length > 0 && (
          <select className="ds-select" value={clientId} onChange={(e) => { setOffset(0); setClientId(e.target.value); }}>
            <option value="">All modules</option>
            {clients.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        )}
        <label>
          <input type="checkbox" checked={onlyDenied} onChange={(e) => { setOffset(0); setOnlyDenied(e.target.checked); }} />{" "}
          Not permitted only
        </label>
      </div>
      {loading ? (
        <div className="ds-empty">Loading…</div>
      ) : data.items.length === 0 ? (
        <div className="ds-empty">No events reported yet.</div>
      ) : (
        <div className="ds-table-wrap">
          <table className="data-table">
            <thead>
              <tr><th>Recorded</th><th>Module</th><th>User</th><th>Action</th><th>Entity</th><th>Permission</th><th>Details</th></tr>
            </thead>
            <tbody>
              {data.items.map((ev) => (
                <tr key={ev.id}>
                  <td>{fmt(ev.created_at)}</td>
                  <td>{ev.source_client || <span className="muted">(deleted)</span>}</td>
                  <td>{ev.user_id ?? "—"}</td>
                  <td className="ds-mono">{ev.resource_name}:{ev.action_type}</td>
                  <td className="ds-mono">{ev.entity_ref || "—"}</td>
                  <td>
                    <span className={`ds-pill ${ev.permitted ? "ds-pill-ok" : "ds-pill-bad"}`}>
                      {ev.permitted ? "Permitted" : "Not permitted"}
                    </span>
                  </td>
                  <td className="ds-mono" title={ev.details ? JSON.stringify(ev.details) : ""}>
                    {ev.details ? JSON.stringify(ev.details).slice(0, 60) : ""}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Pager offset={offset} pageSize={PAGE} count={data.items.length} total={data.total} onChange={setOffset} />
    </div>
  );
}

export default function Integrations() {
  const { can, loaded } = usePermissions();
  const canRead = Boolean(loaded && can && can("service_client", "read"));
  const canWrite = Boolean(loaded && can && can("service_client", "write"));
  const canEvents = Boolean(loaded && can && can("fraud", "read"));

  const [tab, setTab] = useState(null);
  const [clients, setClients] = useState([]);
  const [scopes, setScopes] = useState([]);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");

  const loadClients = useCallback(() => {
    if (!canRead) return;
    api
      .get("/api/service-clients/")
      .then((res) => setClients(res.data))
      .catch((err) => setError(errText(err, "Failed to load service clients")));
    api
      .get("/api/service-clients/scopes")
      .then((res) => setScopes(res.data))
      .catch(() => {});
  }, [canRead]);

  useEffect(() => {
    loadClients();
  }, [loadClients]);

  const tabs = [
    canRead && { id: "clients", label: "Service clients" },
    canRead && { id: "audit", label: "Authorization audit" },
    canEvents && { id: "events", label: "Reported events" },
  ].filter(Boolean);

  useEffect(() => {
    if (!tab && tabs.length) setTab(tabs[0].id);
  }, [tabs.length]);

  if (!loaded) return <p className="muted">Loading…</p>;
  if (tabs.length === 0) return <p className="muted">You do not have permission to view integrations.</p>;

  return (
    <div>
      <h2>Integrations</h2>
      <p className="muted">
        Other modules of the Digital School Feeding System use this service for login, permissions and
        activity reporting. API documentation for developers is at{" "}
        <a href="/api/v1/docs" target="_blank" rel="noreferrer">/api/v1/docs</a>.
      </p>
      {error && <p className="error">{error}</p>}
      {info && <p className="info">{info}</p>}

      <div className="ds-tabs">
        {tabs.map((t) => (
          <button
            key={t.id}
            className={`ds-tab${tab === t.id ? " active" : ""}`}
            onClick={() => { setError(""); setInfo(""); setTab(t.id); }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === "clients" && (
        <ClientsTab
          clients={clients}
          scopes={scopes}
          canWrite={canWrite}
          reload={loadClients}
          setError={setError}
          setInfo={setInfo}
        />
      )}
      {tab === "audit" && <AuditTab clients={clients} setError={setError} />}
      {tab === "events" && <EventsTab clients={clients} setError={setError} />}
    </div>
  );
}