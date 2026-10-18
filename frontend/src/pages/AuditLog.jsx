import { useEffect, useMemo, useState } from "react";
import client from "../api/client";
import { parseUtc } from "../utils/date";
import { usePermissions } from "../context/PermissionsContext";

function presetRange(days) {
  const end = new Date();
  const start = new Date();
  start.setDate(start.getDate() - (days - 1));
  return {
    startDate: start.toISOString().slice(0, 10),
    endDate: end.toISOString().slice(0, 10),
  };
}

function describeAction(row) {
  if (row.source === "ui") return row.action_performed.replaceAll("_", " ");
  return `${row.resource_name} · ${row.action_performed}`;
}

export default function AuditLog() {
  const [users, setUsers] = useState([]);
  const [selectedUserIds, setSelectedUserIds] = useState([]);
  const [componentOptions, setComponentOptions] = useState([]);
  const [selectedComponents, setSelectedComponents] = useState([]);
  const [source, setSource] = useState("");
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [previewRows, setPreviewRows] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [downloading, setDownloading] = useState(false);
  const { can, loaded } = usePermissions();

  useEffect(() => {
    if (!loaded) return;
    if (can && can("user", "read")) {
      client.get("/api/users/").then((res) => setUsers(res.data)).catch(() => {});
    }
    client.get("/api/audit/components").then((res) => setComponentOptions(res.data)).catch(() => {});
  }, [loaded]);

  function applyPreset(days) {
    const { startDate: s, endDate: e } = presetRange(days);
    setStartDate(s);
    setEndDate(e);
  }

  function clearFilters() {
    setStartDate("");
    setEndDate("");
    setSelectedUserIds([]);
    setSelectedComponents([]);
    setSource("");
    setPreviewRows(null);
  }

  function toggleUser(userId) {
    setSelectedUserIds((prev) =>
      prev.includes(userId) ? prev.filter((id) => id !== userId) : [...prev, userId]
    );
  }

  function toggleComponent(name) {
    setSelectedComponents((prev) =>
      prev.includes(name) ? prev.filter((c) => c !== name) : [...prev, name]
    );
  }

  function buildParams() {
    const params = new URLSearchParams();
    if (startDate) {
      params.append("start_date", new Date(`${startDate}T00:00:00`).toISOString());
    }
    if (endDate) {
      params.append("end_date", new Date(`${endDate}T23:59:59.999`).toISOString());
    }
    selectedUserIds.forEach((id) => params.append("user_ids", id));
    selectedComponents.forEach((c) => params.append("components", c));
    if (source) params.append("source", source);
    return params;
  }

  async function handlePreview() {
    setError("");
    setLoading(true);
    try {
      const res = await client.get(`/api/audit/preview?${buildParams().toString()}`);
      setPreviewRows(res.data);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to load preview");
    } finally {
      setLoading(false);
    }
  }

  async function handleDownload() {
    setError("");
    setDownloading(true);
    try {
      const res = await client.get(`/api/audit/export?${buildParams().toString()}`, {
        responseType: "blob",
      });
      const url = window.URL.createObjectURL(new Blob([res.data]));
      const link = document.createElement("a");
      link.href = url;
      link.setAttribute("download", "audit_log.csv");
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to export audit log");
    } finally {
      setDownloading(false);
    }
  }

  const componentCounts = useMemo(() => {
    const counts = {};
    (previewRows || []).forEach((r) => {
      counts[r.component] = (counts[r.component] || 0) + 1;
    });
    return Object.entries(counts).sort((a, b) => b[1] - a[1]);
  }, [previewRows]);

  return (
    <div>
      <h2>Audit Log</h2>
      <p className="muted">
        What each user did and which part of the system they touched. Preview the records, then export them as CSV.
      </p>

      <div className="panel">
        <div className="preset-row">
          <button type="button" className="secondary" onClick={() => applyPreset(1)}>Today</button>
          <button type="button" className="secondary" onClick={() => applyPreset(7)}>Last 7 days</button>
          <button type="button" className="secondary" onClick={() => applyPreset(30)}>Last 30 days</button>
          <button type="button" className="secondary" onClick={clearFilters}>Clear all</button>
        </div>

        <div className="inline-form">
          <label>
            From{" "}
            <input type="date" value={startDate} onChange={(e) => setStartDate(e.target.value)} />
          </label>
          <label>
            To{" "}
            <input type="date" value={endDate} onChange={(e) => setEndDate(e.target.value)} />
          </label>
          <label>
            Activity{" "}
            <select value={source} onChange={(e) => setSource(e.target.value)}>
              <option value="">All activity</option>
              <option value="api">Pages and API requests</option>
              <option value="ui">Interface actions (e.g. notification bell)</option>
            </select>
          </label>
        </div>

        {componentOptions.length > 0 && (
          <div className="user-picker">
            <p className="muted">Filter by component (leave empty for all):</p>
            <div className="ds-filters">
              {componentOptions.map((name) => (
                <button
                  key={name}
                  type="button"
                  className={`ds-btn ds-btn-sm${selectedComponents.includes(name) ? " ds-btn-primary" : ""}`}
                  onClick={() => toggleComponent(name)}
                >
                  {name}
                </button>
              ))}
            </div>
          </div>
        )}

        {can && can("user", "read") && (
          <div className="user-picker">
            <p className="muted">Filter by user (leave empty for all):</p>
            <div className="user-checklist">
              {users.map((u) => (
                <label key={u.user_id} className="user-check-item">
                  <input
                    type="checkbox"
                    checked={selectedUserIds.includes(u.user_id)}
                    onChange={() => toggleUser(u.user_id)}
                  />
                  {u.username} ({u.department})
                </label>
              ))}
            </div>
          </div>
        )}

        <div className="inline-form">
          <button onClick={handlePreview} disabled={loading}>
            {loading ? "Loading…" : "Preview"}
          </button>
          <button onClick={handleDownload} disabled={downloading} className="secondary">
            {downloading ? "Exporting…" : "Download CSV"}
          </button>
        </div>
        {error && <p className="error">{error}</p>}
      </div>

      {previewRows && (
        <div className="panel">
          <h3>
            Preview ({previewRows.length} row{previewRows.length === 1 ? "" : "s"}
            {previewRows.length === 500 ? ", capped" : ""})
          </h3>

          {componentCounts.length > 0 && (
            <p>
              {componentCounts.map(([name, count]) => (
                <span key={name} className="ds-chip">{name}: {count}</span>
              ))}
            </p>
          )}

          <div className="ds-table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Timestamp</th>
                  <th>Username</th>
                  <th>Department</th>
                  <th>Component</th>
                  <th>Action</th>
                  <th>Request</th>
                  <th>Session</th>
                  <th>Type</th>
                </tr>
              </thead>
              <tbody>
                {previewRows.map((r) => (
                  <tr key={r.entry_id}>
                    <td>{parseUtc(r.timestamp).toLocaleString()}</td>
                    <td>{r.username}</td>
                    <td>{r.department}</td>
                    <td><strong>{r.component}</strong></td>
                    <td>{describeAction(r)}</td>
                    <td className="ds-mono">{r.endpoint || "—"}</td>
                    <td>{r.session_id ?? "—"}</td>
                    <td>
                      <span className={`ds-pill ${r.source === "ui" ? "ds-pill-off" : "ds-pill-ok"}`}>
                        {r.source === "ui" ? "UI" : "API"}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {previewRows.length === 0 && <p className="muted">No matching records.</p>}
        </div>
      )}
    </div>
  );
}