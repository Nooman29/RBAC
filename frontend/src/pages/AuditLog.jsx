import { useEffect, useState } from "react";
import client from "../api/client";

function presetRange(days) {
  const end = new Date();
  const start = new Date();
  start.setDate(start.getDate() - (days - 1));
  return {
    startDate: start.toISOString().slice(0, 10),
    endDate: end.toISOString().slice(0, 10),
  };
}

export default function AuditLog() {
  const [users, setUsers] = useState([]);
  const [selectedUserIds, setSelectedUserIds] = useState([]);
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [previewRows, setPreviewRows] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [downloading, setDownloading] = useState(false);

  useEffect(() => {
    client.get("/api/users/").then((res) => setUsers(res.data)).catch(() => {});
  }, []);

  function applyPreset(days) {
    const { startDate: s, endDate: e } = presetRange(days);
    setStartDate(s);
    setEndDate(e);
  }

  function clearFilters() {
    setStartDate("");
    setEndDate("");
    setSelectedUserIds([]);
    setPreviewRows(null);
  }

  function toggleUser(userId) {
    setSelectedUserIds((prev) =>
      prev.includes(userId) ? prev.filter((id) => id !== userId) : [...prev, userId]
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
    return params;
  }

  async function handlePreview() {
    setError("");
    setLoading(true);
    try {
      const params = buildParams();
      const res = await client.get(`/api/dashboard/audit-log/preview?${params.toString()}`);
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
      const params = buildParams();
      const res = await client.get(`/api/dashboard/audit-log/export?${params.toString()}`, {
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

  return (
    <div>
      <h2>Audit Log Export</h2>
      <p className="muted">Preview access log records before exporting as CSV.</p>

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
        </div>

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
          <h3>Preview ({previewRows.length} row{previewRows.length === 1 ? "" : "s"}{previewRows.length === 500 ? ", capped" : ""})</h3>
          <table className="data-table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Username</th>
                <th>Department</th>
                <th>Session</th>
                <th>Resource</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {previewRows.map((r) => (
                <tr key={r.log_id}>
                  <td>{new Date(r.timestamp).toLocaleString()}</td>
                  <td>{r.username}</td>
                  <td>{r.department}</td>
                  <td>{r.session_id}</td>
                  <td>{r.resource_name}</td>
                  <td>{r.action_performed}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {previewRows.length === 0 && <p className="muted">No matching records.</p>}
        </div>
      )}
    </div>
  );
}