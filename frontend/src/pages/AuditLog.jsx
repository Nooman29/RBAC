import { useState } from "react";
import client from "../api/client";

export default function AuditLog() {
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [userId, setUserId] = useState("");
  const [error, setError] = useState("");
  const [downloading, setDownloading] = useState(false);

  async function handleExport() {
    setError("");
    setDownloading(true);
    try {
      const params = {};
      if (startDate) params.start_date = new Date(startDate).toISOString();
      if (endDate) params.end_date = new Date(endDate).toISOString();
      if (userId) params.user_id = userId;

      const res = await client.get("/api/dashboard/audit-log/export", {
        params,
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
      <p className="muted">Export access log records as CSV for compliance or review.</p>
      <div className="panel">
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
            User ID{" "}
            <input
              type="number"
              value={userId}
              onChange={(e) => setUserId(e.target.value)}
              placeholder="all users"
            />
          </label>
          <button onClick={handleExport} disabled={downloading}>
            {downloading ? "Exporting…" : "Download CSV"}
          </button>
        </div>
        {error && <p className="error">{error}</p>}
      </div>
    </div>
  );
}