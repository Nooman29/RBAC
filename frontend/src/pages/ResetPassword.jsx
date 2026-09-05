import { useState } from "react";
import { useSearchParams, useNavigate, Link } from "react-router-dom";
import client from "../api/client";

export default function ResetPassword() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token");
  const navigate = useNavigate();

  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [done, setDone] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");

    if (!token) {
      setError("This reset link is missing its token. Request a new one.");
      return;
    }
    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    if (password.length < 8) {
      setError("Password must be at least 8 characters.");
      return;
    }

    setBusy(true);
    try {
      await client.post("/api/auth/reset-password", { token, new_password: password });
      setDone(true);
      setTimeout(() => navigate("/login"), 1500);
    } catch (err) {
      setError(err.response?.data?.detail || "This link is invalid or has expired.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="auth-screen">
      <div className="auth-card">
        <h1>Reset Password</h1>
        {done ? (
          <p className="info">Password reset — redirecting to login…</p>
        ) : (
          <form onSubmit={handleSubmit}>
            <label>New Password</label>
            <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} required />
            <label>Confirm Password</label>
            <input type="password" value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
            {error && <p className="error">{error}</p>}
            <button type="submit" disabled={busy}>
              {busy ? "Resetting…" : "Reset Password"}
            </button>
          </form>
        )}
        {!done && (
          <p className="muted" style={{ textAlign: "center", marginTop: 10 }}>
            <Link to="/forgot-password">Request a new link</Link>
          </p>
        )}
      </div>
    </div>
  );
}