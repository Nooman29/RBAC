import { useState } from "react";
import { useSearchParams, useNavigate, Link } from "react-router-dom";
import client from "../api/client";
import AuthShell from "../components/AuthShell";

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
    <AuthShell title="Reset password" subtitle="Choose a new password for your account.">
      {done ? (
        <p className="auth-alert auth-alert-info" role="status">Password reset. Redirecting to login…</p>
      ) : (
        <form onSubmit={handleSubmit}>
          <label htmlFor="rp-password">New password</label>
          <input
            id="rp-password"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="new-password"
            autoFocus
            required
          />
          <p className="auth-hint">At least 8 characters.</p>
          <label htmlFor="rp-confirm">Confirm password</label>
          <input
            id="rp-confirm"
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            autoComplete="new-password"
            required
          />
          {error && <p className="auth-alert auth-alert-error" role="alert">{error}</p>}
          <button type="submit" disabled={busy}>
            {busy ? "Resetting…" : "Reset password"}
          </button>
          <Link to="/forgot-password" className="auth-link">Request a new link</Link>
        </form>
      )}
    </AuthShell>
  );
}