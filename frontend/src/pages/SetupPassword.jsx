import { useState } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import AuthShell from "../components/AuthShell";

export default function SetupPassword() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token");
  const navigate = useNavigate();
  const { setupPassword } = useAuth();

  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");

    if (!token) {
      setError("This setup link is missing its token. Ask an administrator to resend it.");
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
      const pendingToken = await setupPassword(token, password);
      navigate("/first-time-setup", { state: { pendingToken } });
    } catch (err) {
      setError(err.response?.data?.detail || "This link is invalid or has expired.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell
      title="Set your password"
      subtitle="This activates your account. You'll set up sign-in verification next."
    >
      <form onSubmit={handleSubmit}>
        <label htmlFor="sp-password">New password</label>
        <input
          id="sp-password"
          type="password"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="new-password"
          autoFocus
          required
        />
        <p className="auth-hint">At least 8 characters.</p>
        <label htmlFor="sp-confirm">Confirm password</label>
        <input
          id="sp-confirm"
          type="password"
          value={confirm}
          onChange={(e) => setConfirm(e.target.value)}
          autoComplete="new-password"
          required
        />
        {error && <p className="auth-alert auth-alert-error" role="alert">{error}</p>}
        <button type="submit" disabled={busy}>
          {busy ? "Setting up…" : "Continue"}
        </button>
      </form>
    </AuthShell>
  );
}