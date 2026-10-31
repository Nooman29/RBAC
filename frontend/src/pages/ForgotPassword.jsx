import { useState } from "react";
import { Link } from "react-router-dom";
import client from "../api/client";
import AuthShell from "../components/AuthShell";

export default function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [submitted, setSubmitted] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function handleSubmit(e) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      await client.post("/api/auth/forgot-password", { email });
      setSubmitted(true);
    } catch (err) {
      setError(err.response?.data?.detail || "Something went wrong. Try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell title="Forgot password" subtitle="Enter your email and we'll send you a link to reset it.">
      {submitted ? (
        <div>
          <p className="auth-alert auth-alert-info" role="status">
            If an account exists with that email, a reset link has been sent. Check your inbox.
          </p>
          <Link to="/login" className="auth-secondary">Back to login</Link>
        </div>
      ) : (
        <form onSubmit={handleSubmit}>
          <label htmlFor="fp-email">Email</label>
          <input
            id="fp-email"
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="email"
            autoFocus
            required
          />
          {error && <p className="auth-alert auth-alert-error" role="alert">{error}</p>}
          <button type="submit" disabled={busy}>
            {busy ? "Sending…" : "Send reset link"}
          </button>
          <Link to="/login" className="auth-secondary">Back to login</Link>
        </form>
      )}
    </AuthShell>
  );
}