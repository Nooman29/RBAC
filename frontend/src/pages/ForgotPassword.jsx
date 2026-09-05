import { useState } from "react";
import { Link } from "react-router-dom";
import client from "../api/client";

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
    <div className="auth-screen">
      <div className="auth-card">
        <h1>Forgot Password</h1>
        {submitted ? (
          <div>
            <p className="info">If an account exists with that email, a reset link has been sent. Check your inbox.</p>
            <Link to="/login">Back to login</Link>
          </div>
        ) : (
          <form onSubmit={handleSubmit}>
            <label>Email</label>
            <input
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
            />
            {error && <p className="error">{error}</p>}
            <button type="submit" disabled={busy}>
              {busy ? "Sending…" : "Send Reset Link"}
            </button>
            <Link to="/login" className="secondary" style={{ textAlign: "center", marginTop: 8 }}>
              Back to login
            </Link>
          </form>
        )}
      </div>
    </div>
  );
}