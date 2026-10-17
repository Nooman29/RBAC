import { useState } from "react";
import { useLocation, useNavigate, Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import FaceCapture from "../components/FaceCapture";
import AuthShell from "../components/AuthShell";
import { Icon } from "../components/Sidebar";

function MailIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="2" y="4" width="20" height="16" rx="2" />
      <polyline points="22 6 12 13 2 6" />
    </svg>
  );
}

export default function FirstTimeSetup() {
  const location = useLocation();
  const navigate = useNavigate();
  const { completeBiometricSetup, skipBiometricSetup } = useAuth();

  const pendingToken = location.state?.pendingToken;
  const [mode, setMode] = useState("choose"); // "choose" | "face"
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  if (!pendingToken) {
    return (
      <AuthShell title="Session expired" subtitle="Please log in again to continue setup.">
        <Link to="/login" className="auth-link">Back to login</Link>
      </AuthShell>
    );
  }

  async function handleFaceCapture(imageBase64) {
    setError("");
    setBusy(true);
    try {
      await completeBiometricSetup(pendingToken, imageBase64);
      navigate("/");
    } catch (err) {
      setError(err.response?.data?.detail || "Face enrollment failed. Try again or skip with email code.");
    } finally {
      setBusy(false);
    }
  }

  async function handleSkip() {
    setError("");
    setBusy(true);
    try {
      await skipBiometricSetup(pendingToken);
      navigate("/");
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to complete setup.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <AuthShell
      title="Set up sign-in verification"
      subtitle="Required before you can access your account. Choose how you'll confirm it's you each time you sign in."
    >
      <div className="auth-steps">
        <div className="auth-step on">1 · Password</div>
        <div className="auth-step on">2 · Verification setup</div>
      </div>

      {error && <p className="auth-alert auth-alert-error" role="alert">{error}</p>}

      {mode === "choose" && (
        <div className="auth-options">
          <button type="button" className="auth-option" onClick={() => setMode("face")} disabled={busy}>
            <span className="auth-option-icon"><Icon name="face" size={22} /></span>
            <span>
              <strong>Set up Face ID</strong>
              <small>Fastest sign-in. Needs camera access in your browser.</small>
            </span>
          </button>
          <button type="button" className="auth-option" onClick={handleSkip} disabled={busy}>
            <span className="auth-option-icon"><MailIcon /></span>
            <span>
              <strong>{busy ? "Setting up…" : "Use email codes instead"}</strong>
              <small>No camera needed. We'll email a 6-digit code at each sign-in.</small>
            </span>
          </button>
        </div>
      )}

      {mode === "face" && (
        <div>
          <FaceCapture onCapture={handleFaceCapture} onCancel={() => setMode("choose")} busy={busy} />
          <button type="button" className="auth-link" onClick={handleSkip} disabled={busy}>
            I don't have camera access. Use email code instead
          </button>
        </div>
      )}
    </AuthShell>
  );
}