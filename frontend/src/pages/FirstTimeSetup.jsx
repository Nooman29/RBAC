import { useState } from "react";
import { useLocation, useNavigate, Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import FaceCapture from "../components/FaceCapture";

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
      <div className="auth-screen">
        <div className="auth-card">
          <h1>Session Expired</h1>
          <p className="muted">Please log in again to continue setup.</p>
          <Link to="/login">Back to login</Link>
        </div>
      </div>
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
    <div className="auth-screen">
      <div className="auth-card">
        <h1>Set Up Sign-In Verification</h1>
        <p className="muted">
          This is required before you can access your account. Enroll Face ID for quick sign-in,
          or use an email code if you don't have camera access.
        </p>

        {error && <p className="error">{error}</p>}

        {mode === "choose" && (
          <div>
            <button type="button" onClick={() => setMode("face")}>
              Set Up Face ID
            </button>
            <button type="button" className="secondary" onClick={handleSkip} disabled={busy}>
              {busy ? "Setting up…" : "No camera access — use email code"}
            </button>
          </div>
        )}

        {mode === "face" && (
          <div>
            <FaceCapture onCapture={handleFaceCapture} onCancel={() => setMode("choose")} busy={busy} />
            <button type="button" className="link-btn" onClick={handleSkip}>
              I don't have camera access — use email code instead
            </button>
          </div>
        )}
      </div>
    </div>
  );
}