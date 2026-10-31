import { useState } from "react";
import client from "../api/client";
import FaceCapture from "../components/FaceCapture";

export default function FaceEnroll() {
  const [status, setStatus] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [capturing, setCapturing] = useState(true);

  async function handleCapture(imageBase64) {
    setError("");
    setBusy(true);
    try {
      await client.post("/api/auth/enroll-face", { image_base64: imageBase64 });
      setStatus("Face ID enrolled successfully. You can now log in using Face ID.");
      setCapturing(false);
    } catch (err) {
      setError(err.response?.data?.detail || "No face detected — try again with better lighting.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div>
      <h2>Face ID Setup</h2>
      <p className="muted">
        Enroll your face to enable biometric login. You can re-enroll at any time to replace it.
      </p>
      {error && <p className="error">{error}</p>}
      {status && <p className="info">{status}</p>}
      {capturing && (
        <FaceCapture onCapture={handleCapture} onCancel={() => {}} busy={busy} />
      )}
      {!capturing && (
        <button className="ds-btn ds-btn-primary" onClick={() => { setCapturing(true); setStatus(""); }}>Re-enroll</button>
      )}
    </div>
  );
}