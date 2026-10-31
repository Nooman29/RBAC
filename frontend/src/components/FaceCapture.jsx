import { useEffect, useRef, useState } from "react";

export default function FaceCapture({ onCapture, onCancel, busy }) {
  const videoRef = useRef(null);
  const canvasRef = useRef(null);
  const streamRef = useRef(null);
  const [cameraError, setCameraError] = useState("");

  useEffect(() => {
    async function startCamera() {
      try {
        const stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: "user" } });
        streamRef.current = stream;
        if (videoRef.current) {
          videoRef.current.srcObject = stream;
        }
      } catch (err) {
        setCameraError("Could not access camera. Check browser permissions.");
      }
    }
    startCamera();

    return () => {
      if (streamRef.current) {
        streamRef.current.getTracks().forEach((t) => t.stop());
      }
    };
  }, []);

  function handleCapture() {
    const video = videoRef.current;
    const canvas = canvasRef.current;
    if (!video || !canvas) return;

    canvas.width = video.videoWidth;
    canvas.height = video.videoHeight;
    const ctx = canvas.getContext("2d");
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);

    // toDataURL gives "data:image/jpeg;base64,...." — strip the prefix before sending
    const dataUrl = canvas.toDataURL("image/jpeg", 0.9);
    const base64 = dataUrl.split(",")[1];
    onCapture(base64);
  }

  return (
    <div className="face-capture">
      {cameraError && <p className="error">{cameraError}</p>}
      <video ref={videoRef} autoPlay playsInline muted className="face-video" />
      <canvas ref={canvasRef} style={{ display: "none" }} />
      <div className="face-capture-actions">
        <button type="button" className="ds-btn ds-btn-primary" onClick={handleCapture} disabled={busy || !!cameraError}>
          {busy ? "Verifying…" : "Capture"}
        </button>
        <button type="button" className="ds-btn secondary" onClick={onCancel} disabled={busy}>
          Cancel
        </button>
      </div>
    </div>
  );
}