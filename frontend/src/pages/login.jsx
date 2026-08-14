import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import FaceCapture from "../components/FaceCapture";
import { useLocation } from "react-router-dom";

export default function Login() {
  const { loginWithPassword, requestOtp, verifyOtp, verifyFace } = useAuth();
  const navigate = useNavigate();

  // "password" | "choose_method" | "face" | "otp"
  const [stage, setStage] = useState("password");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [pendingToken, setPendingToken] = useState(null);
  const [hasFaceOption, setHasFaceOption] = useState(false);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [faceBusy, setFaceBusy] = useState(false);
  const location = useLocation();
  const idleTimeout = location.state?.idleTimeout;

  async function handlePasswordSubmit(e) {
    e.preventDefault();
    setError("");
    try {
      const result = await loginWithPassword(username, password);

      if (result.status === "first_time_setup_required") {
        navigate("/first-time-setup", { state: { pendingToken: result.pendingToken } });
        return;
      }

      setPendingToken(result.pendingToken);
      setHasFaceOption(result.hasFaceOption);

      if (!result.hasFaceOption) {
        // Nothing enrolled — go straight to OTP, no dead-end "choose" screen
        await requestOtp(result.pendingToken);
        setInfo("Code sent — check your email.");
        setStage("otp");
      } else {
        setStage("choose_method");
      }
    } catch (err) {
      setError(err.response?.data?.detail || "Login failed");
    }
  }

  async function handleChooseFace() {
    setError("");
    setStage("face");
  }

  async function handleChooseOtp() {
    setError("");
    try {
      await requestOtp(pendingToken);
      setInfo("Code sent — check your email.");
      setStage("otp");
    } catch (err) {
      setError("Failed to send code");
    }
  }

  async function handleFaceCapture(imageBase64) {
    setError("");
    setFaceBusy(true);
    try {
      await verifyFace(pendingToken, imageBase64);
      navigate("/");
    } catch (err) {
      setError(err.response?.data?.detail || "Face verification failed. Try again or use email code.");
    } finally {
      setFaceBusy(false);
    }
  }

  async function handleOtpSubmit(e) {
    e.preventDefault();
    setError("");
    try {
      await verifyOtp(pendingToken, code);
      navigate("/");
    } catch (err) {
      setError(err.response?.data?.detail || "Incorrect or expired code");
    }
  }

  async function handleResend() {
    setError("");
    setInfo("");
    try {
      await requestOtp(pendingToken);
      setInfo("New code sent.");
    } catch (err) {
      setError("Failed to resend code");
    }
  }

  return (
    <div className="auth-screen">
      <div className="auth-card">
        <h1>RBAC Admin</h1>
        {idleTimeout && <p className="info">You were signed out after 20 minutes of inactivity.</p>}
        {stage === "password" && (
          <form onSubmit={handlePasswordSubmit}>
            <label>Username</label>
            <input value={username} onChange={(e) => setUsername(e.target.value)} required />
            <label>Password</label>
            <input
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
            {error && <p className="error">{error}</p>}
            <button type="submit">Continue</button>
          </form>
        )}

        {stage === "choose_method" && (
          <div>
            <p>Choose a verification method:</p>
            {error && <p className="error">{error}</p>}
            {hasFaceOption && (
              <button type="button" onClick={handleChooseFace}>
                Verify with Face ID
              </button>
            )}
            <button type="button" className="secondary" onClick={handleChooseOtp}>
              Verify with Email Code
            </button>
          </div>
        )}

        {stage === "face" && (
          <div>
            <p>Look at the camera and capture your face.</p>
            {error && <p className="error">{error}</p>}
            <FaceCapture onCapture={handleFaceCapture} onCancel={() => setStage("choose_method")} busy={faceBusy} />
            <button type="button" className="link-btn" onClick={handleChooseOtp}>
              Use email code instead
            </button>
          </div>
        )}

        {stage === "otp" && (
          <form onSubmit={handleOtpSubmit}>
            <p>Enter the 6-digit code sent to your email.</p>
            <label>Code</label>
            <input value={code} onChange={(e) => setCode(e.target.value)} required />
            {info && <p className="info">{info}</p>}
            {error && <p className="error">{error}</p>}
            <button type="submit">Verify</button>
            <button type="button" className="secondary" onClick={handleResend}>
              Resend code
            </button>
            {hasFaceOption && (
              <button type="button" className="link-btn" onClick={() => setStage("choose_method")}>
                Use Face ID instead
              </button>
            )}
          </form>
        )}
      </div>
    </div>
  );
}