import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function Login() {
  const { loginWithPassword, requestOtp, verifyOtp } = useAuth();
  const navigate = useNavigate();

  const [stage, setStage] = useState("password"); // "password" | "otp"
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [pendingToken, setPendingToken] = useState(null);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");

  async function handlePasswordSubmit(e) {
    e.preventDefault();
    setError("");
    try {
      const result = await loginWithPassword(username, password);
      if (result.status === "logged_in") {
        navigate("/");
        return;
      }
      setPendingToken(result.pendingToken);
      await requestOtp(result.pendingToken);
      setInfo("Code sent — check your email.");
      setStage("otp");
    } catch (err) {
      setError(err.response?.data?.detail || "Login failed");
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
          </form>
        )}
      </div>
    </div>
  );
}