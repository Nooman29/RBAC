import { useEffect, useState } from "react";
import { useNavigate, useLocation, useSearchParams, Link } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import FaceCapture from "../components/FaceCapture";
import AuthShell from "../components/AuthShell";
import { Icon } from "../components/Sidebar";

const OTP_COOLDOWN_SECONDS = 30;

const STAGE_COPY = {
  password: { title: "Welcome back", subtitle: "Sign in to manage access across the feeding programme." },
  choose_method: { title: "Verify it's you", subtitle: "Choose how you'd like to confirm this sign-in." },
  face: { title: "Face verification", subtitle: "Look at the camera and capture your face." },
  otp: { title: "Check your email", subtitle: "Enter the 6-digit code we sent you." },
};

function MailIcon() {
  return (
    <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <rect x="2" y="4" width="20" height="16" rx="2" />
      <polyline points="22 6 12 13 2 6" />
    </svg>
  );
}

function Steps({ stage }) {
  return (
    <div className="auth-steps">
      <div className="auth-step on">1 · Password</div>
      <div className={`auth-step${stage !== "password" ? " on" : ""}`}>2 · Verification</div>
    </div>
  );
}

export default function Login() {
  const { loginWithPassword, requestOtp, verifyOtp, verifyFace } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();

  // "password" | "choose_method" | "face" | "otp"
  const [stage, setStage] = useState("password");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [code, setCode] = useState("");
  const [pendingToken, setPendingToken] = useState(null);
  const [hasFaceOption, setHasFaceOption] = useState(false);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [busy, setBusy] = useState(false);
  const [faceBusy, setFaceBusy] = useState(false);
  const [cooldown, setCooldown] = useState(0);

  const wasTerminated = searchParams.get("terminated") === "1";
  const idleTimeout = location.state?.idleTimeout;

  useEffect(() => {
    if (cooldown <= 0) return undefined;
    const timer = setTimeout(() => setCooldown((c) => c - 1), 1000);
    return () => clearTimeout(timer);
  }, [cooldown]);

  async function handlePasswordSubmit(e) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      const result = await loginWithPassword(username, password);

      if (result.status === "first_time_setup_required") {
        navigate("/first-time-setup", { state: { pendingToken: result.pendingToken } });
        return;
      }

      setPendingToken(result.pendingToken);
      setHasFaceOption(result.hasFaceOption);

      if (!result.hasFaceOption) {
        // Nothing enrolled: go straight to OTP, no dead-end "choose" screen
        await requestOtp(result.pendingToken);
        setInfo("Code sent. Check your email.");
        setCooldown(OTP_COOLDOWN_SECONDS);
        setStage("otp");
      } else {
        setStage("choose_method");
      }
    } catch (err) {
      setError(err.response?.data?.detail || "Login failed");
    } finally {
      setBusy(false);
    }
  }

  function handleChooseFace() {
    setError("");
    setStage("face");
  }

  async function handleChooseOtp() {
    setError("");
    setBusy(true);
    try {
      await requestOtp(pendingToken);
      setInfo("Code sent. Check your email.");
      setCooldown(OTP_COOLDOWN_SECONDS);
      setStage("otp");
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to send code");
    } finally {
      setBusy(false);
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
    setBusy(true);
    try {
      await verifyOtp(pendingToken, code);
      navigate("/");
    } catch (err) {
      setError(err.response?.data?.detail || "Incorrect or expired code");
    } finally {
      setBusy(false);
    }
  }

  async function handleResend() {
    setError("");
    setInfo("");
    try {
      await requestOtp(pendingToken);
      setInfo("New code sent.");
      setCooldown(OTP_COOLDOWN_SECONDS);
    } catch (err) {
      setError(err.response?.data?.detail || "Failed to resend code");
    }
  }

  function startOver() {
    setStage("password");
    setPendingToken(null);
    setHasFaceOption(false);
    setPassword("");
    setCode("");
    setError("");
    setInfo("");
    setCooldown(0);
  }

  const copy = STAGE_COPY[stage];

  return (
    <AuthShell title={copy.title} subtitle={copy.subtitle}>
      <Steps stage={stage} />

      {idleTimeout && (
        <p className="auth-alert auth-alert-info" role="status">You were signed out after 20 minutes of inactivity.</p>
      )}
      {wasTerminated && (
        <p className="auth-alert auth-alert-error" role="alert">
          Your session was terminated by an administrator. Please log in again.
        </p>
      )}

      {stage === "password" && (
        <form onSubmit={handlePasswordSubmit}>
          <label htmlFor="login-username">Username</label>
          <input
            id="login-username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            autoFocus
            required
          />
          <label htmlFor="login-password">Password</label>
          <div className="auth-password">
            <input
              id="login-password"
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              autoComplete="current-password"
              required
            />
            <button type="button" className="auth-toggle" onClick={() => setShowPassword((s) => !s)}>
              {showPassword ? "Hide" : "Show"}
            </button>
          </div>
          {error && <p className="auth-alert auth-alert-error" role="alert">{error}</p>}
          <button type="submit" disabled={busy}>{busy ? "Signing in…" : "Continue"}</button>
          <Link to="/forgot-password" className="auth-secondary">Forgot password?</Link>
        </form>
      )}

      {stage === "choose_method" && (
        <div>
          {error && <p className="auth-alert auth-alert-error" role="alert">{error}</p>}
          <div className="auth-options">
            {hasFaceOption && (
              <button type="button" className="auth-option" onClick={handleChooseFace}>
                <span className="auth-option-icon"><Icon name="face" size={22} /></span>
                <span>
                  <strong>Face ID</strong>
                  <small>Fastest option. Uses your camera.</small>
                </span>
              </button>
            )}
            <button type="button" className="auth-option" onClick={handleChooseOtp} disabled={busy}>
              <span className="auth-option-icon"><MailIcon /></span>
              <span>
                <strong>Email code</strong>
                <small>We'll send a 6-digit code to your email.</small>
              </span>
            </button>
          </div>
          <button type="button" className="secondary" onClick={startOver}>Use a different account</button>
        </div>
      )}

      {stage === "face" && (
        <div>
          {error && <p className="auth-alert auth-alert-error" role="alert">{error}</p>}
          <FaceCapture onCapture={handleFaceCapture} onCancel={() => setStage("choose_method")} busy={faceBusy} />
          <button type="button" className="secondary" onClick={handleChooseOtp}>
            Use email code instead
          </button>
        </div>
      )}

      {stage === "otp" && (
        <form onSubmit={handleOtpSubmit}>
          <label htmlFor="login-code">Verification code</label>
          <input
            id="login-code"
            className="auth-otp"
            value={code}
            onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
            inputMode="numeric"
            autoComplete="one-time-code"
            maxLength={6}
            placeholder="000000"
            autoFocus
            required
          />
          {info && <p className="auth-alert auth-alert-info" role="status">{info}</p>}
          {error && <p className="auth-alert auth-alert-error" role="alert">{error}</p>}
          <button type="submit" disabled={busy || code.length < 6}>{busy ? "Verifying…" : "Verify"}</button>
          <button type="button" className="secondary" onClick={handleResend} disabled={cooldown > 0}>
            {cooldown > 0 ? `Resend code (${cooldown}s)` : "Resend code"}
          </button>
          {hasFaceOption && (
            <button type="button" className="secondary" onClick={() => setStage("choose_method")}>
              Use Face ID instead
            </button>
          )}
          <button type="button" className="secondary" onClick={startOver}>Use a different account</button>
        </form>
      )}
    </AuthShell>
  );
}