import { createContext, useContext, useState } from "react";
import client from "../api/client";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [token, setToken] = useState(localStorage.getItem("access_token"));

  async function loginWithPassword(username, password) {
    const form = new URLSearchParams();
    form.append("username", username);
    form.append("password", password);

    const res = await client.post("/api/auth/login", form, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });

    if (res.data.status === "first_time_setup_required") {
      return { status: "first_time_setup_required", pendingToken: res.data.pending_token };
    }

    return {
      status: "2fa_required",
      pendingToken: res.data.pending_token,
      hasFaceOption: res.data.has_face_option,
    };
  }

  async function requestOtp(pendingToken) {
    await client.post("/api/auth/request-otp", { pending_token: pendingToken });
  }

  async function verifyOtp(pendingToken, code) {
    const res = await client.post(
      `/api/auth/verify-otp?code=${encodeURIComponent(code)}`,
      { pending_token: pendingToken }
    );
    // Users who have not chosen Face ID yet go on to first-time setup once the code is verified
    if (res.data.status === "first_time_setup_required") {
      return { status: "first_time_setup_required", pendingToken: res.data.pending_token };
    }
    setToken(res.data.access_token);
    localStorage.setItem("access_token", res.data.access_token);
    return { status: "signed_in" };
  }

  async function verifyFace(pendingToken, imageBase64) {
    const res = await client.post("/api/auth/verify-face", {
      pending_token: pendingToken,
      image_base64: imageBase64,
    });
    setToken(res.data.access_token);
    localStorage.setItem("access_token", res.data.access_token);
  }

  async function setupPassword(setupToken, newPassword) {
    const res = await client.post("/api/auth/setup-password", {
      token: setupToken,
      new_password: newPassword,
    });
    return res.data.pending_token; // caller routes into first-time-setup with this
  }

  async function completeBiometricSetup(pendingToken, imageBase64) {
    const res = await client.post("/api/auth/complete-biometric-setup", {
      pending_token: pendingToken,
      image_base64: imageBase64,
    });
    setToken(res.data.access_token);
    localStorage.setItem("access_token", res.data.access_token);
  }

  async function skipBiometricSetup(pendingToken) {
    const res = await client.post("/api/auth/skip-biometric-setup", {
      pending_token: pendingToken,
    });
    setToken(res.data.access_token);
    localStorage.setItem("access_token", res.data.access_token);
  }

  async function fetchMe() {
    const res = await client.get("/api/auth/me");
    return res.data;
  }

  async function logout() {
    try {
      await client.post("/api/auth/logout");
    } catch {
      // signed out locally even if the server is unreachable or the session already ended
    }
    setToken(null);
    localStorage.removeItem("access_token");
  }

  return (
    <AuthContext.Provider
      value={{
        token,
        loginWithPassword,
        requestOtp,
        verifyOtp,
        verifyFace,
        setupPassword,
        completeBiometricSetup,
        skipBiometricSetup,
        fetchMe,
        logout,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}