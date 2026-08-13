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

    // First-time users with no biometric enrolled get a real token directly
    if (res.data.access_token) {
      setToken(res.data.access_token);
      localStorage.setItem("access_token", res.data.access_token);
      return { status: "logged_in" };
    }

    // Otherwise it's the 2FA path
    return { status: "2fa_required", pendingToken: res.data.pending_token };
  }

  async function requestOtp(pendingToken) {
    await client.post("/api/auth/request-otp", { pending_token: pendingToken });
  }

  async function verifyOtp(pendingToken, code) {
    const res = await client.post(
      `/api/auth/verify-otp?code=${encodeURIComponent(code)}`,
      { pending_token: pendingToken }
    );
    setToken(res.data.access_token);
    localStorage.setItem("access_token", res.data.access_token);
  }

  async function verifyFace(pendingToken, imageBase64) {
    const res = await client.post("/api/auth/verify-face", {
      pending_token: pendingToken,
      image_base64: imageBase64,
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
    } catch (e) {
      // even if this fails, clear local state so the user isn't stuck
    }
    setToken(null);
    localStorage.removeItem("access_token");
  }

   return (
    <AuthContext.Provider
      value={{ token, loginWithPassword, requestOtp, verifyOtp, verifyFace, fetchMe, logout }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}