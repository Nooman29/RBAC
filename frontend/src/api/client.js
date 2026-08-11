import axios from "axios";

// In local dev (npm run dev), talk directly to the backend on :8000.
// In Docker, VITE_API_BASE_URL is baked in as "" at build time, so requests
// go to the same origin nginx serves from, and nginx proxies /api/* to the
// backend container — no CORS involved in that path at all.
const client = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000",
});

client.interceptors.request.use((config) => {
  const token = localStorage.getItem("access_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

export default client;