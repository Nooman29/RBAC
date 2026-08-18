import axios from "axios";

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

client.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 403) {
      const detail = error.response.data?.detail || "You don't have permission to do that.";
      window.dispatchEvent(new CustomEvent("permission-denied", { detail }));
    }

    if (error.response?.status === 401) {
      const detail = error.response.data?.detail || "";
      if (detail.toLowerCase().includes("terminated")) {
        localStorage.removeItem("access_token");
        // Hard redirect — this runs outside React Router context, so a full
        // navigation is the reliable way to force the user back to login.
        window.location.href = "/login?terminated=1";
      }
    }

    return Promise.reject(error);
  }
);

export default client;