import { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

const IDLE_LIMIT_MS = 20 * 60 * 1000; // 20 minutes
const ACTIVITY_EVENTS = ["mousemove", "mousedown", "keydown", "scroll", "touchstart"];

export default function useIdleLogout() {
  const { logout, token } = useAuth();
  const navigate = useNavigate();
  const timerRef = useRef(null);

  useEffect(() => {
    if (!token) return;

    function resetTimer() {
      if (timerRef.current) clearTimeout(timerRef.current);
      timerRef.current = setTimeout(async () => {
        await logout();
        navigate("/login", { state: { idleTimeout: true } });
      }, IDLE_LIMIT_MS);
    }

    ACTIVITY_EVENTS.forEach((evt) => window.addEventListener(evt, resetTimer));
    resetTimer();

    return () => {
      ACTIVITY_EVENTS.forEach((evt) => window.removeEventListener(evt, resetTimer));
      if (timerRef.current) clearTimeout(timerRef.current);
    };
  }, [token]);
}