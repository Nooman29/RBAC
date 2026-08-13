import { useEffect, useState } from "react";

export default function PermissionDeniedBanner() {
  const [message, setMessage] = useState(null);

  useEffect(() => {
    function handler(e) {
      setMessage(e.detail);
      const timer = setTimeout(() => setMessage(null), 6000);
      return () => clearTimeout(timer);
    }
    window.addEventListener("permission-denied", handler);
    return () => window.removeEventListener("permission-denied", handler);
  }, []);

  if (!message) return null;

  return (
    <div className="permission-banner">
      <span className="permission-icon">🔒</span>
      <div>
        <strong>Access denied</strong>
        <p>{message}</p>
      </div>
      <button className="permission-close" onClick={() => setMessage(null)}>×</button>
    </div>
  );
}