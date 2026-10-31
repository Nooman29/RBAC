import { useEffect, useState, useRef } from "react";
import { Link } from "react-router-dom";
import client from "../api/client";
import { parseUtc } from "../utils/date";

// Interface actions are reported to the audit log. Polling is never reported.
function reportUi(action) {
  client.post("/api/audit/ui-event", { component: "Notifications", action }).catch(() => {});
}

export default function NotificationBell() {
  const [unreadCount, setUnreadCount] = useState(0);
  const [notifications, setNotifications] = useState([]);
  const [open, setOpen] = useState(false);
  const dropdownRef = useRef(null);

  async function fetchUnreadCount() {
    try {
      const res = await client.get("/api/notifications/unread-count");
      setUnreadCount(res.data.unread_count);
    } catch (e) {
      // ignore transient poll failures
    }
  }

  async function fetchNotifications() {
    try {
      const res = await client.get("/api/notifications");
      setNotifications(res.data);
    } catch (e) {}
  }

  useEffect(() => {
    fetchUnreadCount();
    const interval = setInterval(fetchUnreadCount, 15000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    function handleClickOutside(e) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target)) {
        setOpen(false);
      }
    }
    document.addEventListener("mousedown", handleClickOutside);
    return () => document.removeEventListener("mousedown", handleClickOutside);
  }, []);

  async function toggleOpen() {
    const next = !open;
    setOpen(next);
    if (next) {
      reportUi("opened");
      await fetchNotifications();
    }
  }

  async function markAllRead() {
    await client.post("/api/notifications/read-all");
    reportUi("marked_all_read");
    setUnreadCount(0);
    setNotifications((prev) => prev.map((n) => ({ ...n, is_read: true })));
  }

  async function markOneRead(id) {
    await client.post(`/api/notifications/${id}/read`);
    setNotifications((prev) =>
      prev.map((n) => (n.notification_id === id ? { ...n, is_read: true } : n))
    );
    setUnreadCount((c) => Math.max(0, c - 1));
  }

  return (
    <div className="notif-bell" ref={dropdownRef}>
      <button onClick={toggleOpen} className="bell-btn">
        🔔 {unreadCount > 0 && <span className="notif-count">{unreadCount}</span>}
      </button>
      {open && (
        <div className="notif-dropdown">
          <div className="notif-header">
            <strong>Notifications</strong>
            {unreadCount > 0 && (
              <button onClick={markAllRead} className="mark-all-link">
                Mark all read
              </button>
            )}
          </div>
          {notifications.length === 0 && <p className="notif-empty">No notifications</p>}
          {notifications.map((n) => (
            <Link
              key={n.notification_id}
              to={n.alert_id ? `/alerts/${n.alert_id}` : n.live_alert_id ? "/alerts#live" : "/alerts"}
              className={`notif-item ${n.is_read ? "" : "unread"}`}
              onClick={() => {
                reportUi("opened_item");
                if (!n.is_read) markOneRead(n.notification_id);
                setOpen(false);
              }}
            >
              <div className="notif-title">{n.title}</div>
              <div className="notif-body">{n.body}</div>
              <div className="notif-time">{parseUtc(n.created_at).toLocaleString()}</div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}