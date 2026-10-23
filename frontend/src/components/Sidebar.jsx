import { NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { usePermissions } from "../context/PermissionsContext";

const ICONS = {
  dashboard: (
    <>
      <rect x="3" y="3" width="7" height="7" rx="1" />
      <rect x="14" y="3" width="7" height="7" rx="1" />
      <rect x="14" y="14" width="7" height="7" rx="1" />
      <rect x="3" y="14" width="7" height="7" rx="1" />
    </>
  ),
  sessions: (
    <>
      <rect x="2" y="3" width="20" height="14" rx="2" />
      <line x1="8" y1="21" x2="16" y2="21" />
      <line x1="12" y1="17" x2="12" y2="21" />
    </>
  ),
  alerts: (
    <>
      <path d="M10.3 3.9L1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" />
      <line x1="12" y1="9" x2="12" y2="13" />
      <line x1="12" y1="17" x2="12.01" y2="17" />
    </>
  ),
  outcomes: (
    <>
      <line x1="18" y1="20" x2="18" y2="10" />
      <line x1="12" y1="20" x2="12" y2="4" />
      <line x1="6" y1="20" x2="6" y2="14" />
    </>
  ),
  audit: (
    <>
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
      <line x1="16" y1="13" x2="8" y2="13" />
      <line x1="16" y1="17" x2="8" y2="17" />
    </>
  ),
  simulate: <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />,
  users: (
    <>
      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
    </>
  ),
  roles: <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />,
  compare: (
    <>
      <rect x="3" y="3" width="18" height="18" rx="2" />
      <line x1="3" y1="9" x2="21" y2="9" />
      <line x1="9" y1="9" x2="9" y2="21" />
    </>
  ),
  integrations: (
    <>
      <path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71" />
      <path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71" />
    </>
  ),
  face: (
    <>
      <circle cx="12" cy="12" r="10" />
      <path d="M8 14s1.5 2 4 2 4-2 4-2" />
      <line x1="9" y1="9" x2="9.01" y2="9" />
      <line x1="15" y1="9" x2="15.01" y2="9" />
    </>
  ),
  access: (
    <>
      <circle cx="7.5" cy="15.5" r="4.5" />
      <path d="M10.7 12.3 21 2" />
      <path d="M16 7l3 3" />
      <path d="M19 4l2 2" />
    </>
  ),
  logout: (
    <>
      <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
      <polyline points="16 17 21 12 16 7" />
      <line x1="21" y1="12" x2="9" y2="12" />
    </>
  ),
  menu: (
    <>
      <line x1="3" y1="12" x2="21" y2="12" />
      <line x1="3" y1="6" x2="21" y2="6" />
      <line x1="3" y1="18" x2="21" y2="18" />
    </>
  ),
};

export function Icon({ name, size = 18 }) {
  return (
    <svg
      className="ds-icon"
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {ICONS[name]}
    </svg>
  );
}

// Single source of truth for navigation: used by the sidebar and the top-bar breadcrumb.
export function buildNavGroups(can, loaded) {
  const allow = (resource, action) => Boolean(loaded && can && can(resource, action));

  const groups = [
    {
      label: "Overview",
      items: [{ to: "/", label: "Dashboard", icon: "dashboard", end: true, show: allow("dashboard", "read") }],
    },
    {
      label: "Security",
      items: [
        { to: "/sessions", label: "Sessions", icon: "sessions", show: allow("dashboard", "read") },
        { to: "/alerts", label: "Alerts", icon: "alerts", show: allow("dashboard", "read") },
        { to: "/detection-outcomes", label: "Detection Outcomes", icon: "outcomes", show: allow("dashboard", "read") },
        { to: "/audit-log", label: "Audit Log", icon: "audit", show: allow("dashboard", "read") },
        { to: "/simulate-attack", label: "Simulate Attack", icon: "simulate", show: allow("dashboard", "write") },
      ],
    },
    {
      label: "Access control",
      items: [
        { to: "/users", label: "Users", icon: "users", show: allow("user", "read") },
        { to: "/roles", label: "Roles", icon: "roles", show: allow("role", "read") },
        { to: "/roles-comparison", label: "Compare Roles", icon: "compare", show: allow("role", "read") },
      ],
    },
    {
      label: "Integrations",
      items: [
        {
          to: "/integrations",
          label: "Integrations",
          icon: "integrations",
          show: allow("service_client", "read") || allow("fraud", "read"),
        },
      ],
    },
    {
      label: "Account",
      items: [
        { to: "/my-access", label: "My Access", icon: "access", show: true },
        { to: "/face-id-setup", label: "Face ID Setup", icon: "face", show: true },
      ],
    },
  ];

  return groups
    .map((g) => ({ ...g, items: g.items.filter((i) => i.show) }))
    .filter((g) => g.items.length > 0);
}

export default function Sidebar({ open, onClose }) {
  const { logout } = useAuth();
  const { can, username, roleName, department, loaded } = usePermissions();
  const navigate = useNavigate();
  const groups = buildNavGroups(can, loaded);

  async function handleLogout() {
    await logout();
    navigate("/login");
  }

  return (
    <aside className={`ds-sidebar${open ? " open" : ""}`}>
      <div className="ds-brand">
        <span className="ds-brand-mark">
          <Icon name="roles" size={20} />
        </span>
        <div>
          <div className="ds-brand-name">RBAC</div>
          <div className="ds-brand-sub">Access control</div>
        </div>
      </div>

      <nav className="ds-nav">
        {groups.map((group) => (
          <div key={group.label}>
            <div className="ds-nav-label">{group.label}</div>
            {group.items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.end}
                onClick={onClose}
                className={({ isActive }) => `ds-nav-item${isActive ? " active" : ""}`}
              >
                <Icon name={item.icon} />
                <span>{item.label}</span>
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      {loaded && (
        <div className="ds-user" title={department ? `Department: ${department}` : ""}>
          <div className="ds-avatar">{(username || "?").charAt(0).toUpperCase()}</div>
          <div className="ds-user-meta">
            <div className="ds-user-name">{username}</div>
            <div className="ds-user-role">{roleName || "No role"}</div>
          </div>
          <button className="ds-logout" onClick={handleLogout} title="Log out" aria-label="Log out">
            <Icon name="logout" />
          </button>
        </div>
      )}
    </aside>
  );
}