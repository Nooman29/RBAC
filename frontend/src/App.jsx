import { Routes, Route, Navigate, Link, useNavigate } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext";
import { PermissionsProvider, usePermissions } from "./context/PermissionsContext";
import Login from "./pages/Login";
import SetupPassword from "./pages/SetupPassword";
import FirstTimeSetup from "./pages/FirstTimeSetup";
import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import AlertDetail from "./pages/AlertDetail";
import Users from "./pages/Users";
import Roles from "./pages/Roles";
import RoleDetail from "./pages/RoleDetail";
import RoleComparison from "./pages/RoleComparison";
import Sessions from "./pages/Sessions";
import AuditLog from "./pages/AuditLog";
import FaceEnroll from "./pages/FaceEnroll";
import SimulateAttack from "./pages/SimulateAttack";
import DetectionOutcomes from "./pages/DetectionOutcomes";
import NotificationBell from "./components/NotificationBell";
import PermissionDeniedBanner from "./components/PermissionDeniedBanner";
import NavMore from "./components/NavMore";
import useIdleLogout from "./hooks/useIdleLogout";
import "./App.css";
import { NavLink } from "react-router-dom";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword from "./pages/ResetPassword";

function Layout({ children }) {
  const { logout } = useAuth();
  const { can, username, roleName, department, loaded } = usePermissions();
  const navigate = useNavigate();
  useIdleLogout();

  async function handleLogout() {
    await logout();
    navigate("/login");
  }

  const links = [
    { to: "/", label: "Dashboard", show: true, end: true },
    { to: "/sessions", label: "Sessions", show: loaded && can && can("dashboard", "read") },
    { to: "/alerts", label: "Alerts", show: loaded && can && can("dashboard", "read") },
    { to: "/users", label: "Users", show: loaded && can && can("user", "read") },
    { to: "/roles", label: "Roles", show: loaded && can && can("role", "read") },
    { to: "/roles-comparison", label: "Compare Roles", show: loaded && can && can("role", "read") },
    { to: "/simulate-attack", label: "Simulate Attack", show: loaded && can && can("dashboard", "write") },
    { to: "/detection-outcomes", label: "Detection Outcomes", show: loaded && can && can("dashboard", "read") },
    { to: "/audit-log", label: "Audit Log", show: loaded && can && can("dashboard", "read") },
    { to: "/face-id-setup", label: "Face ID Setup", show: true },
  ];

  return (
    <div className="app-shell">
      <PermissionDeniedBanner />
      <nav className="navbar">
        <div className="nav-left">
          <span className="brand">RBAC</span>
          {links.filter((l) => l.show).map((l) => (
            <NavLink
              key={l.to}
              to={l.to}
              end={l.end}
              className={({ isActive }) => `nav-tab${isActive ? " nav-tab-active" : ""}`}
            >
              {l.label}
            </NavLink>
          ))}
        </div>
        <div className="nav-right">
          <NotificationBell />
          {loaded && (
            <span className="identity-badge" title={department ? `Department: ${department}` : ""}>
              {username} · {roleName || "No role"}
            </span>
          )}
          <button className="logout-btn" onClick={handleLogout}>Logout</button>
        </div>
      </nav>
      <main className="content">{children}</main>
    </div>
  );
}

function ProtectedRoute({ children }) {
  const { token } = useAuth();
  if (!token) return <Navigate to="/login" replace />;
  return children;
}


function Wrapped({ children }) {
  return (
    <ProtectedRoute>
      <Layout>{children}</Layout>
    </ProtectedRoute>
  );
}

function App() {
  return (
    <AuthProvider>
      <PermissionsProvider>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/setup-password" element={<SetupPassword />} />
          <Route path="/first-time-setup" element={<FirstTimeSetup />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password" element={<ResetPassword />} />
          <Route path="/" element={<Wrapped><Dashboard /></Wrapped>} />
          <Route path="/sessions" element={<Wrapped><Sessions /></Wrapped>} />
          <Route path="/alerts" element={<Wrapped><Alerts /></Wrapped>} />
          <Route path="/alerts/:alertId" element={<Wrapped><AlertDetail /></Wrapped>} />
          <Route path="/users" element={<Wrapped><Users /></Wrapped>} />
          <Route path="/roles" element={<Wrapped><Roles /></Wrapped>} />
          <Route path="/roles/:roleId" element={<Wrapped><RoleDetail /></Wrapped>} />
          <Route path="/roles-comparison" element={<Wrapped><RoleComparison /></Wrapped>} />
          <Route path="/detection-outcomes" element={<Wrapped><DetectionOutcomes /></Wrapped>} />
          <Route path="/simulate-attack" element={<Wrapped><SimulateAttack /></Wrapped>} />
          <Route path="/audit-log" element={<Wrapped><AuditLog /></Wrapped>} />
          <Route path="/face-id-setup" element={<Wrapped><FaceEnroll /></Wrapped>} />
        </Routes>
      </PermissionsProvider>
    </AuthProvider>
  );
}

export default App;