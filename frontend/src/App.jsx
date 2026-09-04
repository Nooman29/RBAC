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
import useIdleLogout from "./hooks/useIdleLogout";
import "./App.css";

function ProtectedRoute({ children }) {
  const { token } = useAuth();
  if (!token) return <Navigate to="/login" replace />;
  return children;
}

function Layout({ children }) {
  const { logout } = useAuth();
  const { username, roleName, department, loaded } = usePermissions();
  const navigate = useNavigate();
  useIdleLogout();

  async function handleLogout() {
    await logout();
    navigate("/login");
  }

  return (
    <div className="app-shell">
      <PermissionDeniedBanner />
      <nav className="navbar">
        <span className="brand">RBAC</span>
        {loaded && (
          <span className="identity-badge" title={department ? `Department: ${department}` : ""}>
            {username} · {roleName || "No role"}
          </span>
        )}
        <Link to="/">Dashboard</Link>
        <Link to="/sessions">Sessions</Link>
        <Link to="/alerts">Alerts</Link>
        <Link to="/users">Users</Link>
        <Link to="/roles">Roles</Link>
        <Link to="/simulate-attack">Simulate Attack</Link>
        <Link to="/roles-comparison">Compare Roles</Link>
        <Link to="/detection-outcomes">Detection Outcomes</Link>
        <Link to="/audit-log">Audit Log</Link>
        <Link to="/face-id-setup">Face ID Setup</Link>
        <NotificationBell />
        
        <button className="logout-btn" onClick={handleLogout}>Logout</button>
      </nav>
      <main className="content">{children}</main>
    </div>
  );
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