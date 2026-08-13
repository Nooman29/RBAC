import { Routes, Route, Navigate, Link, useNavigate } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext";
import Login from "./pages/Login";
import Dashboard from "./pages/Dashboard";
import Alerts from "./pages/Alerts";
import AlertDetail from "./pages/AlertDetail";
import Users from "./pages/Users";
import Roles from "./pages/Roles";
import RoleDetail from "./pages/RoleDetail";
import Sessions from "./pages/Sessions";
import AuditLog from "./pages/AuditLog";
import "./App.css";
import NotificationBell from "./components/NotificationBell";
import FaceEnroll from "./pages/FaceEnroll";
import RoleComparison from "./pages/RoleComparison";
import PermissionDeniedBanner from "./components/PermissionDeniedBanner";
import SetupPassword from "./pages/SetupPassword";
import FirstTimeSetup from "./pages/FirstTimeSetup";

function ProtectedRoute({ children }) {
  const { token } = useAuth();
  if (!token) return <Navigate to="/login" replace />;
  return children;
}

function Layout({ children }) {
  const { logout } = useAuth();
  const navigate = useNavigate();

  async function handleLogout() {
    await logout();
    navigate("/login");
  }

  return (
    <div className="app-shell">
      <PermissionDeniedBanner />
      <nav className="navbar">
        <span className="brand">RBAC Admin</span>
        <Link to="/">Dashboard</Link>
        <Link to="/sessions">Sessions</Link>
        <Link to="/alerts">Alerts</Link>
        <Link to="/users">Users</Link>
        <Link to="/roles">Roles</Link>
        <Link to="/roles-comparison">Compare Roles</Link>
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
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route path="/" element={<Wrapped><Dashboard /></Wrapped>} />
        <Route path="/sessions" element={<Wrapped><Sessions /></Wrapped>} />
        <Route path="/alerts" element={<Wrapped><Alerts /></Wrapped>} />
        <Route path="/alerts/:alertId" element={<Wrapped><AlertDetail /></Wrapped>} />
        <Route path="/users" element={<Wrapped><Users /></Wrapped>} />
        <Route path="/roles" element={<Wrapped><Roles /></Wrapped>} />
        <Route path="/roles/:roleId" element={<Wrapped><RoleDetail /></Wrapped>} />
        <Route path="/audit-log" element={<Wrapped><AuditLog /></Wrapped>} />
        <Route path="/roles-comparison" element={<Wrapped><RoleComparison /></Wrapped>} />
        <Route path="/face-id-setup" element={<Wrapped><FaceEnroll /></Wrapped>} />
        <Route path="/setup-password" element={<SetupPassword />} />
        <Route path="/first-time-setup" element={<FirstTimeSetup />} />
      </Routes>
    </AuthProvider>
  );
}

export default App;