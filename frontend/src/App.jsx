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
      <nav className="navbar">
        <span className="brand">RBAC Admin</span>
        <Link to="/">Dashboard</Link>
        <Link to="/sessions">Sessions</Link>
        <Link to="/alerts">Alerts</Link>
        <Link to="/users">Users</Link>
        <Link to="/roles">Roles</Link>
        <Link to="/audit-log">Audit Log</Link>
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
      </Routes>
    </AuthProvider>
  );
}

export default App;