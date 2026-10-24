import { useEffect, useState } from "react";
import { Routes, Route, Navigate, useLocation } from "react-router-dom";
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
import Integrations from "./pages/Integrations";
import ForgotPassword from "./pages/ForgotPassword";
import ResetPassword from "./pages/ResetPassword";
import MyAccess from "./pages/MyAccess";
import ModelManagement from "./pages/ModelManagement";
import NotificationBell from "./components/NotificationBell";
import PermissionDeniedBanner from "./components/PermissionDeniedBanner";
import Sidebar, { Icon, buildNavGroups } from "./components/Sidebar";
import useIdleLogout from "./hooks/useIdleLogout";
import "./App.css";
import "./layout.css";

// Longest matching nav entry for the current path -> breadcrumb.
function findCrumb(pathname, groups) {
  let best = null;
  for (const group of groups) {
    for (const item of group.items) {
      const match = pathname === item.to || (item.to !== "/" && pathname.startsWith(item.to + "/"));
      if (match && (!best || item.to.length > best.item.to.length)) {
        best = { group: group.label, item };
      }
    }
  }
  return best;
}

function Layout({ children }) {
  const { can, loaded, scope } = usePermissions();
  const { pathname } = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  useIdleLogout();

  useEffect(() => {
    setSidebarOpen(false);
  }, [pathname]);

  const crumb = findCrumb(pathname, buildNavGroups(can, loaded, scope));

  return (
    <div className="ds-shell">
      <Sidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />
      {sidebarOpen && <div className="ds-overlay" onClick={() => setSidebarOpen(false)} />}

      <div className="ds-main">
        <PermissionDeniedBanner />
        <header className="ds-topbar">
          <button
            className="ds-menu-btn"
            onClick={() => setSidebarOpen(true)}
            aria-label="Open navigation"
          >
            <Icon name="menu" size={20} />
          </button>
          {crumb && (
            <div className="ds-crumb">
              <span>{crumb.group}</span>
              <span className="ds-crumb-sep">/</span>
              <strong>{crumb.item.label}</strong>
            </div>
          )}
          <div className="ds-topbar-right">
            <NotificationBell />
          </div>
        </header>
        <main className="ds-content">{children}</main>
      </div>
    </div>
  );
}

// Roles without the security dashboard (most DSFS roles: they work in the module apps)
// land on My Access instead of a dashboard they are not allowed to load.
function Home() {
  const { can, loaded } = usePermissions();
  if (!loaded) return <p>Loading…</p>;
  if (!can("dashboard", "read")) return <Navigate to="/my-access" replace />;
  return <Dashboard />;
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
          <Route path="/" element={<Wrapped><Home /></Wrapped>} />
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
          <Route path="/model" element={<Wrapped><ModelManagement /></Wrapped>} />
          <Route path="/integrations" element={<Wrapped><Integrations /></Wrapped>} />
          <Route path="/my-access" element={<Wrapped><MyAccess /></Wrapped>} />
          <Route path="/face-id-setup" element={<Wrapped><FaceEnroll /></Wrapped>} />
        </Routes>
      </PermissionsProvider>
    </AuthProvider>
  );
}

export default App;