import { createContext, useContext, useEffect, useState } from "react";
import client from "../api/client";
import { useAuth } from "./AuthContext";

const PermissionsContext = createContext(null);

export function PermissionsProvider({ children }) {
  const { token } = useAuth();
  const [permissions, setPermissions] = useState([]);
  const [username, setUsername] = useState(null);
  const [roleName, setRoleName] = useState(null);
  const [department, setDepartment] = useState(null);
  const [scope, setScope] = useState(null);
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    if (!token) {
      setPermissions([]);
      setUsername(null);
      setRoleName(null);
      setDepartment(null);
      setScope(null);
      setLoaded(false);
      return;
    }
    Promise.all([
      client.get("/api/auth/my-permissions"),
      // Data scope (global / school / department / organization / own); optional.
      client.get("/api/auth/my-access").catch(() => null),
    ])
      .then(([perms, access]) => {
        setPermissions(perms.data.permissions || []);
        setUsername(perms.data.username);
        setRoleName(perms.data.role_name);
        setDepartment(perms.data.department);
        setScope(access ? access.data.scope : null);
        setLoaded(true);
      })
      .catch(() => setLoaded(true));
  }, [token]);

  function can(resource, action) {
    return permissions.some((p) => p.resource_name === resource && p.action_type === action);
  }

  return (
    <PermissionsContext.Provider value={{ can, username, roleName, department, scope, loaded }}>
      {children}
    </PermissionsContext.Provider>
  );
}

export function usePermissions() {
  return useContext(PermissionsContext);
}