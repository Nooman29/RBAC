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
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    if (!token) {
      setPermissions([]);
      setUsername(null);
      setRoleName(null);
      setDepartment(null);
      setLoaded(false);
      return;
    }
    client
      .get("/api/auth/my-permissions")
      .then((res) => {
        setPermissions(res.data.permissions || []);
        setUsername(res.data.username);
        setRoleName(res.data.role_name);
        setDepartment(res.data.department);
        setLoaded(true);
      })
      .catch(() => setLoaded(true));
  }, [token]);

  function can(resource, action) {
    return permissions.some((p) => p.resource_name === resource && p.action_type === action);
  }

  return (
    <PermissionsContext.Provider value={{ can, username, roleName, department, loaded }}>
      {children}
    </PermissionsContext.Provider>
  );
}

export function usePermissions() {
  return useContext(PermissionsContext);
}