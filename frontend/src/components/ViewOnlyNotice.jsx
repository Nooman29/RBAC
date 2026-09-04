import { usePermissions } from "../context/PermissionsContext";

export default function ViewOnlyNotice({ resource, label }) {
  const { can, loaded } = usePermissions();
  if (!loaded || !can) return null;
  if (can(resource, "write")) return null;
  return (
    <div className="view-only-notice">
      <span className="view-only-icon">👁</span>
      <span>You have <strong>view-only</strong> access to {label || resource}. Changes are not available for your role.</span>
    </div>
  );
}