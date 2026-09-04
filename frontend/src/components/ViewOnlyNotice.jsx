import { usePermissions } from "../context/PermissionsContext";

export default function ViewOnlyNotice({ resource, label }) {
  const { can, loaded } = usePermissions();
  if (!loaded || !can) return null;
  if (can(resource, "write")) return null;
  return (
    <p className="view-only-badge">
      👁 View only — your role has read-only access to {label || resource}.
    </p>
  );
}