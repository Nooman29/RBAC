import { useEffect, useMemo, useState } from "react";
import client from "../api/client";
import "./RoleComparison.css";

const MODULE_LABELS = {
  dashboard: "Dashboard & monitoring",
  role: "Role management",
  user: "User management",
  service_client: "Integrations",
  beneficiary: "Student beneficiaries",
  attendance: "Meal attendance",
  payment: "Feeding payments",
  supply: "Supply chain",
  logistics: "Logistics tracking",
  analytics: "Analytics",
  fraud: "Fraud detection",
  sync: "Offline data sync",
  sms: "SMS notifications",
};
const CORE = ["dashboard", "role", "user", "service_client"];
const MODULE_ORDER = ["beneficiary", "attendance", "payment", "supply", "logistics", "analytics", "fraud", "sync", "sms"];
const ACTION_ORDER = ["read", "write", "approve", "export"];
const SCOPE_HELP = {
  global: "All records",
  school: "Only the user's own school",
  department: "Only the user's own department",
  own: "Only their own records (guardians: linked students)",
  organization: "Only their own organisation",
};

const label = (resource) => MODULE_LABELS[resource] || resource;

function actionRank(a) {
  const i = ACTION_ORDER.indexOf(a);
  return i === -1 ? 99 : i;
}
function sortActions(list) {
  return [...list].sort((a, b) => actionRank(a) - actionRank(b) || a.localeCompare(b));
}

export default function RoleComparison() {
  const [roles, setRoles] = useState([]);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [hidden, setHidden] = useState(() => new Set());
  const [moduleFilter, setModuleFilter] = useState("all");
  const [diffOnly, setDiffOnly] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const listRes = await client.get("/api/roles/");
        const details = await Promise.all(
          listRes.data.map((r) => client.get(`/api/roles/${r.role_id}`).then((res) => res.data))
        );
        setRoles(details);
      } catch (err) {
        setError(err.response?.data?.detail || "Failed to load roles");
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  const permSets = useMemo(() => {
    const map = new Map();
    roles.forEach((r) =>
      map.set(r.role_id, new Set(r.permissions.map((p) => `${p.resource_name}:${p.action_type}`)))
    );
    return map;
  }, [roles]);

  const resources = useMemo(() => {
    const seen = new Set();
    roles.forEach((r) => r.permissions.forEach((p) => seen.add(p.resource_name)));
    const ordered = [...CORE, ...MODULE_ORDER];
    const known = ordered.filter((r) => seen.has(r));
    const extra = [...seen].filter((r) => !ordered.includes(r)).sort();
    return [...known, ...extra];
  }, [roles]);

  const actionsByResource = useMemo(() => {
    const collected = {};
    roles.forEach((r) =>
      r.permissions.forEach((p) => {
        if (!collected[p.resource_name]) collected[p.resource_name] = new Set();
        collected[p.resource_name].add(p.action_type);
      })
    );
    const out = {};
    Object.keys(collected).forEach((res) => {
      out[res] = sortActions(collected[res]);
    });
    return out;
  }, [roles]);

  const visibleRoles = roles.filter((r) => !hidden.has(r.role_id));

  function toggleRole(roleId) {
    setHidden((prev) => {
      const next = new Set(prev);
      if (next.has(roleId)) {
        next.delete(roleId);
      } else if (roles.length - next.size > 1) {
        next.add(roleId); // always keep at least one role visible
      }
      return next;
    });
  }

  if (loading) return <p>Loading…</p>;
  if (error) return <p className="error">{error}</p>;

  const sections = resources
    .filter((res) => moduleFilter === "all" || res === moduleFilter)
    .map((resource) => {
      const rows = (actionsByResource[resource] || [])
        .map((action) => {
          const key = `${resource}:${action}`;
          const flags = visibleRoles.map((r) => permSets.get(r.role_id).has(key));
          return { action, key, flags, differs: flags.some(Boolean) && !flags.every(Boolean) };
        })
        .filter((row) => row.flags.some(Boolean))
        .filter((row) => !diffOnly || row.differs);
      return { resource, rows };
    })
    .filter((s) => s.rows.length > 0);

  const scopesInUse = [...new Set(roles.map((r) => r.scope).filter(Boolean))];

  function groupedPermissions(role) {
    const grouped = {};
    role.permissions.forEach((p) => {
      if (!grouped[p.resource_name]) grouped[p.resource_name] = [];
      grouped[p.resource_name].push(p.action_type);
    });
    return resources
      .filter((res) => grouped[res])
      .map((res) => ({ resource: res, actions: sortActions(grouped[res]) }));
  }

  return (
    <div>
      <h2>Role Comparison</h2>
      <p className="muted">
        A live view of the principle of least privilege: which actions each role can perform on each module,
        and how far its access reaches (its scope).
      </p>

      <div className="rm-toolbar">
        <label>
          Module
          <select className="ds-select" value={moduleFilter} onChange={(e) => setModuleFilter(e.target.value)}>
            <option value="all">All modules</option>
            {resources.map((res) => (
              <option key={res} value={res}>{label(res)}</option>
            ))}
          </select>
        </label>
        <label>
          <input type="checkbox" checked={diffOnly} onChange={(e) => setDiffOnly(e.target.checked)} />
          Only show differences between the roles below
        </label>
      </div>
      <div className="rm-toolbar" style={{ marginTop: 0 }}>
        <span className="muted">Roles:</span>
        <div className="rm-roles-filter">
          {roles.map((role) => (
            <button
              key={role.role_id}
              type="button"
              className={`rm-role-toggle${hidden.has(role.role_id) ? "" : " on"}`}
              onClick={() => toggleRole(role.role_id)}
            >
              {role.role_name}
            </button>
          ))}
        </div>
      </div>

      <div className="rm-scroll">
        <table className="rm-table">
          <thead>
            <tr>
              <th className="rm-first">Permission</th>
              {visibleRoles.map((role) => (
                <th key={role.role_id}>
                  {role.role_name}
                  <span className="rm-scope">{role.scope || "—"}</span>
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sections.map((section) => (
              <SectionRows key={section.resource} section={section} colSpan={visibleRoles.length + 1} />
            ))}
          </tbody>
        </table>
        {sections.length === 0 && (
          <div className="rm-empty">
            {diffOnly
              ? "No differences among the selected roles for this module."
              : "No permissions have been granted to the selected roles."}
          </div>
        )}
      </div>

      <div className="panel">
        <h3>What "scope" means</h3>
        <p className="muted">
          A permission says <em>what</em> a role may do. Its scope limits <em>which records</em> it applies to.
          Other modules pass the record's context, and the server enforces the match.
        </p>
        <dl className="rm-legend">
          {scopesInUse.map((scope) => (
            <div key={scope}>
              <dt>{scope}</dt>
              <dd>{SCOPE_HELP[scope] || ""}</dd>
            </div>
          ))}
        </dl>
      </div>

      <div className="panel">
        <h3>What each role can do</h3>
        {roles.map((role) => {
          const perms = groupedPermissions(role);
          return (
            <div key={role.role_id} className="role-summary-card">
              <div className="rm-role-head">
                <strong>{role.role_name}</strong>
                <span className="ds-chip">{role.scope || "—"} scope</span>
              </div>
              <p className="muted">{role.description}</p>
              {perms.length === 0 ? (
                <p className="matrix-no">No permissions granted.</p>
              ) : (
                perms.map((g) => (
                  <div key={g.resource} className="rm-perm-line">
                    <span className="rm-perm-res">{label(g.resource)}</span>
                    {g.actions.map((a) => (
                      <span key={a} className="ds-chip">{a}</span>
                    ))}
                  </div>
                ))
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function SectionRows({ section, colSpan }) {
  const isCore = CORE.includes(section.resource);
  return (
    <>
      <tr className="rm-group">
        <td colSpan={colSpan}>
          {label(section.resource)}
          <span className="rm-group-tag">{isCore ? "Core system" : "Feeding programme"}</span>
        </td>
      </tr>
      {section.rows.map((row) => (
        <tr key={row.key}>
          <td className="rm-first rm-action">{row.action}</td>
          {row.flags.map((has, i) => (
            <td key={i} className="matrix-cell">
              {has ? <span className="matrix-yes">✓</span> : <span className="matrix-no">—</span>}
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}