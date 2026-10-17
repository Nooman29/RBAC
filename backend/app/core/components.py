"""Friendly names for the parts of the dashboard a request belongs to (used by the audit log)."""

from typing import Optional

# (path prefix, component). The longest matching prefix wins.
_ROUTE_COMPONENTS = [
    ("/api/dashboard/summary", "Dashboard"),
    ("/api/dashboard/charts", "Dashboard"),
    ("/api/dashboard/alerts", "Alerts"),
    ("/api/dashboard/sessions", "Sessions"),
    ("/api/dashboard/detection-outcomes", "Detection Outcomes"),
    ("/api/dashboard/audit-log", "Audit Log"),
    ("/api/dashboard/simulate-attack", "Simulate Attack"),
    ("/api/audit", "Audit Log"),
    ("/api/users", "Users"),
    ("/api/roles", "Roles"),
    ("/api/service-clients", "Integrations"),
    ("/api/module-events", "Integrations"),
]

# Interface-only actions the frontend may report (they are not permission-gated API calls).
UI_EVENTS = {
    "Notifications": {"opened", "opened_item", "marked_all_read"},
}

KNOWN_COMPONENTS = sorted({label for _, label in _ROUTE_COMPONENTS} | set(UI_EVENTS))


def component_for(path: str) -> str:
    best: Optional[tuple] = None
    for prefix, label in _ROUTE_COMPONENTS:
        if path == prefix or path.startswith(prefix + "/"):
            if best is None or len(prefix) > len(best[0]):
                best = (prefix, label)
    return best[1] if best else "Other"