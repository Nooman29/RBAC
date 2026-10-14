"""Scopes a service client (another module of the DSFS) can be granted."""

SERVICE_SCOPES = {
    "auth:introspect": "Validate user access tokens and read the user's roles and permissions",
    "authz:check": "Ask whether a user may perform an action on a resource",
    "roles:read": "List roles and their permissions",
    "users:read": "List and read users and their guardian links",
    "users:write": "Create users, update school/organisation, set role, manage guardian links",
    "events:write": "Report user activity so it feeds anomaly detection",
    "events:read": "Read reported activity events (for fraud detection and reporting)",
}