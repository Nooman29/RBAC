"""
Single source of truth for the Digital School Feeding System (DSFS) access model.

Describes resources, actions, scopes and role policies. Nothing here touches
the database; the seed script reads it.

The three original roles (Administrator, Manager, Standard User) are NOT
defined here as policies; they stay in scripts/seed_roles_and_permissions.py
because the anomaly simulation depends on them. They appear in ROLE_SCOPES
only so every role has a documented scope.

Validate and print the role x resource matrix:
    python -m app.core.dsfs_catalog
"""

from app.core.constants import RESOURCES

ACTIONS = ["read", "write", "approve", "export"]

# global       -> all records
# school       -> records belonging to the user's school_id
# department   -> records belonging to the user's department
# own          -> only records owned by / linked to the user
# organization -> only the user's own supplier organisation's records
SCOPES = ["global", "school", "department", "own", "organization"]

ROLE_SCOPES = {
    # Original roles (unchanged)
    "Administrator": "global",
    "Manager": "department",
    "Standard User": "own",
    # DSFS roles
    "Programme Administrator": "global",
    "School Administrator": "school",
    "Teacher": "school",
    "School Staff": "school",
    "Finance Officer": "global",
    "Logistics Officer": "global",
    "Supplier": "organization",
    "Parent/Guardian": "own",
    "Auditor": "global",
}

DSFS_ROLE_DESCRIPTIONS = {
    "Programme Administrator": "Oversees the feeding programme across all schools: monitoring, fraud review and reporting.",
    "School Administrator": "Manages beneficiaries, attendance and notifications for one school.",
    "Teacher": "Records meal attendance and views beneficiaries for their school.",
    "School Staff": "Handles meal service and receives supplies at their school.",
    "Finance Officer": "Creates, approves and exports school feeding payments.",
    "Logistics Officer": "Manages supply and delivery logistics across schools.",
    "Supplier": "External supplier: sees and updates only their own orders and deliveries.",
    "Parent/Guardian": "Views their own child's attendance and payment status.",
    "Auditor": "Read-only oversight across all modules, including exports.",
}

# resource -> actions, per role
DSFS_ROLE_POLICIES = {
    "Programme Administrator": {
        "dashboard": ["read"],
        "user": ["read"],
        "beneficiary": ["read"],
        "attendance": ["read"],
        "payment": ["read"],
        "supply": ["read"],
        "logistics": ["read"],
        "analytics": ["read", "export"],
        "fraud": ["read", "write"],
        "sms": ["read", "write"],
    },
    "School Administrator": {
        "dashboard": ["read"],
        "user": ["read"],
        "beneficiary": ["read", "write"],
        "attendance": ["read", "write"],
        "supply": ["read"],
        "analytics": ["read"],
        "sync": ["read", "write"],
        "sms": ["read", "write"],
    },
    "Teacher": {
        "beneficiary": ["read"],
        "attendance": ["read", "write"],
        "sync": ["write"],
    },
    "School Staff": {
        "beneficiary": ["read"],
        "attendance": ["read", "write"],
        "supply": ["read", "write"],
        "sync": ["write"],
    },
    "Finance Officer": {
        "beneficiary": ["read"],
        "payment": ["read", "write", "approve", "export"],
        "analytics": ["read"],
        "fraud": ["read"],
    },
    "Logistics Officer": {
        "supply": ["read", "write"],
        "logistics": ["read", "write"],
        "sync": ["write"],
    },
    "Supplier": {
        "supply": ["read", "write"],
        "logistics": ["read"],
    },
    "Parent/Guardian": {
        "beneficiary": ["read"],
        "attendance": ["read"],
        "payment": ["read"],
    },
    "Auditor": {
        "dashboard": ["read"],
        "role": ["read"],
        "user": ["read"],
        "beneficiary": ["read", "export"],
        "attendance": ["read", "export"],
        "payment": ["read", "export"],
        "supply": ["read", "export"],
        "logistics": ["read", "export"],
        "analytics": ["read", "export"],
        "fraud": ["read"],
    },
}


def validate_catalog() -> None:
    """Raise AssertionError if the catalog is internally inconsistent."""
    for role, scope in ROLE_SCOPES.items():
        assert scope in SCOPES, f"{role}: unknown scope '{scope}'"

    assert set(DSFS_ROLE_POLICIES) == set(DSFS_ROLE_DESCRIPTIONS), \
        "Every DSFS role needs both a policy and a description"

    for role in DSFS_ROLE_POLICIES:
        assert role in ROLE_SCOPES, f"{role}: missing from ROLE_SCOPES"

    for role, policy in DSFS_ROLE_POLICIES.items():
        for resource, actions in policy.items():
            assert resource in RESOURCES, f"{role}: unknown resource '{resource}'"
            for action in actions:
                assert action in ACTIONS, f"{role}: unknown action '{action}' on {resource}"


def print_matrix() -> None:
    cols = [r for r in RESOURCES if any(r in p for p in DSFS_ROLE_POLICIES.values())]
    width = max(len(r) for r in DSFS_ROLE_POLICIES) + 2
    print("Role".ljust(width) + "Scope".ljust(14) + " | ".join(c[:11].ljust(11) for c in cols))
    for role, policy in DSFS_ROLE_POLICIES.items():
        cells = []
        for c in cols:
            acts = policy.get(c, [])
            cells.append("".join(a[0].upper() for a in acts).ljust(11) or "-".ljust(11))
        print(role.ljust(width) + ROLE_SCOPES[role].ljust(14) + " | ".join(cells))
    print("\nLegend: R=read W=write A=approve E=export")


if __name__ == "__main__":
    validate_catalog()
    print("Catalog valid.\n")
    print_matrix()
