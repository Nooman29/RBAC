DEPARTMENTS = ["IT", "Finance", "HR", "Operations", "Executive"]

# Core RBAC resources plus the Digital School Feeding System (DSFS) modules.
RESOURCES = [
    "dashboard",
    "role",
    "user",
    # DSFS modules
    "beneficiary",
    "attendance",
    "payment",
    "supply",
    "logistics",
    "analytics",
    "fraud",
    "sync",
    "sms",
    "service_client",
]

REVIEW_VERDICTS = ["confirmed_threat", "false_positive", "authorized_exception"]