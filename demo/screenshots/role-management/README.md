# Role management screenshots (issue #87)

Captured on 31 October 2026 from the running system (frontend at http://127.0.0.1:5173), signed in as a
temporary administrator `admin_demo`. Demo data used: a role "Exam Invigilator" held by one user with a
deliberately long name and email, and an unused "Temporary Test Role". Both were removed afterwards; the
test role "Developer" was left untouched.

| File | Shows |
|---|---|
| `01_roles_list_users_builtin_delete.png` | Roles list: user count per role, "Built-in" badges, Delete enabled only for roles nobody holds and that are not built-in |
| `02_role_detail_revoke_and_grant.png` | Role page: a Revoke button per permission, and the grant picker with the catalog's resources and actions |
| `03_permission_revoked.png` | After revoking export on payment (confirmation accepted): the permission is gone |
| `04_permission_granted_from_catalog.png` | After granting export on attendance from the picker |
| `05_lockout_guard_role_write.png` | Revoking role:write from Administrator is refused: nobody else could manage roles |
| `06_unused_role_deleted.png` | "Temporary Test Role" deleted; roles still held (e.g. Exam Invigilator, 1 user) stay blocked |
| `07_audit_log_change_details.png` | Audit Log filtered to Roles (today, newest 8 rows): the delete is described in words, ordinary reads are not |
| `07b_audit_log_changes_only.png` | The same preview showing only the rows that describe a change (presentation crop): delete, grant and revoke |
| `08_users_table_1024px.png` | Users table at 1024 px: no sideways scroll, email under the name, one Role column |
| `08_users_table_768px.png` | Users table at 768 px: long username and email cut with "…" (full value on hover), still no sideways scroll |

The refused revoke in 05 appears in the audit log as a request with no change description, because nothing
changed. Deleting a role and revoking permissions are DELETE requests, so the live burst rule (R2) counts them.
