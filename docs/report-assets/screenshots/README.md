# Full system screenshots (backup for the live demo)

Captured on 31 October 2026 from the running system with Playwright (local Chrome), viewport 1440 x 900, in demo
order. Accounts: the `live_` demo accounts from `backend/scripts/setup_live_demo.py`, a temporary Manager
(`screens_manager`), and the pre-seeded `demo_teacher`. Everything the run created was deleted afterwards; real
accounts and `synth_` users were not touched.

How sign-in was handled without changing application code:
- Screens 01–04 use the real sign-in page: `live_admin`'s real password step, then the Face ID / email-code
  choice. The camera is Chrome's built-in fake camera, and the request that emails the code was stubbed in the
  browser, so no email was sent.
- Every other screen uses a test session token created by a backend script (the same token a successful sign-in
  issues), placed in the browser's storage. The attendance module received the same kind of token in place of
  the emailed code.

| File | What it shows | What you can say |
|---|---|---|
| `01_signin_password-step.png` | Sign-in, step 1 | "Every sign-in starts with a password, and a second factor is always required." |
| `02_signin_choose-face-id-or-email-code.png` | Second-factor choice | "After the password, the user verifies with Face ID or a one-time code sent by email." |
| `03_signin_face-id-camera.png` | Face ID camera step (test camera image) | "Face ID compares a live camera capture with the enrolled face, with an anti-spoofing check." |
| `04_signin_email-code.png` | Email code step | "Users without a camera receive a six-digit code that expires after five minutes." |
| `05_dashboard_administrator-all-records.png` | Administrator dashboard | "An administrator with global scope sees every session and alert, plus the alerts waiting for review." |
| `06_dashboard_manager-department-scope.png` | Manager dashboard | "A Manager sees the same dashboard, but only for their own department: visibility comes from the role's scope." |
| `07_my-access_teacher-school-scope.png` | Teacher's My Access page | "A Teacher has no security dashboard; they see exactly what their role allows, for their own school." |
| `08_users_list-and-role-assignment.png` | Users | "Administrators create users and assign one role each; long names are truncated so the table never scrolls sideways." |
| `09_roles_list-users-builtin-delete.png` | Roles list | "Each role shows how many users hold it; built-in roles and roles still in use cannot be deleted." |
| `10_roles_grant-permission.png` | Granting a permission | "Permissions are granted from the catalog of real resources and actions." |
| `11_roles_revoke-permission.png` | Revoking a permission | "Revoking takes effect on the user's very next request, because permissions are checked on every request." |
| `12_roles_delete-unused-role.png` | Deleting an unused role | "A role nobody holds can be deleted; the system blocks it while any user still has the role." |
| `13_compare-roles_permission-matrix.png` | Compare Roles | "The permission matrix shows least privilege at a glance: what each role can read, write, approve or export." |
| `14_my-access_administrator.png` | Administrator's My Access | "Every user can see their own role, data scope and risk tier." |
| `15_r1_refused-page-permission-banner.png` | A Standard User types a hidden page | "Going around the menu is refused by the server, and each refusal is counted by live rule R1." |
| `16_sessions_active-with-live-alert-badges.png` | Active sessions | "Active sessions with a live alert carry a red badge naming the rule that fired." |
| `17_alerts_in-progress-panel-r1-to-r5.png` | In progress panel | "All five live rules fired while the sessions were still active, each with a Terminate button." |
| `18_alerts_live-panel-and-scored-sessions.png` | Alerts page | "Live warnings sit above the scored sessions; the end-of-session score stays the official verdict." |
| `19_audit-log_role-changes-with-details.png` | Audit Log, Roles component | "Every administrative change is recorded in words, for example which permission was revoked from which role." |
| `20_detection-outcomes_verdict-summary.png` | Detection Outcomes | "Administrator verdicts show how many flags were real threats, false positives or authorised exceptions." |
| `21_detection-model_live-version-and-drift.png` | Detection Model, top | "The live model version, its thresholds and a drift indicator are visible to global administrators." |
| `22_detection-model_versions-and-guardrails.png` | Versions with guardrails expanded | "Every retrained version is kept, passes four guardrails before going live, and can be rolled back." |
| `23_simulate-attack_scenarios.png` | Simulate Attack | "Three attack scenarios run through the real scoring pipeline to show and test detection." |
| `24_integrations_service-clients.png` | Integrations, service clients | "Other DSFS modules connect with their own credentials and limited scopes." |
| `25_attendance-module_sign-in.png` | Attendance module sign-in | "The attendance module has no accounts of its own: sign-in is relayed to the central service." |
| `26_attendance-module_allowed-own-school.png` | Teacher views own school | "The module asks the central service before every action; the Teacher may view their own school (SCH-1)." |
| `27_attendance-module_denied-other-school.png` | Teacher views another school | "The same Teacher is denied another school's records (SCH-2): the decision is made centrally, by scope." |
| `28_integrations_authorization-audit-allowed-denied.png` | Authorization audit | "Every decision the module asked for is logged centrally, allowed and denied." |
| `29_integrations_reported-events.png` | Reported events | "Actions in the module are reported back and join the user's session for anomaly detection." |
| `30_alert-detail_provisional-vs-final-score.png` | Alert detail after termination | "The provisional score from the live check sits next to the final, official score of the same session." |
| `31_alert-detail_shap-explanation.png` | SHAP explanation | "SHAP shows which behaviours pushed the score up, so a reviewer can judge the alert." |

Note: screenshot 17 shows "4 refused requests" for R1 because screenshot 15 (live_staff opening /users) added a
fourth refused request during the run. In 26–27 the Present/Absent buttons are part of the module; the only one
clicked (for screenshot 29) marked a student who was already present, so the module's demo data did not change.
