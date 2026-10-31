# Consistent buttons (issue #89): before and after

Captured on 31 October 2026 from the running system at 1366 px wide, signed in as a temporary administrator
(`ui_review_admin`, removed afterwards). `before/` is the interface before the change, `after/` the same pages
after it. Behaviour is unchanged: the same 45 click handlers and link destinations exist before and after.

## The button system

One style for every page, from the existing design system (`ds-btn` in `frontend/src/layout.css`):

| Variant | Used for |
|---|---|
| Primary (solid blue) | the main action of a form or page: Create, Save Verdict, Grant, Preview, Run Scenario, Retrain now |
| Secondary (outlined) | neutral actions and navigation: Back, View, Review, Refresh, Download CSV, Resend email, Dismiss |
| Danger (outlined red) | destructive actions: Delete, Terminate, Revoke, Report as threat, Full reset |
| Small | the same three, inside table rows |

Navigation actions stay real links (`<Link>`) styled as buttons. The sign-in screens use their card's own
primary and secondary buttons, so secondary actions there ("Forgot password?", "Back to login") are outlined
buttons too. The sidebar stays as links.

## Files

| Page | before / after | What changed |
|---|---|---|
| Alerts | `01_alerts.png` | Alert IDs are plain text with a View button; live panel Terminate / Dismiss are buttons |
| Alert detail | `02_alert_detail.png` | Back is a button; Terminate Session and Save Verdict were browser-default grey |
| Sessions | `03_sessions.png` | Refresh, Terminate, Review and Report as threat in one style; the Live alert badge is a button |
| Roles | `04_roles.png` | Role names are plain text with View and Delete buttons |
| Role detail | `05_role_detail.png` | Back, Revoke and Grant in one style |
| Users | `06_users.png` | Create, Resend email and Delete were a solid form button and underlined text |
| Audit log | `07_audit_log.png` | Date presets, Preview and Download CSV were browser-default grey |
| Simulate attack | `08_simulate_attack.png` | Run Scenario, Clear simulated history, Full reset, View full alert |
| Model management | `09_model_management.png` | Retrain now, version expander and Put live / Roll back |
| Face ID setup | `10_face_enroll.png` | Re-enroll was browser-default grey |
| Sign in | `11_login.png` | "Forgot password?" is an outlined secondary button |
| Forgot password | `12_forgot_password.png` | "Back to login" is an outlined secondary button |
| Alerts at 1024 px | `after/13_alerts_1024px.png` | No sideways scroll; row buttons stack on narrower screens |
| Model at 1024 px | `after/14_model_management_1024px.png` | No sideways scroll |

No page scrolls sideways at 768, 1024, 1280 or 1440 px (checked on Alerts, Sessions, Roles, Role detail, Users,
Audit log, Simulate attack, Model management, Integrations and Dashboard).
