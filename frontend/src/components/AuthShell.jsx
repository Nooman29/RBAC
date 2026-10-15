import { Icon } from "./Sidebar";
import "../auth.css";

// Shared layout for every sign-in / account-setup page.
// Keeps the .auth-screen and .auth-card class names so existing form styling still applies.
export default function AuthShell({ title, subtitle, children }) {
  return (
    <div className="auth-screen ds-auth">
      <aside className="ds-auth-brand">
        <div className="ds-auth-brand-inner">
          <span className="ds-brand-mark ds-auth-mark">
            <Icon name="roles" size={24} />
          </span>
          <h2>Digital School Feeding System</h2>
          <p>Central sign-in and access control for every module of the programme.</p>
          <ul className="ds-auth-points">
            <li>Two-step verification with Face ID or an email code</li>
            <li>Role-based access, enforced on the server</li>
            <li>Every session monitored for unusual activity</li>
          </ul>
        </div>
      </aside>
      <div className="ds-auth-panel">
        <div className="auth-card">
          {title && <h1>{title}</h1>}
          {subtitle && <p className="auth-subtitle">{subtitle}</p>}
          {children}
        </div>
      </div>
    </div>
  );
}