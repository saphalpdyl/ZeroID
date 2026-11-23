// Client portal (Samip): the page a user reaches after password + TOTP.
// Rendered on the server for every request; without a valid server-side
// session the user is redirected to /login (deny by default, OWASP A01).
import { redirect } from 'next/navigation';
import { getCurrentUser, type AuthEvent } from '../../lib/session';
import LogoutButton from './LogoutButton';

export const dynamic = 'force-dynamic';
export const metadata = { title: 'Portal · ZeroID' };

const EVENT_LABELS: Record<string, string> = {
  register: 'Account created',
  email_verify: 'Email verified',
  login_password: 'Password check',
  login_totp: 'Authenticator code',
  login_recovery_code: 'Recovery code used',
  lockout: 'Account locked',
  logout: 'Signed out',
  session_revoked: 'Session revoked',
  totp_enroll: 'Authenticator enrolled',
  password_reset_request: 'Password reset requested',
  password_reset: 'Password reset',
};

function formatTime(iso: string): string {
  const date = new Date(iso);
  return Number.isNaN(date.getTime())
    ? 'unknown'
    : date.toLocaleString('en-US', { dateStyle: 'medium', timeStyle: 'short' });
}

function EventRow({ event }: { event: AuthEvent }) {
  // React escapes all of these values, so attacker-controlled text
  // (e.g. a user agent or email) cannot inject HTML (XSS).
  return (
    <tr>
      <td>{EVENT_LABELS[event.type] ?? event.type}</td>
      <td className={event.success ? 'success' : 'error'}>{event.success ? 'Success' : 'Failed'}</td>
      <td>{event.ip ?? '—'}</td>
      <td>{formatTime(event.at)}</td>
    </tr>
  );
}

export default async function Portal() {
  const user = await getCurrentUser();
  if (!user) redirect('/login');

  return (
    <section className="panel wide">
      <div className="kicker">Client portal</div>
      <h1>You&apos;re signed in</h1>
      <p className="muted">Password and authenticator code verified. This session is held on the server, not in your browser.</p>

      <dl className="facts">
        <div><dt>Account</dt><dd>{user.email}</dd></div>
        <div><dt>Email</dt><dd className={user.emailVerified ? 'success' : 'error'}>{user.emailVerified ? 'Verified' : 'Not verified'}</dd></div>
        <div><dt>Session started</dt><dd>{formatTime(user.session.startedAt)}</dd></div>
        <div><dt>Session expires</dt><dd>{formatTime(user.session.expiresAt)}</dd></div>
      </dl>
      <p className="muted small">Sessions end after 10 minutes of inactivity and always after 1 hour.</p>

      <h2>Recent sign-in activity</h2>
      {user.recentEvents.length === 0 ? (
        <p className="muted">No activity recorded yet.</p>
      ) : (
        <div className="table-wrap">
          <table className="events">
            <thead><tr><th>Event</th><th>Result</th><th>IP address</th><th>When</th></tr></thead>
            <tbody>{user.recentEvents.slice(0, 10).map((e, i) => <EventRow key={i} event={e} />)}</tbody>
          </table>
        </div>
      )}
      <p className="muted small">Don&apos;t recognise something? Sign out and reset your password.</p>

      <LogoutButton />
    </section>
  );
}
