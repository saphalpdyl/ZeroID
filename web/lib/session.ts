// Server-side session lookup for the client portal (Samip).
//
// The portal never decides on its own whether someone is logged in. It
// forwards the browser's cookie to the Go identity service and trusts only the
// service's answer (server-side sessions, OWASP A01/A08). Import this file only
// from server components.
//
// ─── Contract with the Go service (adjust here if Saphal's API differs) ───
//   GET  {ZEROID_API_URL}/api/me
//        Cookie: <session cookie from the browser>
//        200 → MeResponse JSON        401/403 → not logged in
//   POST /api/logout  (called from the browser through the /api proxy)
//        revokes the server-side session and clears the cookie
// ─────────────────────────────────────────────────────────────────────────
import { headers } from 'next/headers';

export const ME_PATH = '/api/me';

export type AuthEvent = {
  type: string;      // matches auth_events.event_type in db/migrations/001_init.sql
  success: boolean;
  ip: string | null;
  at: string;        // ISO timestamp
};

export type MeResponse = {
  email: string;
  emailVerified: boolean;
  session: { startedAt: string; expiresAt: string };
  recentEvents: AuthEvent[];
};

/** Returns the logged-in user, or null if there is no valid session. */
export async function getCurrentUser(): Promise<MeResponse | null> {
  const backend = process.env.ZEROID_API_URL;
  if (!backend) return null;

  const cookie = (await headers()).get('cookie');
  if (!cookie) return null; // deny by default: no cookie, no session

  try {
    const response = await fetch(new URL(ME_PATH, backend), {
      method: 'GET',
      headers: { Cookie: cookie, Accept: 'application/json' },
      cache: 'no-store',
      redirect: 'manual',
      signal: AbortSignal.timeout(5000),
    });
    if (response.status !== 200) return null;
    const data: unknown = await response.json();
    return isMeResponse(data) ? data : null; // never trust an unexpected shape
  } catch {
    return null; // service down → treat as logged out (fail closed)
  }
}

function isMeResponse(value: unknown): value is MeResponse {
  if (typeof value !== 'object' || value === null) return false;
  const v = value as Record<string, unknown>;
  const s = v.session as Record<string, unknown> | undefined;
  return (
    typeof v.email === 'string' &&
    typeof v.emailVerified === 'boolean' &&
    typeof s === 'object' && s !== null &&
    typeof s.startedAt === 'string' &&
    typeof s.expiresAt === 'string' &&
    Array.isArray(v.recentEvents)
  );
}
