export function validEmail(raw: string): boolean {
  const email = raw.trim();
  return email.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}
export function validPassword(value: string): boolean { return value.length >= 12 && value.length <= 128; }
export function validTOTP(code: string): boolean { return /^[0-9]{6}$/.test(code); }
export function validToken(token: string): boolean { return /^[A-Za-z0-9_-]{16,512}$/.test(token); }
export async function postJSON(path: string, payload: object): Promise<{ ok: boolean; message: string }> {
  try {
    const response = await fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify(payload), cache: 'no-store' });
    const data: unknown = await response.json().catch(() => null);
    const message = typeof data === 'object' && data !== null && 'message' in data && typeof data.message === 'string' ? data.message : response.ok ? 'Request accepted.' : 'Unable to complete the request.';
    return { ok: response.ok, message };
  } catch { return { ok: false, message: 'Cannot reach the identity service. Check that the Go backend is running.' }; }
}
