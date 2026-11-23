'use client';
import { useState } from 'react';
import { postJSON } from '../../lib/validation';

// Logout revokes the session on the server (POST /api/logout through the
// same-origin proxy), then leaves the portal. Deleting a cookie in the browser
// alone would not be enough: the server-side session must die too.
export default function LogoutButton() {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  async function logout() {
    setBusy(true);
    setError('');
    const result = await postJSON('/api/logout', {});
    if (result.ok) {
      window.location.assign('/login');
      return;
    }
    setError(result.message);
    setBusy(false);
  }

  return (
    <>
      <button type="button" onClick={logout} disabled={busy}>{busy ? 'Signing out...' : 'Sign out'}</button>
      {error && <p role="status" className="note error">{error}</p>}
    </>
  );
}
