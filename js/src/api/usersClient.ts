// Typed client for the pattern-auth user-management endpoints
// (MapPatternAuthUsersEndpoints on the backend). All calls send credentials so
// the auth cookie flows.

export interface AuthUser {
  id: string;
  label: string;
  /** Login name — set for 'password' users, null for 'pattern' users. */
  username: string | null;
  /** How this user authenticates. */
  method: 'pattern' | 'password';
  totpEnabled: boolean;
  backupCodesRemaining: number;
  createdAt: string;
  lastLoginAt: string | null;
}

/** Exactly one of `pattern` or `username` must be provided. */
export interface NewUser {
  label: string;
  /** Pattern user: dash-joined dot indices, e.g. "0-7-14-21". */
  pattern?: string | null;
  /** Password user: login name (3–32 chars, [a-z0-9._-]). */
  username?: string | null;
  password: string;
  totpSecret?: string | null;
  /** Current authenticator code proving the secret was enrolled. */
  totpCode?: string | null;
  backupCodes?: string[] | null;
}

export interface UsersApi {
  list(): Promise<AuthUser[]>;
  create(user: NewUser): Promise<{ ok: boolean; id?: string; label?: string; error?: string }>;
  remove(id: string): Promise<{ ok: boolean; error?: string }>;
  newTotpSecret(label?: string): Promise<{ secret: string; otpauthUri: string }>;
}

export function createUsersApi(basePath = '/api/users'): UsersApi {
  const opts: RequestInit = { credentials: 'include' };
  return {
    async list() {
      const r = await fetch(basePath, opts);
      if (!r.ok) throw new Error(`users list failed (${r.status})`);
      return r.json();
    },
    async create(user) {
      const r = await fetch(basePath, {
        ...opts,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(user),
      });
      return r.json().catch(() => ({ ok: false, error: `create failed (${r.status})` }));
    },
    async remove(id) {
      const r = await fetch(`${basePath}/${encodeURIComponent(id)}`, { ...opts, method: 'DELETE' });
      return r.json().catch(() => ({ ok: r.ok }));
    },
    async newTotpSecret(label) {
      const q = label ? `?label=${encodeURIComponent(label)}` : '';
      const r = await fetch(`${basePath}/new-totp-secret${q}`, opts);
      if (!r.ok) throw new Error(`new-totp-secret failed (${r.status})`);
      return r.json();
    },
  };
}
