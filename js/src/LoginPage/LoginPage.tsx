import { FormEvent, ReactNode, useEffect, useRef, useState } from 'react';
import { parseDevice } from '../services/fingerprint';
import PatternPad from '../PatternPad';
import styles from './LoginPage.module.css';

export interface LoginPageProps {
  onAuthenticated: () => void;
  /** Called when the backend answers 403 {"error":"vpn_required"} (an IP-gate
   *  in front of auth). Optional — omit if the host app has no such gate. */
  onVpnRequired?: () => void;
  /** Base path of the pattern-auth endpoints. Default '/api/auth'. */
  apiBasePath?: string;
  title?: string;
  subtitle?: string;
  /** Rendered at the bottom of the panel; replaces the default system line. */
  footer?: ReactNode;
  /** Show the animated "intrusion profile" fingerprint panel. Default true. */
  showFingerprintPanel?: boolean;
  /** Fetch geo/ISP data from ipapi.co for the fingerprint panel (requires the
   *  host CSP to allow it). Default true. */
  geoLookup?: boolean;
}

interface GeoInfo {
  ip: string;
  city: string;
  country: string;
  isp: string;
  latencyMs: number;
}

export default function LoginPage({
  onAuthenticated,
  onVpnRequired,
  apiBasePath = '/api/auth',
  title = 'SECURE ACCESS',
  subtitle = '// RESTRICTED ACCESS — AUTHORIZED PERSONNEL ONLY',
  footer,
  showFingerprintPanel = true,
  geoLookup = true,
}: LoginPageProps) {
  const [mode, setMode]               = useState<'pattern' | 'user' | 'breakglass'>('pattern');
  const [breakglass, setBreakglass]   = useState(true);   // env break-glass sign-in offered?
  const [userLogin, setUserLogin]     = useState(false);  // traditional username+password offered?
  const [pattern, setPattern]         = useState<number[]>([]);
  const [username, setUsername]       = useState('');
  const [password, setPassword]       = useState('');
  const [totpCode, setTotpCode]       = useState('');
  const [totpRequired, setTotpRequired] = useState(false);
  const [error, setError]             = useState('');
  const [attemptsLeft, setAttemptsLeft] = useState<number | null>(null);
  const [lockSecsLeft, setLockSecsLeft] = useState(0);
  const [loading, setLoading]         = useState(false);
  const [geo, setGeo]                 = useState<GeoInfo | null>(null);
  const [scanDone, setScanDone]       = useState(false);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const device = useRef(parseDevice());

  useEffect(() => {
    const t0 = performance.now();
    fetch(`${apiBasePath}/config`)
      .then(r => r.json())
      .then(d => {
        const latencyMs = Math.round(performance.now() - t0);
        setTotpRequired(d.totpRequired ?? false);
        const bg = d.breakglassAvailable ?? true;
        setBreakglass(bg);
        setUserLogin(d.passwordLoginAvailable ?? false);
        if (!bg) setMode('pattern');
        if (!geoLookup) {
          setGeo({ ip: '—', city: '—', country: '—', isp: '—', latencyMs });
          setScanDone(true);
          return;
        }
        fetch('https://ipapi.co/json/')
          .then(r => r.json())
          .then((g: { ip?: string; city?: string; country_name?: string; org?: string }) => {
            const rawIsp = g.org ?? '—';
            const isp = rawIsp.replace(/^AS\d+\s*/, '').toUpperCase().slice(0, 28);
            setGeo({ ip: g.ip ?? '—', city: g.city ?? '—', country: g.country_name ?? '—', isp, latencyMs });
            setTimeout(() => setScanDone(true), 200);
          })
          .catch(() => {
            setGeo({ ip: '—', city: '—', country: '—', isp: '—', latencyMs });
            setScanDone(true);
          });
      })
      .catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (lockSecsLeft <= 0) {
      if (timerRef.current) clearInterval(timerRef.current);
      return;
    }
    timerRef.current = setInterval(() => {
      setLockSecsLeft(s => {
        if (s <= 1) { clearInterval(timerRef.current!); return 0; }
        return s - 1;
      });
    }, 1000);
    return () => { if (timerRef.current) clearInterval(timerRef.current); };
  }, [lockSecsLeft]);

  const locked = lockSecsLeft > 0;
  const dev = device.current;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (locked) return;
    setError('');
    setLoading(true);
    try {
      const res = await fetch(`${apiBasePath}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          password,
          totpCode: totpCode || null,
          pattern: mode === 'pattern' ? pattern.join('-') : null,
          username: mode === 'user' ? username : null,
          fingerprint: {
            ip: geo?.ip ?? null, isp: geo?.isp ?? null, city: geo?.city ?? null,
            country: geo?.country ?? null, latencyMs: geo?.latencyMs ?? null,
            os: dev.os, browser: dev.browser, resolution: dev.resolution, tz: dev.tz,
            lang: dev.lang, cores: String(dev.cores), mem: dev.mem ?? null,
            touch: dev.touch, cookies: dev.cookies, userAgent: navigator.userAgent,
          },
        }),
      });
      if (res.ok) { onAuthenticated(); return; }
      const data = await res.json().catch(() => ({}));
      if (res.status === 403 && data.error === 'vpn_required' && onVpnRequired) { onVpnRequired(); return; }
      if (res.status === 423) {
        setLockSecsLeft(data.secsLeft ?? 900);
        setError(data.error ?? 'Locked out');
        setAttemptsLeft(null);
      } else {
        if (data.attemptsRemaining != null) setAttemptsLeft(data.attemptsRemaining);
        setError(data.error ?? 'Authentication failed');
      }
      setPassword('');
      setTotpCode('');
    } catch {
      setError('Connection error — retry');
    } finally {
      setLoading(false);
    }
  }

  const mm = String(Math.floor(lockSecsLeft / 60)).padStart(2, '0');
  const ss = String(lockSecsLeft % 60).padStart(2, '0');

  function Row({ k, v, warn }: { k: string; v: string; warn?: boolean }) {
    return (
      <div className={styles.loginConnRow}>
        <span className={styles.loginConnKey}>{k}</span>
        <span className={warn ? styles.loginConnWarn : styles.loginConnVal}>{v}</span>
      </div>
    );
  }

  return (
    <div className={styles.loginWrap}>
      <div className={`${styles.loginPanel}${showFingerprintPanel ? ` ${styles.loginWide}` : ''}`}>
        <div className={styles.loginHeader}>
          <div className={styles.loginTitle}>{title}</div>
          <div className={styles.loginSub}>{subtitle}</div>
        </div>

        <form className={styles.loginForm} onSubmit={handleSubmit}>
          {(breakglass || userLogin) && (
            <div className={styles.loginFieldLabel} style={{ display: 'flex', gap: 16 }}>
              {([
                ['pattern', 'PATTERN'],
                ...(userLogin ? [['user', 'USER LOGIN']] : []),
                ...(breakglass ? [['breakglass', 'OVERRIDE']] : []),
              ] as ['pattern' | 'user' | 'breakglass', string][]).map(([m, label]) => (
                <button
                  key={m}
                  type="button"
                  onClick={() => setMode(m)}
                  style={{
                    background: 'none', border: 'none', padding: 0, cursor: 'pointer',
                    font: 'inherit', letterSpacing: 'inherit',
                    color: mode === m ? 'var(--cy, #26e0ff)' : 'var(--muted, #7f97a3)',
                  }}
                >
                  {label}
                </button>
              ))}
            </div>
          )}

          {mode === 'pattern' && (
            <>
              <div className={styles.loginFieldLabel} style={{ marginTop: 4 }}>UNLOCK PATTERN</div>
              <div className={styles.patternSlot}>
                <PatternPad onChange={setPattern} disabled={loading || locked} />
              </div>
            </>
          )}

          {mode === 'user' && (
            <>
              <div className={styles.loginFieldLabel} style={{ marginTop: 4 }}>USERNAME</div>
              <input
                className={styles.loginInput}
                type="text"
                value={username}
                onChange={e => setUsername(e.target.value)}
                placeholder="enter username"
                autoFocus
                disabled={loading || locked}
                spellCheck={false}
                autoCapitalize="none"
                autoComplete="username"
              />
            </>
          )}

          <div className={styles.loginFieldLabel} style={{ marginTop: 4 }}>
            {mode === 'breakglass' ? 'ACCESS KEY' : 'PASSWORD'}
          </div>
          <div className={styles.pwWrap}>
            <input
              className={styles.loginInput}
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="enter password"
              autoFocus={mode === 'breakglass'}
              disabled={loading || locked}
              spellCheck={false}
              autoComplete="current-password"
            />
            <div className={styles.pwDots} aria-hidden="true">
              {Array.from({ length: password.length }, (_, i) => (
                <span
                  key={i}
                  className={`${styles.pwDot}${
                    i === password.length - 1
                      ? ` ${password.length % 2 ? styles.pwDotPopA : styles.pwDotPopB}`
                      : ''
                  }`}
                />
              ))}
            </div>
          </div>

          {(mode !== 'breakglass' || totpRequired) && (
            <>
              <div className={styles.loginFieldLabel} style={{ marginTop: 4 }}>
                AUTHENTICATOR CODE{mode !== 'breakglass' ? ' (IF ENABLED)' : ''}
              </div>
              <div className={styles.totpWrap}>
                <input
                  className={styles.totpHidden}
                  type="text"
                  inputMode="numeric"
                  pattern="[0-9]*"
                  maxLength={6}
                  value={totpCode}
                  onChange={e => setTotpCode(e.target.value.replace(/\D/g, ''))}
                  disabled={loading || locked}
                  autoComplete="one-time-code"
                  spellCheck={false}
                  aria-label="Authenticator code"
                />
                <div className={styles.totpRow} aria-hidden="true">
                  {Array.from({ length: 6 }, (_, i) => {
                    const ch = totpCode[i];
                    const isNewest = ch !== undefined && i === totpCode.length - 1;
                    return (
                      <div
                        key={i}
                        className={`${styles.totpBox}${ch ? ` ${styles.totpBoxFilled}` : ''}${
                          isNewest ? ` ${i % 2 ? styles.totpRollA : styles.totpRollB}` : ''
                        }`}
                      >
                        {ch ?? '0'}
                      </div>
                    );
                  })}
                </div>
              </div>
            </>
          )}

          {attemptsLeft !== null && attemptsLeft <= 5 && !locked && (
            <div className={styles.loginWarn}>⚠ {attemptsLeft} attempt{attemptsLeft !== 1 ? 's' : ''} remaining before lockout</div>
          )}
          {error && <div className={styles.loginError}>⚠ {error}</div>}

          <button
            className={styles.loginBtn}
            type="submit"
            disabled={loading || locked || !password
              || (mode === 'pattern' && pattern.length < 4)
              || (mode === 'user' && !username.trim())}
          >
            {locked
              ? <span>LOCKED — {mm}:{ss}</span>
              : loading
              ? <span className="blink">AUTHENTICATING...</span>
              : mode === 'pattern' ? 'UNLOCK' : 'AUTHENTICATE'}
          </button>
        </form>

        {showFingerprintPanel && (
          <div className={styles.loginConn}>
            <div className={styles.connScan} aria-hidden="true" />
            <div className={styles.connCursor} aria-hidden="true" />
            <div className={styles.loginConnHeader}>
              <span className={scanDone ? styles.loginConnAlert : `${styles.loginConnScanning} blink`}>
                {scanDone && (
                  <span className={styles.fpWrap} aria-hidden="true">
                    <span className={styles.fpRing} />
                    <span className={`${styles.fpRing} ${styles.fpRingLate}`} />
                    <span className={styles.fpCore} />
                  </span>
                )}
                {scanDone ? 'INTRUSION PROFILE ACQUIRED' : '◈ SCANNING INTRUDER...'}
              </span>
            </div>

            <div className={styles.loginConnSectionLabel}>// NETWORK</div>
            {/* Hide the geo rows if the lookup resolved with no data (blocked /
                rate-limited) rather than showing empty dashes. */}
            {(!geo || geo.ip !== '—') && <Row k="ORIGIN IP" v={geo?.ip ?? '…'} />}
            {(!geo || geo.isp !== '—') && <Row k="ISP" v={geo?.isp ?? '…'} />}
            {(!geo || geo.city !== '—') && <Row k="LOCATION" v={geo ? `${geo.city}, ${geo.country}` : '…'} />}
            <Row k="SRV LATENCY" v={geo ? `${geo.latencyMs}ms` : '…'} warn={!!geo && geo.latencyMs > 300} />

            <div className={styles.loginConnSectionLabel} style={{ marginTop: 6 }}>// DEVICE</div>
            <Row k="OS"         v={dev.os} />
            <Row k="BROWSER"    v={dev.browser} />
            <Row k="DISPLAY"    v={dev.resolution} />
            <Row k="TIMEZONE"   v={dev.tz} />

            <div className={styles.loginConnSectionLabel} style={{ marginTop: 6 }}>// FINGERPRINT</div>
            <Row k="LANGUAGE"   v={dev.lang} />
            <Row k="CPU CORES"  v={String(dev.cores)} />
            {dev.mem && <Row k="MEMORY" v={`${dev.mem} GB`} />}
            <Row k="TOUCH INPUT" v={dev.touch} />
            <Row k="COOKIES"    v={dev.cookies} />

            <div className={styles.loginConnFooter}>
              ⚠ THIS ACCESS ATTEMPT HAS BEEN LOGGED AND WILL BE REPORTED
            </div>
          </div>
        )}

        <div className={`${styles.loginFooter} mono`}>
          {footer ?? <>PATTERN-AUTH ● TLS{totpRequired ? ' + TOTP' : ''} ENCRYPTED</>}
        </div>
      </div>
    </div>
  );
}
