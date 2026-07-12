// Client-side device fingerprint, shared by the login page and the VPN gate
// page. Pure `navigator`/`screen` reads — no network. Geo/ISP is fetched
// separately (ipapi.co) by the pages that need it.

export function parseDevice() {
  const ua = navigator.userAgent;

  let os = 'UNKNOWN OS';
  if (/Windows NT 10/.test(ua))      os = 'WINDOWS 10/11';
  else if (/Windows NT 6/.test(ua))  os = 'WINDOWS (LEGACY)';
  else if (/iPhone/.test(ua))        os = 'IOS (IPHONE)';
  else if (/iPad/.test(ua))          os = 'IOS (IPAD)';
  else if (/Android/.test(ua))       os = 'ANDROID';
  else if (/Mac OS X/.test(ua))      os = 'MACOS';
  else if (/Linux/.test(ua))         os = 'LINUX';

  let browser = 'UNKNOWN BROWSER';
  let bver = '';
  const edgeM = ua.match(/Edg\/(\d+)/);
  const chrM  = ua.match(/Chrome\/(\d+)/);
  const ffM   = ua.match(/Firefox\/(\d+)/);
  const safM  = ua.match(/Version\/(\d+).*Safari/);
  if (edgeM)      { browser = 'EDGE';    bver = edgeM[1]; }
  else if (chrM)  { browser = 'CHROME';  bver = chrM[1]; }
  else if (ffM)   { browser = 'FIREFOX'; bver = ffM[1]; }
  else if (safM)  { browser = 'SAFARI';  bver = safM[1]; }

  const resolution = `${screen.width}×${screen.height}`;
  const dpr        = window.devicePixelRatio > 1 ? ` @${window.devicePixelRatio}x` : '';
  const tz         = Intl.DateTimeFormat().resolvedOptions().timeZone;
  const lang       = navigator.language.toUpperCase();
  const cores      = navigator.hardwareConcurrency ?? '—';
  const mem        = (navigator as { deviceMemory?: number }).deviceMemory;
  const touch      = navigator.maxTouchPoints > 0 ? 'YES' : 'NO';
  const cookies    = navigator.cookieEnabled ? 'ENABLED' : 'DISABLED';

  return { os, browser: bver ? `${browser} ${bver}` : browser, resolution: resolution + dpr, tz, lang, cores, mem, touch, cookies };
}

export type Device = ReturnType<typeof parseDevice>;
