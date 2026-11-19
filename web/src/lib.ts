export type Row = Record<string, any>;
let csrf = '';
export function setCsrf(value: string) { csrf = value; }
export class ApiError extends Error {
  constructor(message: string, public status: number, public code?: string, public requestId?: string) { super(message); }
}
export async function api<T = any>(path: string, method = 'GET', body?: unknown, signal?: AbortSignal): Promise<T> {
  const response = await fetch('/api/v1' + path, {
    method, credentials: 'same-origin', signal,
    headers: { ...(body !== undefined && !(body instanceof FormData) ? {'Content-Type': 'application/json'} : {}), ...(method !== 'GET' ? {'X-CSRF-Token': csrf, 'Idempotency-Key': crypto.randomUUID()} : {}) },
    body: body === undefined ? undefined : body instanceof FormData ? body : JSON.stringify(body),
  });
  const json = await response.json().catch(() => ({}));
  if (!response.ok) {
    if (response.status === 401 && path !== '/auth/session') window.dispatchEvent(new Event('session-expired'));
    const detail = typeof json.detail === 'string' ? json.detail : Array.isArray(json.detail) ? json.detail.map((x: Row) => x.msg).join('; ') : 'Request could not be completed';
    throw new ApiError(detail, response.status, json.code, json.request_id || response.headers.get('X-Request-ID'));
  }
  return json;
}
export function parseJson(value: unknown, fallback: any = {}) { if (typeof value !== 'string') return value ?? fallback; try { return JSON.parse(value); } catch { return fallback; } }
export function pretty(value: unknown) { return JSON.stringify(value, null, 2); }
export function short(value: unknown, length = 12) { const s = String(value || '—'); return s.length > length ? s.slice(0,length) + '…' : s; }
export function bytes(value: unknown): string { const n = Number(value); if (!Number.isFinite(n) || value == null) return 'Unknown'; if (n < 1024) return `${n} B`; const unit = Math.min(4,Math.floor(Math.log(n)/Math.log(1024))); return `${(n/1024**unit).toFixed(1)} ${['B','KiB','MiB','GiB','TiB'][unit]}`; }
export function utc(value: unknown): string { if (!value) return 'Unknown'; const d = new Date(typeof value === 'number' ? value * 1000 : String(value)); return Number.isNaN(d.getTime()) ? 'Unknown' : d.toISOString().replace('T',' ').replace('.000','').replace('Z',' UTC'); }
export function routeQuery(path: string, values: Row) { const q = new URLSearchParams(); for (const [k,v] of Object.entries(values)) if (v !== '' && v != null) q.set(k,String(v)); return path + (q.size ? '?' + q.toString() : ''); }
export function downloadJson(filename: string, data: unknown) { const url = URL.createObjectURL(new Blob([pretty(data)],{type:'application/json'})); const a = document.createElement('a'); a.href=url; a.download=filename; a.click(); setTimeout(()=>URL.revokeObjectURL(url),1000); }

export function caseLabel(c: Row): string {
  return `${c.title} · ${utc(c.created_at)} · ID ${c.id} · v${c.version}`;
}

export function statusTone(value: string): string {
  const status = String(value ?? '').trim().toUpperCase().replace(/\s+/g,'_');
  if (['FAILED','INVALID','REVOKED','QUARANTINED','REJECTED','ERROR','OFFLINE','STALE','CANCELLED','EXPIRED','UNAVAILABLE'].includes(status)) return 'red';
  if (['ONLINE','ACTIVE','COMPLETE','COMPLETED','VALID','SEALED','RESOLVED','APPROVED','ACCEPTED','ENABLED','AVAILABLE','INSTALLED','RECENT','VERIFIED','RUNNING_OK'].includes(status)) return 'green';
  if (['PENDING','STAGED','QUEUED','UNANCHORED','REVIEW','LEASED','RUNNING','STOPPING','FINALIZING','PARTIAL','INTERRUPTED','NEEDS_REVIEW','PROPOSED','TRIAGE','INVESTIGATING','NEW','UNREVIEWED','DISABLED','NOT_CONFIGURED','MISSING'].includes(status)) return 'amber';
  if (['OPEN','ACKNOWLEDGED','IN_PROGRESS','INFO','RETAINED'].includes(status)) return 'blue';
  return 'slate';
}

/** Evidence severity scale used by the backend parser: 0 unknown, 1 informational … 5 critical. */
export const severityLabels = ['Unknown','Informational','Low','Medium','High','Critical'];
export function severityLabel(value: unknown): string { const n = Number(value); return Number.isInteger(n) && n >= 0 && n <= 5 ? severityLabels[n] : 'Unknown'; }

/** Safe property access for loosely typed API documents. */
export function pick<T = any>(value: unknown, ...path: (string|number)[]): T | undefined {
  let cur: any = value;
  for (const key of path) { if (cur == null || typeof cur !== 'object') return undefined; cur = cur[key]; }
  return cur as T;
}
export function asArray<T = any>(value: unknown): T[] { return Array.isArray(value) ? value as T[] : []; }

/** Online state: prefer the server-computed flag; fall back to heartbeat age. */
export function isOnline(c: Row): boolean {
  if (typeof c.online === 'boolean') return c.online && c.state === 'ACTIVE';
  const t = Date.parse(c.last_heartbeat || '');
  return c.state === 'ACTIVE' && Number.isFinite(t) && Date.now() - t < 90000;
}

export function hashPath(page: string, values: Row = {}): string { return routeQuery(page, values); }
