import type { Env, User } from '../types';

const YUBIKEY_PUBLIC_ID_LENGTH = 12;
const YUBIKEY_MIN_OTP_LENGTH = 32;
const YUBIKEY_MAX_OTP_LENGTH = 48;
const YUBICO_DEFAULT_VALIDATION_URL = 'https://api.yubico.com/wsapi/2.0/verify';
const YUBICO_GET_API_KEY_URL = 'https://upgrade.yubico.com/getapikey/';
const YUBICO_REQUEST_TIMEOUT_MS = 8000;
const MODHEX_RE = /^[cbdefghijklnrtuv]+$/;

export interface YubicoApiCredentials {
  clientId: string;
  secretKey: string;
}

export function normalizeYubiKeyOtp(input: string): string {
  return String(input || '').replace(/\s+/g, '').toLowerCase();
}

export function yubiKeyPublicIdFromOtp(input: string): string | null {
  const otp = normalizeYubiKeyOtp(input);
  if (otp.length === YUBIKEY_PUBLIC_ID_LENGTH && MODHEX_RE.test(otp)) return otp;
  if (otp.length < YUBIKEY_MIN_OTP_LENGTH || otp.length > YUBIKEY_MAX_OTP_LENGTH) return null;
  if (!MODHEX_RE.test(otp)) return null;
  return otp.slice(0, YUBIKEY_PUBLIC_ID_LENGTH);
}

export function isYubiKeyPublicId(input: string): boolean {
  const value = normalizeYubiKeyOtp(input);
  return value.length === YUBIKEY_PUBLIC_ID_LENGTH && MODHEX_RE.test(value);
}

export function isYubiKeyOtp(input: string): boolean {
  const otp = normalizeYubiKeyOtp(input);
  return otp.length >= YUBIKEY_MIN_OTP_LENGTH && otp.length <= YUBIKEY_MAX_OTP_LENGTH && MODHEX_RE.test(otp);
}

export function userYubiKeyPublicIds(user: User): string[] {
  return [
    user.yubikeyKey1,
    user.yubikeyKey2,
    user.yubikeyKey3,
    user.yubikeyKey4,
    user.yubikeyKey5,
  ].map((value) => String(value || '').trim().toLowerCase()).filter(Boolean);
}

export function isYubiKeyEnabled(user: User): boolean {
  return userYubiKeyPublicIds(user).length > 0;
}

function randomNonce(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(bytes).map((byte) => byte.toString(16).padStart(2, '0')).join('');
}

function parseYubicoResponse(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split(/\r?\n/)) {
    const idx = line.indexOf('=');
    if (idx <= 0) continue;
    out[line.slice(0, idx)] = line.slice(idx + 1);
  }
  return out;
}

function base64ToBytes(input: string): Uint8Array {
  const binary = atob(input);
  const out = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) out[index] = binary.charCodeAt(index);
  return out;
}

function bytesToBase64(input: Uint8Array): string {
  let binary = '';
  for (const byte of input) binary += String.fromCharCode(byte);
  return btoa(binary);
}

async function hmacSha1Base64(base64Key: string, message: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    base64ToBytes(base64Key),
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign']
  );
  return bytesToBase64(new Uint8Array(await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message))));
}

function constantTimeStringEquals(a: string, b: string): boolean {
  const aBytes = new TextEncoder().encode(a);
  const bBytes = new TextEncoder().encode(b);
  let diff = aBytes.length ^ bBytes.length;
  for (let index = 0; index < aBytes.length && index < bBytes.length; index += 1) {
    diff |= aBytes[index] ^ bBytes[index];
  }
  return diff === 0;
}

function canonicalQuery(params: URLSearchParams): string {
  return Array.from(params.entries())
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([key, value]) => `${key}=${value}`)
    .join('&');
}

function isBlockedIpv4Host(hostname: string): boolean {
  const parts = hostname.split('.');
  if (parts.length !== 4) return false;
  const octets = parts.map((part) => (/^\d{1,3}$/.test(part) ? Number(part) : -1));
  if (octets.some((value) => value < 0 || value > 255)) return true;
  const [a, b, c] = octets;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && (b === 0 || b === 168)) ||
    (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
    (a === 203 && b === 0 && c === 113) ||
    a >= 224
  );
}

function isAllowedValidationHost(hostname: string): boolean {
  const normalized = hostname.trim().toLowerCase().replace(/^\[|\]$/g, '').replace(/\.$/, '');
  if (!normalized) return false;
  if (
    normalized === 'localhost' ||
    normalized === 'localhost.localdomain' ||
    normalized.endsWith('.localhost') ||
    normalized.endsWith('.localhost.localdomain') ||
    normalized.endsWith('.local') ||
    normalized.endsWith('.internal') ||
    normalized.endsWith('.home.arpa') ||
    normalized.endsWith('.lan') ||
    normalized === 'metadata.google.internal' ||
    normalized.endsWith('.nip.io') ||
    normalized.endsWith('.sslip.io') ||
    normalized.endsWith('.xip.io') ||
    normalized.endsWith('.localtest.me') ||
    normalized.endsWith('.lvh.me')
  ) {
    return false;
  }
  if (isBlockedIpv4Host(normalized)) return false;
  if (normalized.includes(':')) {
    if (
      normalized === '::' ||
      normalized === '::1' ||
      normalized.startsWith('fe80:') ||
      normalized.startsWith('fc') ||
      normalized.startsWith('fd') ||
      normalized.startsWith('ff') ||
      normalized.startsWith('2001:db8:') ||
      normalized.startsWith('2001:0db8:') ||
      normalized.includes('::ffff:')
    ) {
      return false;
    }
  }
  return true;
}

export function parseValidationUrls(env: Env): URL[] {
  const configured = String(env['globalSettings__yubico__validationUrls'] || env.YUBICO_VALIDATION_URLS || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  if (configured.length === 0) {
    return [new URL(YUBICO_DEFAULT_VALIDATION_URL)];
  }

  const allowed: URL[] = [];
  for (const candidate of configured) {
    try {
      const parsed = new URL(candidate);
      if (parsed.protocol !== 'https:') continue;
      if (parsed.username || parsed.password || parsed.hash) continue;
      if (!isAllowedValidationHost(parsed.hostname)) continue;
      allowed.push(parsed);
    } catch {
      continue;
    }
  }
  return allowed;
}

async function fetchYubicoEndpoint(url: string | URL, init: RequestInit): Promise<Response> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), YUBICO_REQUEST_TIMEOUT_MS);
  try {
    return await fetch(url.toString(), {
      ...init,
      redirect: 'manual',
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timeout);
  }
}

export async function requestYubicoApiCredentials(email: string, otpInput: string): Promise<YubicoApiCredentials | null> {
  const normalizedEmail = String(email || '').trim().toLowerCase();
  const otp = normalizeYubiKeyOtp(otpInput);
  if (!normalizedEmail || !isYubiKeyOtp(otp)) return null;

  const body = new URLSearchParams();
  body.set('email', normalizedEmail);
  body.set('otp', otp);
  body.set('terms_conditions', 'consented');

  let response: Response;
  try {
    response = await fetchYubicoEndpoint(YUBICO_GET_API_KEY_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body,
    });
  } catch {
    return null;
  }
  if (!response.ok) return null;

  const html = await response.text();
  const clientId = /Client ID:<\/th>\s*<td><b>(\d+)<\/b>/i.exec(html)?.[1]?.trim() || '';
  const secretKey = /Secret key:<\/th>\s*<td><code>([^<]+)<\/code>/i.exec(html)?.[1]?.trim() || '';
  return clientId && secretKey ? { clientId, secretKey } : null;
}

export async function verifyYubicoOtp(
  env: Env,
  otpInput: string,
  credentials: YubicoApiCredentials | null
): Promise<boolean> {
  const otp = normalizeYubiKeyOtp(otpInput);
  if (!isYubiKeyOtp(otp)) return false;

  const clientId = String(credentials?.clientId || '').trim();
  const secretKey = String(credentials?.secretKey || '').trim();
  if (!clientId || !secretKey) return false;

  const nonce = randomNonce();
  const params = new URLSearchParams({
    id: clientId,
    nonce,
    otp,
  });
  try {
    params.set('h', await hmacSha1Base64(secretKey, canonicalQuery(params)));
  } catch {
    return false;
  }

  for (const baseUrl of parseValidationUrls(env)) {
    try {
      const requestUrl = new URL(baseUrl.toString());
      for (const [key, value] of params.entries()) {
        requestUrl.searchParams.set(key, value);
      }
      const response = await fetchYubicoEndpoint(requestUrl, { method: 'GET' });
      if (!response.ok) continue;
      const parsed = parseYubicoResponse(await response.text());
      if (parsed.otp !== otp || parsed.nonce !== nonce || parsed.status !== 'OK') continue;
      if (!parsed.h) continue;
      const signedParams = new URLSearchParams();
      for (const [key, value] of Object.entries(parsed)) {
        if (key !== 'h') signedParams.set(key, value);
      }
      if (!constantTimeStringEquals(await hmacSha1Base64(secretKey, canonicalQuery(signedParams)), parsed.h)) continue;
      return true;
    } catch {
      continue;
    }
  }

  return false;
}
