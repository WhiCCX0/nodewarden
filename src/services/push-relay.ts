import type { Env } from '../types';

const PUSH_RELAY_URI = 'https://push.bitwarden.com';
const PUSH_IDENTITY_URI = 'https://identity.bitwarden.com';
const INSTALLATIONS_URI = 'https://api.bitwarden.com/installations';
const PUSH_INSTALLATION_ID_KEY = 'push.installation.id';
const PUSH_INSTALLATION_KEY_KEY = 'push.installation.key';
const PUSH_REQUEST_TIMEOUT_MS = 5000;

interface CachedPushAccessToken {
  token: string;
  expiresAt: number;
}

let cachedPushCredentials: { id: string; key: string } | null = null;
let cachedPushAccessToken: CachedPushAccessToken | null = null;
let inflightInstallationPromise: Promise<{ id: string; key: string } | null> | null = null;

export function resetPushRelayCacheForTests(): void {
  cachedPushCredentials = null;
  cachedPushAccessToken = null;
  inflightInstallationPromise = null;
}

async function fetchPushEndpoint(url: string, init: RequestInit, errorMessage: string): Promise<Response | null> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), PUSH_REQUEST_TIMEOUT_MS);
  try {
    return await fetch(url, { ...init, redirect: 'manual', signal: controller.signal });
  } catch (error) {
    console.error(errorMessage, error);
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

function randomInstallationEmail(): string {
  const bytes = new Uint8Array(10);
  crypto.getRandomValues(bytes);
  const localPart = Array.from(bytes, (byte) => (byte % 36).toString(36)).join('');
  return `${localPart}@nodewarden.app`;
}

async function getPushInstallationCredentials(db: D1Database): Promise<{ id: string; key: string } | null> {
  if (cachedPushCredentials) return cachedPushCredentials;
  const result = await db
    .prepare('SELECT key, value FROM config WHERE key IN (?, ?)')
    .bind(PUSH_INSTALLATION_ID_KEY, PUSH_INSTALLATION_KEY_KEY)
    .all<{ key: string; value: string }>();
  const map = new Map((result.results || []).map((row) => [row.key, String(row.value || '').trim()]));
  const id = map.get(PUSH_INSTALLATION_ID_KEY) || '';
  const key = map.get(PUSH_INSTALLATION_KEY_KEY) || '';
  if (!id || !key) return null;
  cachedPushCredentials = { id, key };
  return cachedPushCredentials;
}

export async function ensurePushInstallationCredentials(db: D1Database): Promise<{ id: string; key: string } | null> {
  const existing = await getPushInstallationCredentials(db);
  if (existing) return existing;

  if (inflightInstallationPromise) {
    return inflightInstallationPromise;
  }

  inflightInstallationPromise = (async () => {
    const rechecked = await getPushInstallationCredentials(db);
    if (rechecked) return rechecked;

    const response = await fetchPushEndpoint(
      INSTALLATIONS_URI,
      {
        method: 'POST',
        headers: {
          accept: 'application/json',
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          email: randomInstallationEmail(),
        }),
      },
      'Failed to request Bitwarden push installation:'
    );
    if (!response) return null;

    if (!response.ok) {
      console.error('Failed to request Bitwarden push installation:', response.status, await response.text().catch(() => ''));
      return null;
    }

    const body = (await response.json().catch(() => null)) as { id?: string; Id?: string; key?: string; Key?: string; enabled?: boolean; Enabled?: boolean } | null;
    const id = String(body?.id || body?.Id || '').trim();
    const key = String(body?.key || body?.Key || '').trim();
    if (!id || !key) {
      console.error('Bitwarden push installation response did not include id/key');
      return null;
    }

    await db.batch([
      db.prepare('INSERT INTO config(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind(PUSH_INSTALLATION_ID_KEY, id),
      db.prepare('INSERT INTO config(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value').bind(PUSH_INSTALLATION_KEY_KEY, key),
    ]);
    cachedPushCredentials = { id, key };
    return cachedPushCredentials;
  })().finally(() => {
    inflightInstallationPromise = null;
  });

  return inflightInstallationPromise;
}

async function getPushAccessToken(env: Env): Promise<string | null> {
  const credentials = await ensurePushInstallationCredentials(env.DB);
  if (!credentials) return null;

  const now = Date.now();
  if (cachedPushAccessToken && cachedPushAccessToken.expiresAt > now + 30_000) {
    return cachedPushAccessToken.token;
  }

  const params = new URLSearchParams({
    grant_type: 'client_credentials',
    scope: 'api.push',
    client_id: `installation.${credentials.id}`,
    client_secret: credentials.key,
  });

  const response = await fetchPushEndpoint(
    `${PUSH_IDENTITY_URI}/connect/token`,
    {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: params.toString(),
    },
    'Failed to get Bitwarden push relay token:'
  );
  if (!response) return null;

  if (!response.ok) {
    console.error('Failed to get Bitwarden push relay token:', response.status, await response.text().catch(() => ''));
    return null;
  }

  const body = (await response.json().catch(() => null)) as { access_token?: string; expires_in?: number } | null;
  const token = String(body?.access_token || '').trim();
  if (!token) {
    console.error('Bitwarden push relay token response did not include an access_token');
    return null;
  }

  const expiresInSeconds = Math.max(60, Number(body?.expires_in || 3600));
  cachedPushAccessToken = {
    token,
    expiresAt: now + Math.floor(expiresInSeconds * 500),
  };
  return token;
}

async function postToPushRelay(env: Env, path: string, body?: unknown): Promise<boolean> {
  const token = await getPushAccessToken(env);
  if (!token) return false;

  const response = await fetchPushEndpoint(
    `${PUSH_RELAY_URI}${path}`,
    {
      method: 'POST',
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${token}`,
        ...(body === undefined ? {} : { 'content-type': 'application/json' }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    },
    `Bitwarden push relay request failed: ${path}`
  );
  if (!response) return false;

  if (!response.ok) {
    console.error('Bitwarden push relay request failed:', path, response.status, await response.text().catch(() => ''));
    return false;
  }

  return true;
}

function mobilePayloadFromSignalR(updateType: number, userId: string, revisionDate: string, payload: Record<string, unknown> | null | undefined): Record<string, unknown> {
  const source = payload || {};
  const id = source.Id ?? source.id;
  const organizationId = source.OrganizationId ?? source.organizationId ?? null;
  const collectionIds = source.CollectionIds ?? source.collectionIds ?? null;

  if (id != null) {
    return {
      id,
      userId: source.UserId ?? source.userId ?? userId,
      organizationId,
      collectionIds,
      revisionDate: source.RevisionDate ?? source.revisionDate ?? revisionDate,
    };
  }

  return {
    userId: source.UserId ?? source.userId ?? userId,
    date: source.Date ?? source.date ?? revisionDate,
  };
}

export async function registerMobilePushDevice(
  env: Env,
  input: {
    userId: string;
    deviceIdentifier: string;
    type: number;
    pushUuid: string;
    pushToken: string;
  }
): Promise<boolean> {
  const credentials = await ensurePushInstallationCredentials(env.DB);
  if (!credentials) return false;

  return postToPushRelay(env, '/push/register', {
    deviceId: input.pushUuid,
    pushToken: input.pushToken,
    userId: input.userId,
    type: input.type,
    identifier: input.deviceIdentifier,
    installationId: credentials.id,
  });
}

export async function unregisterMobilePushDevice(env: Env, pushUuid: string | null | undefined): Promise<boolean> {
  const normalized = String(pushUuid || '').trim();
  if (!normalized) return false;
  return postToPushRelay(env, '/push/delete', { id: normalized });
}

export async function notifyMobilePush(
  env: Env,
  input: {
    userId: string;
    updateType: number;
    revisionDate: string;
    contextId: string | null;
    payload: Record<string, unknown> | null | undefined;
  }
): Promise<void> {
  const hasPushDevice = await env.DB
    .prepare('SELECT 1 FROM devices WHERE user_id = ? AND push_token IS NOT NULL AND push_token <> ? LIMIT 1')
    .bind(input.userId, '')
    .first<{ '1': number }>();
  if (!hasPushDevice) return;

  let actingPushUuid: string | null = null;
  if (input.contextId) {
    const row = await env.DB
      .prepare('SELECT push_uuid FROM devices WHERE user_id = ? AND device_identifier = ? LIMIT 1')
      .bind(input.userId, input.contextId)
      .first<{ push_uuid: string | null }>();
    actingPushUuid = row?.push_uuid ?? null;
  }

  await postToPushRelay(env, '/push/send', {
    userId: input.userId,
    organizationId: null,
    deviceId: actingPushUuid,
    identifier: input.contextId,
    type: input.updateType,
    payload: mobilePayloadFromSignalR(input.updateType, input.userId, input.revisionDate, input.payload),
    clientType: null,
    installationId: null,
  });
}
