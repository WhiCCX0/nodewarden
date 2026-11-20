const OFFICIAL_DESKTOP_ORIGIN = 'bw-desktop-file://bundle';

function safeDecodeURIComponent(value) {
  let decoded = String(value || '');
  for (let index = 0; index < 2 && /%[0-9a-f]{2}/i.test(decoded); index += 1) {
    try {
      const next = decodeURIComponent(decoded);
      if (next === decoded) break;
      decoded = next;
    } catch (_error) {
      break;
    }
  }
  return decoded;
}

export function decodeBase64Utf8(value) {
  let normalized = String(value || '').replace(/ /g, '+').replace(/-/g, '+').replace(/_/g, '/');
  normalized += '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
  let binary;
  try {
    binary = atob(normalized);
  } catch (_error) {
    throw new Error('Cannot parse WebAuthn data.');
  }
  const bytes = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (typeof TextDecoder !== 'undefined') return new TextDecoder().decode(bytes);
  return decodeURIComponent(Array.from(bytes, (byte) => `%${byte.toString(16).padStart(2, '0')}`).join(''));
}

export function bytesFromBase64Url(value) {
  let normalized = String(value || '').replace(/-/g, '+').replace(/_/g, '/');
  normalized += '='.repeat((4 - (normalized.length % 4 || 4)) % 4);
  try {
    return Uint8Array.from(atob(normalized), (character) => character.charCodeAt(0));
  } catch (_error) {
    throw new Error('Cannot parse WebAuthn data.');
  }
}

export function base64UrlFromBuffer(value) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = '';
  for (let index = 0; index < bytes.length; index += 1) binary += String.fromCharCode(bytes[index]);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

export function parseConnectorRequest(search) {
  const params = search instanceof URLSearchParams
    ? search
    : new URLSearchParams(String(search || '').replace(/^\?/, ''));
  const parentUrl = safeDecodeURIComponent(params.get('parent'));
  const encodedData = params.get('data');
  if (!parentUrl) throw new Error('No parent.');
  if (!encodedData) throw new Error('No data.');

  let parsedParent;
  try {
    parsedParent = new URL(parentUrl);
  } catch (_error) {
    throw new Error('Invalid parent.');
  }

  let webauthnJson;
  if (params.get('v') === '1') {
    webauthnJson = decodeBase64Utf8(encodedData);
  } else {
    let payload;
    try {
      payload = JSON.parse(decodeBase64Utf8(encodedData));
    } catch (_error) {
      throw new Error('Cannot parse data.');
    }
    if (!payload || (typeof payload.data !== 'string' && typeof payload.data !== 'object')) {
      throw new Error('Cannot parse data.');
    }
    webauthnJson = typeof payload.data === 'string' ? payload.data : JSON.stringify(payload.data);
  }

  return {
    parentUrl,
    parentProtocol: parsedParent.protocol.toLowerCase(),
    parentOrigin: parsedParent.origin,
    webauthnJson,
    buttonText: safeDecodeURIComponent(params.get('btnText')),
    awaitingText: safeDecodeURIComponent(params.get('btnAwaitingInteractionText')),
  };
}

export function normalizePublicKeyOptions(webauthnJson) {
  const source = typeof webauthnJson === 'string' ? JSON.parse(webauthnJson) : webauthnJson;
  if (!source || typeof source !== 'object' || !source.challenge) throw new Error('Cannot parse WebAuthn data.');
  const publicKey = { ...source, challenge: bytesFromBase64Url(source.challenge) };
  if (Array.isArray(source.allowCredentials)) {
    publicKey.allowCredentials = source.allowCredentials.map((credential) => ({
      ...credential,
      id: bytesFromBase64Url(credential?.id),
    }));
  }
  return publicKey;
}

export function buildCredentialData(assertedCredential) {
  const response = assertedCredential?.response;
  if (!assertedCredential || !response?.authenticatorData || !response?.clientDataJSON || !response?.signature) {
    throw new Error('The authenticator returned an incomplete response.');
  }
  return JSON.stringify({
    id: assertedCredential.id,
    rawId: base64UrlFromBuffer(assertedCredential.rawId),
    type: assertedCredential.type,
    extensions: typeof assertedCredential.getClientExtensionResults === 'function'
      ? assertedCredential.getClientExtensionResults()
      : {},
    response: {
      authenticatorData: base64UrlFromBuffer(response.authenticatorData),
      clientDataJson: base64UrlFromBuffer(response.clientDataJSON),
      signature: base64UrlFromBuffer(response.signature),
    },
  });
}

function normalizeAllowedOrigin(value) {
  try {
    const url = new URL(String(value || ''));
    return url.protocol && url.host ? `${url.protocol}//${url.host}` : '';
  } catch (_error) {
    return '';
  }
}

function isExtensionOrigin(origin) {
  return origin.startsWith('chrome-extension://')
    || origin.startsWith('moz-extension://')
    || origin.startsWith('safari-web-extension://');
}

function hasElectronBundleTail(segments, prefixLength) {
  return (
    segments.length === prefixLength + 3 &&
    segments[prefixLength] === 'resources' &&
    (segments[prefixLength + 1] === 'app' || segments[prefixLength + 1] === 'app.asar') &&
    segments[prefixLength + 2] === 'index.html'
  );
}

function isOfficialDesktopInstallSegments(segments) {
  const first = segments[0] || '';

  // Windows anchored install paths (<Drive>:/Bitwarden, Program Files, WindowsApps MSIX, or %LOCALAPPDATA%/Programs/Bitwarden)
  if (/^[a-z]:$/.test(first)) {
    if (segments[1] === 'bitwarden') {
      return (segments.length === 3 && segments[2] === 'index.html') || hasElectronBundleTail(segments, 2);
    }
    if ((segments[1] === 'program files' || segments[1] === 'program files (x86)') && segments[2] === 'bitwarden') {
      return hasElectronBundleTail(segments, 3);
    }
    if (
      segments[1] === 'program files' &&
      segments[2] === 'windowsapps' &&
      /^8bitsolutionsllc\.bitwardendesktop_[a-z0-9._-]+$/.test(segments[3] || '')
    ) {
      return hasElectronBundleTail(segments, 4) || (segments[4] === 'app' && hasElectronBundleTail(segments, 5));
    }
    if (
      segments[1] === 'users' &&
      Boolean(segments[2]) &&
      segments[2] !== 'public' &&
      segments[2] !== 'default' &&
      segments[3] === 'appdata' &&
      segments[4] === 'local' &&
      segments[5] === 'programs' &&
      segments[6] === 'bitwarden'
    ) {
      return hasElectronBundleTail(segments, 7);
    }
    return false;
  }

  // macOS system bundle (/Applications/Bitwarden.app/Contents/Resources/app(.asar)/index.html)
  if (first === 'applications') {
    return segments[1] === 'bitwarden.app' && segments[2] === 'contents' && hasElectronBundleTail(segments, 3);
  }

  // Linux system packages (/opt/Bitwarden, /usr/share/bitwarden, /usr/lib/bitwarden)
  if (first === 'opt') {
    return segments[1] === 'bitwarden' && hasElectronBundleTail(segments, 2);
  }
  if (first === 'usr') {
    return (
      (segments[1] === 'share' || segments[1] === 'lib' || segments[1] === 'lib64') &&
      segments[2] === 'bitwarden' &&
      hasElectronBundleTail(segments, 3)
    );
  }

  // Linux Snap, Flatpak read-only /app mount, and FUSE read-only AppImage mount
  if (first === 'snap') {
    return segments[1] === 'bitwarden' && /^[a-z0-9._-]+$/.test(segments[2] || '') && hasElectronBundleTail(segments, 3);
  }
  if (first === 'app') {
    return (segments[1] === 'com.bitwarden.desktop' || segments[1] === 'bitwarden') && hasElectronBundleTail(segments, 2);
  }
  if (first === 'tmp' && /^\.mount_bitwar[a-z0-9]{6}$/.test(segments[1] || '')) {
    return (
      hasElectronBundleTail(segments, 2) ||
      (segments[2] === 'usr' && segments[3] === 'bin' && hasElectronBundleTail(segments, 4))
    );
  }

  return false;
}

// Note: Chromium serializes legacy file: frames as opaque 'null' in ancestorOrigins/MessageEvent.origin.
// Anchoring parentUrl to official OS install prefixes constrains targetOrigin; full origin isolation
// is provided by modern Bitwarden Desktop's privileged bw-desktop-file://bundle origin + WebAuthn rpId.
function hasUnsafeRawOrEncodedPath(rawPathPart) {
  // Reject raw backslashes, encoded path separators (%2f, %5c), or null bytes (%00) before URL parsing.
  if (rawPathPart.includes('\\') || /%(?:2f|5c|00)/i.test(rawPathPart)) return true;
  if (/(?:^|\/)\.\.?(?:\/|$)/.test(rawPathPart)) return true;
  let decodedOnce;
  try {
    decodedOnce = decodeURIComponent(rawPathPart);
  } catch (_error) {
    return true;
  }
  // Reject double-encoded sequences (e.g. %252e, %252f), control chars, backslashes, and decoded dot-segments
  // before WHATWG new URL() canonicalization can collapse '/Bitwarden/%2e%2e/Bitwarden/'.
  if (
    /%[0-9a-f]{2}/i.test(decodedOnce) ||
    decodedOnce.includes('\\') ||
    /[\u0000-\u001f\u007f]/.test(decodedOnce)
  ) {
    return true;
  }
  return /(?:^|\/)\.\.?(?:\/|$)/.test(decodedOnce);
}

function parseTrustedLegacyDesktopFileTarget(rawUrl) {
  const input = String(rawUrl || '');
  if (!input || !/^file:\/\/\//i.test(input) || /[\u0000-\u001f\u007f]/.test(input)) return '';
  const pathPart = input.slice('file:'.length).split(/[?#]/, 1)[0];
  if (hasUnsafeRawOrEncodedPath(pathPart)) return '';
  let parsed;
  try {
    parsed = new URL(input);
  } catch (_error) {
    return '';
  }
  // Reject remote UNC/SMB hosts (file://attacker.example/...) and embedded credentials.
  if (
    parsed.protocol !== 'file:' ||
    parsed.host ||
    parsed.hostname ||
    parsed.username ||
    parsed.password
  ) {
    return '';
  }
  let decodedPath;
  try {
    decodedPath = decodeURIComponent(parsed.pathname);
  } catch (_error) {
    return '';
  }
  if (decodedPath.includes('//') || decodedPath.includes('\\')) return '';
  const lowerSegments = decodedPath
    .split('/')
    .filter(Boolean)
    .map((segment) => segment.toLowerCase());
  if (
    lowerSegments.length < 3 ||
    lowerSegments[lowerSegments.length - 1] !== 'index.html' ||
    lowerSegments.some((seg) => seg === '.' || seg === '..')
  ) {
    return '';
  }
  return isOfficialDesktopInstallSegments(lowerSegments) ? input : '';
}

function parseTrustedOfficialDesktopTarget(rawUrl) {
  const input = String(rawUrl || '');
  if (!input || !/^bw-desktop-file:\/\/bundle\//i.test(input) || /[\u0000-\u001f\u007f]/.test(input)) return '';
  const pathPart = input.slice('bw-desktop-file://bundle'.length).split(/[?#]/, 1)[0];
  if (hasUnsafeRawOrEncodedPath(pathPart)) return '';
  let parsed;
  try {
    parsed = new URL(input);
  } catch (_error) {
    return '';
  }
  if (
    parsed.protocol !== 'bw-desktop-file:' ||
    parsed.host !== 'bundle' ||
    parsed.username ||
    parsed.password ||
    parsed.pathname.toLowerCase() !== '/index.html'
  ) {
    return '';
  }
  return input;
}

export function isTrustedAncestorChain(ancestorOrigins, channel, connectorOrigin = '', runtime = {}) {
  if (ancestorOrigins && typeof ancestorOrigins.length === 'number') {
    if (ancestorOrigins.length !== 1) return false;
    const parentAncestor = String(ancestorOrigins[0] || '');
    if (channel.eventOrigin === 'null') {
      return parentAncestor === 'file://' || parentAncestor === 'null';
    }
    if (channel.eventOrigin === OFFICIAL_DESKTOP_ORIGIN) {
      return parentAncestor === OFFICIAL_DESKTOP_ORIGIN || parentAncestor === 'bw-desktop-file://';
    }
    return parentAncestor === channel.eventOrigin;
  }

  // Fallback for engines without location.ancestorOrigins (e.g. Firefox/Gecko):
  // Electron (file:, bw-desktop-file:), Chromium (chrome-extension:), and WebKit
  // (safari-web-extension:) always expose ancestorOrigins, so missing ancestorOrigins
  // for those schemes indicates cross-browser parent spoofing and must fail closed.
  if (connectorOrigin && channel.eventOrigin === connectorOrigin) {
    try {
      return Boolean(runtime.parentWindow) && runtime.parentWindow.location.origin === connectorOrigin;
    } catch (_error) {
      return false;
    }
  }
  if (channel.eventOrigin.startsWith('moz-extension://')) {
    const referrer = String(runtime.referrer || '');
    if (/^https?:\/\//i.test(referrer)) return false;
    return true;
  }
  return false;
}

export function resolveParentChannel(request, connectorOrigin, allowedOrigins = []) {
  if (request.parentProtocol === 'file:') {
    const fileTarget = parseTrustedLegacyDesktopFileTarget(request.parentUrl);
    if (!fileTarget) throw new Error('Untrusted parent.');
    return { eventOrigin: 'null', targetOrigin: fileTarget };
  }

  const parentOrigin = normalizeAllowedOrigin(request.parentUrl);
  if (!parentOrigin) throw new Error('Invalid parent.');
  if (parentOrigin === connectorOrigin) {
    return { eventOrigin: parentOrigin, targetOrigin: parentOrigin };
  }
  if (parentOrigin === OFFICIAL_DESKTOP_ORIGIN) {
    const desktopTarget = parseTrustedOfficialDesktopTarget(request.parentUrl);
    if (!desktopTarget) throw new Error('Untrusted parent.');
    return { eventOrigin: parentOrigin, targetOrigin: desktopTarget };
  }
  const trustedOrigins = allowedOrigins.map(normalizeAllowedOrigin).filter(Boolean);
  if (isExtensionOrigin(parentOrigin) && trustedOrigins.includes(parentOrigin)) {
    return { eventOrigin: parentOrigin, targetOrigin: parentOrigin };
  }
  throw new Error('Untrusted parent.');
}

async function loadAllowedParentOrigins() {
  try {
    const response = await fetch('/api/web-bootstrap', {
      headers: { Accept: 'application/json' },
      credentials: 'omit',
    });
    if (!response.ok) return [];
    const body = await response.json();
    return Array.isArray(body?.webAuthnAllowedOrigins) ? body.webAuthnAllowedOrigins : [];
  } catch (_error) {
    return [];
  }
}

function browserErrorMessage(error) {
  return error?.message || String(error || 'WebAuthn failed.');
}

async function initializePage() {
  const button = document.getElementById('webauthn-button');
  if (!button) return;

  let request;
  let publicKey;
  let channel;
  let stopWebAuthn = false;
  let sentSuccess = false;
  let running = false;

  const defaultText = 'Read security key';
  const awaitingDefaultText = 'Awaiting security key interaction...';

  function setButton(awaiting = false) {
    button.textContent = awaiting
      ? request?.awaitingText || awaitingDefaultText
      : request?.buttonText || defaultText;
    button.setAttribute('aria-disabled', awaiting ? 'true' : 'false');
    button.setAttribute('aria-busy', awaiting ? 'true' : 'false');
    button.onclick = awaiting ? null : executeWebAuthn;
  }

  function post(message) {
    window.parent.postMessage(message, channel.targetOrigin);
  }

  function reportError(error) {
    if (channel) post(`error|${browserErrorMessage(error)}`);
    setButton(false);
  }

  async function executeWebAuthn() {
    if (running || sentSuccess) return;
    if (stopWebAuthn) {
      stopWebAuthn = false;
      setButton(false);
      return;
    }
    running = true;
    setButton(true);
    try {
      const credential = await navigator.credentials.get({ publicKey });
      if (!credential) throw new Error('No security key was selected.');
      if (sentSuccess) return;
      post(`success|${buildCredentialData(credential)}`);
      sentSuccess = true;
    } catch (error) {
      reportError(error);
    } finally {
      running = false;
    }
  }

  try {
    if (window.parent === window || window.parent !== window.top) {
      throw new Error('Untrusted parent.');
    }
    request = parseConnectorRequest(window.location.search);
    publicKey = normalizePublicKeyOptions(request.webauthnJson);
    channel = resolveParentChannel(request, window.location.origin, await loadAllowedParentOrigins());
    if (
      !isTrustedAncestorChain(window.location.ancestorOrigins, channel, window.location.origin, {
        parentWindow: window.parent,
        referrer: document.referrer,
      })
    ) {
      channel = null;
      throw new Error('Untrusted parent.');
    }
    setButton(false);
  } catch (error) {
    button.textContent = browserErrorMessage(error);
    button.setAttribute('aria-disabled', 'true');
    return;
  }

  if (!navigator.credentials || typeof navigator.credentials.get !== 'function' || !window.PublicKeyCredential) {
    reportError(new Error('WebAuthn is not supported in this browser.'));
    return;
  }

  window.addEventListener('message', (event) => {
    if (event.source !== window.parent || event.origin !== channel.eventOrigin) return;
    if (event.data === 'stop') {
      stopWebAuthn = true;
      setButton(false);
    } else if (event.data === 'start' && stopWebAuthn) {
      stopWebAuthn = false;
      void executeWebAuthn();
    }
  });

  post('info|ready');
  const isSafari = /Safari\//.test(navigator.userAgent)
    && !/(?:Chrome|Chromium|CriOS|FxiOS|Edg|EdgiOS|OPR)\//.test(navigator.userAgent);
  if (!isSafari) void executeWebAuthn();
}

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => void initializePage(), { once: true });
  } else {
    void initializePage();
  }
}
