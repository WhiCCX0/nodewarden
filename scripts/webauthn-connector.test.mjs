import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  buildCredentialData,
  isTrustedAncestorChain,
  normalizePublicKeyOptions,
  parseConnectorRequest,
  resolveParentChannel,
} from '../webapp/public/webauthn-connector.js';

function encodeBase64Utf8(value) {
  return Buffer.from(value, 'utf8').toString('base64');
}

const publicKeyOptions = {
  challenge: 'AQID',
  allowCredentials: [{ id: 'BAUG', type: 'public-key', transports: ['usb'] }],
  timeout: 60000,
  rpId: 'vault.example.test',
};

test('parses the official desktop/browser V1 connector request', () => {
  const params = new URLSearchParams({
    data: encodeBase64Utf8(JSON.stringify(publicKeyOptions)),
    parent: encodeURIComponent('file:///C:/Program Files/Bitwarden/resources/app/index.html'),
    btnText: encodeURIComponent('Read security key'),
    btnAwaitingInteractionText: encodeURIComponent('Awaiting security key interaction...'),
    v: '1',
  });
  const request = parseConnectorRequest(params);
  assert.equal(request.parentUrl, 'file:///C:/Program Files/Bitwarden/resources/app/index.html');
  assert.equal(request.parentProtocol, 'file:');
  assert.deepEqual(JSON.parse(request.webauthnJson), publicKeyOptions);
  assert.equal(request.buttonText, 'Read security key');
  assert.equal(request.awaitingText, 'Awaiting security key interaction...');
});

test('keeps V2 parsing compatible with the shared official connector protocol', () => {
  const params = new URLSearchParams({
    data: encodeBase64Utf8(JSON.stringify({ data: JSON.stringify(publicKeyOptions) })),
    parent: encodeURIComponent('chrome-extension://nngceckbapebfimnlniiiahkandclblb/popup/index.html'),
    v: '2',
  });
  assert.deepEqual(JSON.parse(parseConnectorRequest(params).webauthnJson), publicKeyOptions);
});

test('normalizes WebAuthn challenge and allowed credential IDs', () => {
  const normalized = normalizePublicKeyOptions(JSON.stringify(publicKeyOptions));
  assert.deepEqual(Array.from(normalized.challenge), [1, 2, 3]);
  assert.deepEqual(Array.from(normalized.allowCredentials[0].id), [4, 5, 6]);
});

test('emits the exact assertion shape consumed by official Bitwarden clients', () => {
  const output = JSON.parse(buildCredentialData({
    id: 'credential-id',
    rawId: Uint8Array.from([1, 2, 3]).buffer,
    type: 'public-key',
    getClientExtensionResults: () => ({ appid: false }),
    response: {
      authenticatorData: Uint8Array.from([4, 5]).buffer,
      clientDataJSON: Uint8Array.from([6, 7]).buffer,
      signature: Uint8Array.from([8, 9]).buffer,
    },
  }));
  assert.deepEqual(output, {
    id: 'credential-id',
    rawId: 'AQID',
    type: 'public-key',
    extensions: { appid: false },
    response: {
      authenticatorData: 'BAU',
      clientDataJson: 'Bgc',
      signature: 'CAk',
    },
  });
});

test('accepts legacy file and current official desktop parent origins', () => {
  assert.deepEqual(resolveParentChannel({
    parentProtocol: 'file:',
    parentUrl: 'file:///C:/Bitwarden/index.html',
  }, 'https://vault.example.test'), {
    eventOrigin: 'null',
    targetOrigin: 'file:///C:/Bitwarden/index.html',
  });
  assert.deepEqual(resolveParentChannel({
    parentProtocol: 'bw-desktop-file:',
    parentUrl: 'bw-desktop-file://bundle/index.html',
  }, 'https://vault.example.test'), {
    eventOrigin: 'bw-desktop-file://bundle',
    targetOrigin: 'bw-desktop-file://bundle/index.html',
  });
});

test('accepts cross-platform official desktop bundles and rejects malicious file or desktop origins', () => {
  for (const validDesktopUrl of [
    'file:///C:/Program%20Files/Bitwarden/resources/app.asar/index.html?windowId=1#/2fa',
    'file:///C:/Program%20Files%20(x86)/Bitwarden/resources/app.asar/index.html',
    'file:///C:/Users/alice/AppData/Local/Programs/Bitwarden/resources/app.asar/index.html',
    'file:///Applications/Bitwarden.app/Contents/Resources/app.asar/index.html#/2fa',
    'file:///opt/Bitwarden/resources/app.asar/index.html',
    'file:///usr/share/bitwarden/resources/app.asar/index.html',
    'file:///snap/bitwarden/112/resources/app.asar/index.html',
    'file:///app/com.bitwarden.desktop/resources/app.asar/index.html',
    'file:///tmp/.mount_BitwarAbCdEf/resources/app.asar/index.html',
  ]) {
    assert.deepEqual(resolveParentChannel({
      parentProtocol: 'file:',
      parentUrl: validDesktopUrl,
    }, 'https://vault.example.test'), {
      eventOrigin: 'null',
      targetOrigin: validDesktopUrl,
    });
  }

  for (const maliciousUrl of [
    'file://attacker.example/Bitwarden/index.html',
    'file:///C:/Users/victim/Documents/evil/resources/app/index.html',
    'file:///C:/Users/victim/Documents/bitwarden-fake/index.html',
    'file:///home/victim/projects/resources/app.asar/index.html',
    'file:///home/victim/Bitwarden/resources/app.asar/index.html',
    'file:///C:/bitwarden-fake/index.html',
    'file:///C:/Program%20Files/bitwarden-fake/resources/app.asar/index.html',
    'file:///C:/Evil/resources/app.asar/index.html',
    'file:///Users/victim/Applications/Bitwarden.app/Contents/Resources/app.asar/index.html',
    'file:///Users/victim/Downloads/evil.html',
    'file:///Users/victim/Downloads/Bitwarden/index.html',
    'file:///Users/victim/Desktop/Bitwarden/index.html',
    'file:///tmp/evil/Bitwarden/index.html',
    'file:///tmp/.mount_BitwarFakeLongName/resources/app.asar/index.html',
    'file:///C:/Bitwarden/../Users/victim/index.html',
    'file:///C:/Bitwarden/%2e%2e/Users/victim/index.html',
    'bw-desktop-file://evil/index.html',
    'bw-desktop-file://bundle/../evil.html',
    'bw-desktop-file://bundle/sub/index.html',
  ]) {
    const proto = new URL(maliciousUrl).protocol;
    assert.throws(() => resolveParentChannel({
      parentProtocol: proto,
      parentUrl: maliciousUrl,
    }, 'https://vault.example.test', []), /Untrusted parent/);
  }
});

test('accepts configured official extension origins and rejects arbitrary parents', () => {
  const extension = 'chrome-extension://nngceckbapebfimnlniiiahkandclblb';
  assert.deepEqual(resolveParentChannel({
    parentProtocol: 'chrome-extension:',
    parentUrl: `${extension}/popup/index.html`,
  }, 'https://vault.example.test', [extension]), {
    eventOrigin: extension,
    targetOrigin: extension,
  });
  assert.throws(() => resolveParentChannel({
    parentProtocol: 'https:',
    parentUrl: 'https://attacker.example/frame',
  }, 'https://vault.example.test', []), /Untrusted parent/);

  const vaultOrigin = 'https://vault.example.test';
  const fileChannel = { eventOrigin: 'null', targetOrigin: 'file:///C:/Bitwarden/index.html' };
  const desktopChannel = { eventOrigin: 'bw-desktop-file://bundle', targetOrigin: 'bw-desktop-file://bundle/index.html' };
  const chromeExtChannel = { eventOrigin: extension, targetOrigin: extension };
  const mozExt = 'moz-extension://12345678-1234-1234-1234-123456789abc';
  const mozExtChannel = { eventOrigin: mozExt, targetOrigin: mozExt };
  const sameOriginChannel = { eventOrigin: vaultOrigin, targetOrigin: vaultOrigin };

  assert.equal(isTrustedAncestorChain(['null'], fileChannel, vaultOrigin), true);
  assert.equal(isTrustedAncestorChain(['file://'], fileChannel, vaultOrigin), true);
  assert.equal(isTrustedAncestorChain(['https://attacker.example'], fileChannel, vaultOrigin), false);
  assert.equal(isTrustedAncestorChain(['null', 'https://attacker.example'], fileChannel, vaultOrigin), false);
  assert.equal(isTrustedAncestorChain(['bw-desktop-file://bundle'], desktopChannel, vaultOrigin), true);
  assert.equal(isTrustedAncestorChain(['https://attacker.example'], desktopChannel, vaultOrigin), false);

  // When ancestorOrigins is absent (e.g. Firefox), desktop/Chromium schemes fail closed:
  assert.equal(isTrustedAncestorChain(undefined, fileChannel, vaultOrigin), false);
  assert.equal(isTrustedAncestorChain(undefined, desktopChannel, vaultOrigin), false);
  assert.equal(isTrustedAncestorChain(undefined, chromeExtChannel, vaultOrigin), false);
  assert.equal(
    isTrustedAncestorChain(undefined, sameOriginChannel, vaultOrigin, {
      parentWindow: { location: { origin: vaultOrigin } },
    }),
    true,
  );
  assert.equal(
    isTrustedAncestorChain(undefined, sameOriginChannel, vaultOrigin, {
      parentWindow: {
        get location() {
          throw new Error('SecurityError');
        },
      },
    }),
    false,
  );
  assert.equal(isTrustedAncestorChain(undefined, mozExtChannel, vaultOrigin, { referrer: '' }), true);
  assert.equal(
    isTrustedAncestorChain(undefined, mozExtChannel, vaultOrigin, { referrer: 'https://attacker.example/' }),
    false,
  );
});

test('uses the official postMessage message contract and iframe-sized fallback styling', async () => {
  const [html, source, viteConfig] = await Promise.all([
    readFile(new URL('../webapp/public/webauthn-connector.html', import.meta.url), 'utf8'),
    readFile(new URL('../webapp/public/webauthn-connector.js', import.meta.url), 'utf8'),
    readFile(new URL('../webapp/vite.config.ts', import.meta.url), 'utf8'),
  ]);
  assert.match(html, /id="webauthn-button"/);
  assert.match(html, /min-height:\s*40px/);
  assert.match(html, /background:\s*#2563eb/);
  assert.match(source, /post\('info\|ready'\)/);
  assert.match(source, /post\(`success\|\$\{buildCredentialData\(credential\)\}`\)/);
  assert.match(source, /post\(`error\|\$\{browserErrorMessage\(error\)\}`\)/);
  assert.match(source, /event\.data === 'stop'/);
  assert.match(source, /event\.data === 'start'/);
  assert.match(viteConfig, /endsWith\('-connector\.html'\)/);
});
