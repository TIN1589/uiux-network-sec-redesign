/** Browser-side WebAuthn encoding and same-origin API helpers. */

function base64urlToBuffer(value) {
  const padding = '='.repeat((4 - (value.length % 4)) % 4);
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/') + padding;
  const decoded = window.atob(base64);
  return Uint8Array.from(decoded, (character) => character.charCodeAt(0)).buffer;
}

function bufferToBase64url(value) {
  const bytes = new Uint8Array(value);
  let binary = '';
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte);
  });
  return window.btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function creationOptionsFromJSON(options) {
  return {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    user: {
      ...options.user,
      id: base64urlToBuffer(options.user.id),
    },
    excludeCredentials: (options.excludeCredentials || []).map((credential) => ({
      ...credential,
      id: base64urlToBuffer(credential.id),
    })),
  };
}

function requestOptionsFromJSON(options) {
  return {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((credential) => ({
      ...credential,
      id: base64urlToBuffer(credential.id),
    })),
  };
}

function credentialToJSON(credential) {
  const response = {
    clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
  };
  if ('attestationObject' in credential.response) {
    response.attestationObject = bufferToBase64url(credential.response.attestationObject);
    response.transports = credential.response.getTransports?.() || [];
  }
  if ('authenticatorData' in credential.response) {
    response.authenticatorData = bufferToBase64url(credential.response.authenticatorData);
    response.signature = bufferToBase64url(credential.response.signature);
    response.userHandle = credential.response.userHandle
      ? bufferToBase64url(credential.response.userHandle)
      : null;
  }
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment || null,
    response,
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

async function responseJSON(response) {
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || data.error || 'Passkey request failed');
  }
  return data;
}

export function isWebAuthnAvailable() {
  return Boolean(window.PublicKeyCredential && navigator.credentials);
}

export async function fetchCsrfToken() {
  const response = await fetch('/api/auth/csrf-token', {
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { Accept: 'application/json' },
  });
  const data = await responseJSON(response);
  return data.csrf_token;
}

export async function registerPasskey(password, deviceLabel) {
  const csrfToken = await fetchCsrfToken();
  const optionsResponse = await fetch('/api/auth/webauthn/register/options', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken,
    },
    body: JSON.stringify({ password }),
  });
  const options = await responseJSON(optionsResponse);
  const credential = await navigator.credentials.create({
    publicKey: creationOptionsFromJSON(options),
  });
  if (!credential) throw new Error('Passkey creation was cancelled');

  const verifyResponse = await fetch('/api/auth/webauthn/register/verify', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken,
    },
    body: JSON.stringify({
      credential: credentialToJSON(credential),
      device_label: deviceLabel || null,
    }),
  });
  return responseJSON(verifyResponse);
}

export async function authenticateWithPasskey(remember = true) {
  const csrfToken = await fetchCsrfToken();
  const optionsResponse = await fetch('/api/auth/webauthn/authenticate/options', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json',
      'X-CSRF-Token': csrfToken,
    },
  });
  const options = await responseJSON(optionsResponse);
  const credential = await navigator.credentials.get({
    publicKey: requestOptionsFromJSON(options),
  });
  if (!credential) throw new Error('Passkey sign-in was cancelled');

  const verifyResponse = await fetch('/api/auth/webauthn/authenticate/verify', {
    method: 'POST',
    credentials: 'same-origin',
    headers: {
      Accept: 'application/json',
      'Content-Type': 'application/json',
      'X-CSRF-Token': csrfToken,
    },
    body: JSON.stringify({
      credential: credentialToJSON(credential),
      remember,
    }),
  });
  return responseJSON(verifyResponse);
}

export async function listPasskeys() {
  const response = await fetch('/api/auth/webauthn/credentials', {
    credentials: 'same-origin',
    cache: 'no-store',
    headers: { Accept: 'application/json' },
  });
  return responseJSON(response);
}

export async function revokePasskey(credentialId, password) {
  const csrfToken = await fetchCsrfToken();
  const response = await fetch(
    `/api/auth/webauthn/credentials/${encodeURIComponent(credentialId)}`,
    {
      method: 'DELETE',
      credentials: 'same-origin',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        'X-CSRF-Token': csrfToken,
      },
      body: JSON.stringify({ password }),
    },
  );
  return responseJSON(response);
}
