import {
  isWebAuthnAvailable,
  listPasskeys,
  registerPasskey,
  revokePasskey,
} from './webauthn-client.js';

let previousFocus = null;

function elements() {
  return {
    modal: document.getElementById('passkey-manager-modal'),
    panel: document.querySelector('#passkey-manager-modal .passkey-manager__panel'),
    trigger: document.getElementById('passkey-manager-trigger'),
    close: document.getElementById('passkey-manager-close'),
    cancel: document.getElementById('passkey-manager-cancel'),
    form: document.getElementById('passkey-registration-form'),
    button: document.getElementById('passkey-register-btn'),
    password: document.getElementById('passkey-current-password'),
    label: document.getElementById('passkey-device-label'),
    list: document.getElementById('passkey-credential-list'),
    count: document.getElementById('passkey-count'),
    feedback: document.getElementById('passkey-manager-feedback'),
  };
}

function setFeedback(message, kind = 'info') {
  const { feedback } = elements();
  if (!feedback) return;
  feedback.textContent = message;
  feedback.dataset.kind = kind;
}

function readableDate(timestamp) {
  if (!timestamp) return 'Never used';
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: 'medium',
    timeStyle: 'short',
  }).format(new Date(timestamp * 1000));
}

function metadataBadge(text) {
  const badge = document.createElement('span');
  badge.className = 'passkey-card__badge';
  badge.textContent = text;
  return badge;
}

function renderPasskeys(credentials) {
  const { list, count } = elements();
  if (!list || !count) return;
  list.replaceChildren();
  count.textContent = String(credentials.length);
  if (!credentials.length) {
    const empty = document.createElement('p');
    empty.className = 'passkey-list__empty';
    empty.textContent = 'No passkeys registered yet.';
    list.append(empty);
    return;
  }

  credentials.forEach((credential) => {
    const card = document.createElement('article');
    card.className = 'passkey-card';

    const details = document.createElement('div');
    details.className = 'passkey-card__details';
    const title = document.createElement('h4');
    title.textContent = credential.device_label || `Passkey ••••${credential.id.slice(-6)}`;
    const meta = document.createElement('p');
    meta.textContent = `Added ${readableDate(credential.created_at)} · Last used ${readableDate(credential.last_used_at)}`;
    const badges = document.createElement('div');
    badges.className = 'passkey-card__badges';
    (credential.transports || []).forEach((transport) => {
      badges.append(metadataBadge(transport));
    });
    if (credential.backup_eligible) {
      badges.append(metadataBadge(credential.backup_state ? 'synced' : 'sync capable'));
    }
    details.append(title, meta, badges);

    const remove = document.createElement('button');
    remove.type = 'button';
    remove.className = 'soc-btn soc-btn-outline passkey-remove-btn';
    remove.dataset.credentialId = credential.id;
    remove.textContent = 'Remove';
    remove.setAttribute('aria-label', `Remove ${title.textContent}`);

    card.append(details, remove);
    list.append(card);
  });
}

async function refreshPasskeys() {
  const { list } = elements();
  if (list) list.innerHTML = '<p class="passkey-list__empty">Loading passkeys...</p>';
  try {
    const data = await listPasskeys();
    renderPasskeys(data.credentials || []);
  } catch (error) {
    renderPasskeys([]);
    setFeedback(error.message || 'Unable to load passkeys', 'error');
  }
}

function openManager() {
  const { modal, panel, password } = elements();
  if (!modal) return;
  previousFocus = document.getElementById('analyst-avatar-btn') || document.activeElement;
  window.closeAnalystMenu?.();
  modal.hidden = false;
  modal.setAttribute('aria-hidden', 'false');
  document.body.style.overflow = 'hidden';
  setFeedback('');
  void refreshPasskeys();
  window.setTimeout(() => (password || panel)?.focus(), 0);
}

function closeManager() {
  const { modal, form } = elements();
  if (!modal) return;
  modal.hidden = true;
  modal.setAttribute('aria-hidden', 'true');
  document.body.style.overflow = '';
  form?.reset();
  previousFocus?.focus?.();
}

async function handleRegistration(event) {
  event.preventDefault();
  const { button, password, label } = elements();
  if (!password?.value) {
    setFeedback('Enter your current password first.', 'error');
    password?.focus();
    return;
  }
  button.disabled = true;
  button.setAttribute('aria-busy', 'true');
  button.textContent = 'Waiting for authenticator...';
  setFeedback('Follow the browser prompt to create your passkey.');
  try {
    await registerPasskey(password.value, label?.value.trim() || '');
    password.value = '';
    if (label) label.value = '';
    setFeedback('Passkey added successfully.', 'success');
    await refreshPasskeys();
  } catch (error) {
    setFeedback(error.message || 'Unable to add passkey', 'error');
  } finally {
    button.disabled = false;
    button.removeAttribute('aria-busy');
    button.textContent = 'Add passkey';
  }
}

async function handleRemoval(button) {
  const { password } = elements();
  if (!password?.value) {
    setFeedback('Enter your current password before removing a passkey.', 'error');
    password?.focus();
    return;
  }
  if (!window.confirm('Remove this passkey from your account?')) return;
  button.disabled = true;
  button.textContent = 'Removing...';
  try {
    await revokePasskey(button.dataset.credentialId, password.value);
    password.value = '';
    setFeedback('Passkey removed.', 'success');
    await refreshPasskeys();
  } catch (error) {
    setFeedback(error.message || 'Unable to remove passkey', 'error');
    button.disabled = false;
    button.textContent = 'Remove';
  }
}

function keepFocusInside(event) {
  const { modal } = elements();
  if (!modal || modal.hidden || event.key !== 'Tab') return;
  const focusable = [...modal.querySelectorAll(
    'button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])',
  )];
  if (!focusable.length) return;
  const first = focusable[0];
  const last = focusable[focusable.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

export function initPasskeyManager() {
  const { modal, trigger, close, cancel, form, list } = elements();
  if (!modal || !trigger) return;
  if (!isWebAuthnAvailable()) {
    trigger.disabled = true;
    trigger.title = 'Passkeys are not supported by this browser';
  }
  trigger.addEventListener('click', openManager);
  close?.addEventListener('click', closeManager);
  cancel?.addEventListener('click', closeManager);
  form?.addEventListener('submit', (event) => void handleRegistration(event));
  list?.addEventListener('click', (event) => {
    const button = event.target.closest('.passkey-remove-btn');
    if (button) void handleRemoval(button);
  });
  modal.addEventListener('click', (event) => {
    if (event.target === modal) closeManager();
  });
  modal.addEventListener('keydown', keepFocusInside);
  document.addEventListener('keydown', (event) => {
    if (event.key === 'Escape' && !modal.hidden) closeManager();
  });
}
