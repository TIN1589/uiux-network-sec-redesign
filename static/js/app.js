/**
 * SOC COMMAND CENTER - APPLICATION COORDINATOR
 * Modern Vanilla JavaScript ES6+
 */

import { showToast } from './toast.js';
import { initOverviewCharts, destroyOverviewCharts } from './charts.js';

// Application State
export const state = {
  currentTab: 'overview',
  currentTimeWindow: '24h',
  selectedAlertIds: new Set(),
  activeDrawerAlertId: null,
  editingScenarioId: null,
  autoRefreshOn: true,
  secSinceRefresh: 5,
  currentRole: 'admin', // 'tier1' | 'tier2' | 'admin' — ASSUMPTION-03
  csrfToken: null
};

// Navigation and mobile drawer control
/**
 * Mở thanh điều hướng sidebar ở chế độ off-canvas trên thiết bị di động (< 1024px).
 * @returns {void}
 */
export function openMobileSidebar() {
  const sb = document.getElementById('app-sidebar');
  const bd = document.getElementById('sidebar-backdrop');
  if (sb) sb.classList.add('mobile-open');
  if (bd) bd.classList.remove('hidden');
}

/**
 * Đóng thanh điều hướng sidebar mobile và ẩn lớp phủ nền mờ backdrop.
 * @returns {void}
 */
export function closeMobileSidebar() {
  const sb = document.getElementById('app-sidebar');
  const bd = document.getElementById('sidebar-backdrop');
  if (sb) sb.classList.remove('mobile-open');
  if (bd) bd.classList.add('hidden');
}

/**
 * Đồng bộ trạng thái active của mục điều hướng trên thanh sidebar theo URL hiện tại.
 * @param {string} path - Đường dẫn URL cần đối soát (mặc định lấy từ window.location.pathname).
 * @returns {void}
 */
export function syncActiveNav(path = window.location.pathname) {
  const navMap = {
    '/': 'overview',
    '/overview': 'overview',
    '/alerts': 'alerts',
    '/devices': 'devices',
    '/scenarios': 'scenarios'
  };

  const currentTab = navMap[path] || 'overview';
  state.currentTab = currentTab;

  ['overview', 'alerts', 'devices', 'scenarios'].forEach(id => {
    const navBtn = document.getElementById(`nav-${id}`);
    const mobBtn = document.getElementById(`mob-nav-${id}`);
    if (navBtn) {
      if (id === currentTab) {
        navBtn.classList.add('active');
        navBtn.setAttribute('aria-current', 'page');
      } else {
        navBtn.classList.remove('active');
        navBtn.removeAttribute('aria-current');
      }
    }
    if (mobBtn) {
      if (id === currentTab) {
        mobBtn.classList.add('active');
        mobBtn.setAttribute('aria-current', 'page');
      } else {
        mobBtn.classList.remove('active');
        mobBtn.removeAttribute('aria-current');
      }
    }
  });
}

/**
 * Điều phối chuyển đổi tab giao diện, hỗ trợ cả hai chế độ Dynamic HTMX và Static Standalone.
 * @param {'overview'|'alerts'|'devices'|'scenarios'} tabId - Định danh trang tab cần chuyển.
 * @returns {void}
 */
export function switchTab(tabId) {
  state.currentTab = tabId;
  const tabs = ['overview', 'alerts', 'devices', 'scenarios'];
  let foundStaticTab = false;
  tabs.forEach(id => {
    const el = document.getElementById(`tab-${id}`);
    if (el) {
      foundStaticTab = true;
      if (id === tabId) {
        el.style.display = '';
        el.classList.remove('hidden');
      } else {
        el.style.display = 'none';
        el.classList.add('hidden');
      }
    }
  });
  syncActiveNav(tabId === 'overview' ? '/' : `/${tabId}`);
  closeMobileSidebar();
  if (tabId === 'overview') {
    setTimeout(() => {
      if (document.getElementById('severityDonutChart')) {
        initOverviewCharts();
      }
    }, 50);
  }
}

// Slide-over alert drawer lifecycle
export function openAlertDrawer(eventId) {
  state.activeDrawerAlertId = eventId;
  const backdrop = document.getElementById('alert-drawer-backdrop');
  const drawerContainer = document.getElementById('alert-drawer-container');

  if (backdrop) {
    backdrop.classList.add('active');
  }

  // If HTMX is used and running on HTTP/S, load the drawer content via API
  if (typeof htmx !== 'undefined' && drawerContainer && window.location.protocol.startsWith('http')) {
    htmx.ajax('GET', `/api/alerts/${eventId}/drawer`, {
      target: '#alert-drawer-container',
      swap: 'innerHTML'
    });
  }
}

export function closeAlertDrawer() {
  const backdrop = document.getElementById('alert-drawer-backdrop');
  if (backdrop) backdrop.classList.remove('active');
  state.activeDrawerAlertId = null;
}

export async function copyDrawerPayload() {
  const payloadEl = document.getElementById('dw-payload');
  if (!payloadEl) return;
  const text = payloadEl.textContent;

  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    }
    showToast('dark', 'Raw syslog payload copied to clipboard');
  } catch (err) {
    showToast('error', 'Unable to copy payload');
  }
}

// Bulk action state management
export function toggleSelectOneAlert(eventId, checked) {
  if (checked) {
    state.selectedAlertIds.add(eventId);
  } else {
    state.selectedAlertIds.delete(eventId);
  }
  syncBulkBar();
}

export function toggleSelectAllAlerts(checked) {
  const checkboxes = document.querySelectorAll('.alert-row-checkbox');
  checkboxes.forEach(cb => {
    cb.checked = checked;
    const evId = cb.getAttribute('data-event-id');
    if (evId) {
      if (checked) state.selectedAlertIds.add(evId);
      else state.selectedAlertIds.delete(evId);
    }
  });
  syncBulkBar();
}

export function clearBulkSelection() {
  state.selectedAlertIds.clear();
  const allBox = document.getElementById('al-select-all');
  if (allBox) {
    allBox.checked = false;
    allBox.indeterminate = false;
  }
  const checkboxes = document.querySelectorAll('.alert-row-checkbox');
  checkboxes.forEach(cb => { cb.checked = false; });
  syncBulkBar();
}

export function syncBulkBar() {
  const bar = document.getElementById('bulk-action-bar');
  const countText = document.getElementById('bulk-count-text');
  if (!bar) return;

  const count = state.selectedAlertIds.size;
  if (count > 0) {
    bar.classList.remove('hidden');
    if (countText) countText.textContent = `${count} selected`;
  } else {
    bar.classList.add('hidden');
  }
}

export async function executeBulkState(newState) {
  const count = state.selectedAlertIds.size;
  if (!count) return;

  const ids = Array.from(state.selectedAlertIds);
  try {
    const formData = new FormData();
    formData.append('state', newState);
    ids.forEach(id => formData.append('event_ids', id));

    const response = await fetch('/api/alerts/bulk-state', {
      method: 'POST',
      body: formData
    });

    if (response.ok) {
      // Refresh alert table via HTMX trigger or direct swap
      if (typeof htmx !== 'undefined') {
        htmx.trigger('#al-search', 'change');
      }
      clearBulkSelection();
      showToast('light', `Updated ${count} alerts to ${newState}`);
    }
  } catch (e) {
    showToast('error', 'Bulk update failed');
  }
}

// Advanced filters panel control
export function toggleAdvancedFilters() {
  const panel = document.getElementById('adv-filters-panel');
  const caret = document.getElementById('adv-filter-caret');
  const btn = document.getElementById('adv-filter-toggle-btn');
  if (!panel) return;

  const isHidden = panel.classList.toggle('hidden');
  if (caret) caret.style.transform = isHidden ? 'rotate(0deg)' : 'rotate(90deg)';
  if (btn) btn.setAttribute('aria-expanded', String(!isHidden));
}

export function resetAllAlertFilters() {
  const search = document.getElementById('al-search');
  const time = document.getElementById('al-time');
  const sev = document.getElementById('al-severity');
  const rule = document.getElementById('al-rule-id');
  const ip = document.getElementById('al-src-ip');
  const asset = document.getElementById('al-asset');
  const stateSel = document.getElementById('al-state-select');

  if (search) search.value = '';
  if (time) time.value = 'Last 24 hours';
  if (sev) sev.value = 'ALL';
  if (rule) rule.value = '';
  if (ip) ip.value = '';
  if (asset) asset.value = 'ALL';
  if (stateSel) stateSel.value = 'ALL';

  // Trigger HTMX filter refresh
  if (typeof htmx !== 'undefined' && search) {
    htmx.trigger(search, 'input');
  }
}

// Attack scenarios logic and form presets
export function handleScenarioTechniqueChange() {
  const tech = document.getElementById('sc-technique')?.value;
  const presets = {
    T1046: { tool: 'nmap 7.94', rule: '100200', alert: 'EVT-2610-089' },
    T1110: { tool: 'hydra 9.5', rule: '100210', alert: 'EVT-2610-092' },
    T1557: { tool: 'yersinia 0.8.2', rule: '100999', alert: 'EVT-2610-099' },
    T1498: { tool: 'hping3 3.0', rule: '100305', alert: 'EVT-2610-095' }
  };

  const preset = presets[tech];
  if (preset) {
    const toolEl = document.getElementById('sc-tool');
    const ruleEl = document.getElementById('sc-rule');
    const alertEl = document.getElementById('sc-linked-alert');

    if (toolEl) toolEl.value = preset.tool;
    if (ruleEl) ruleEl.value = preset.rule;
    if (alertEl) alertEl.value = preset.alert;

    updateComputedDeltaWell();
  }
}

export function handleScenarioRuleChange() {
  const rule = document.getElementById('sc-rule')?.value;
  const mapRuleToAlert = {
    '100200': 'EVT-2610-089',
    '100210': 'EVT-2610-092',
    '100999': 'EVT-2610-099',
    '100305': 'EVT-2610-095'
  };

  if (mapRuleToAlert[rule]) {
    const alertEl = document.getElementById('sc-linked-alert');
    if (alertEl) {
      alertEl.value = mapRuleToAlert[rule];
      updateComputedDeltaWell();
    }
  }
}

export function updateComputedDeltaWell() {
  const evId = document.getElementById('sc-linked-alert')?.value;
  if (!evId) return;

  // Query delta info via API
  fetch(`/api/scenarios/calculate-delta?linked_id=${evId}`)
    .then(r => r.json())
    .then(data => {
      const startEl = document.getElementById('sc-start-ts');
      const obsEl = document.getElementById('sc-obs-ts');
      const deltaEl = document.getElementById('sc-delta-display');
      const barEl = document.getElementById('sc-delta-bar');
      const badgeEl = document.getElementById('sc-target-badge');

      if (startEl) startEl.textContent = data.testStartTs;
      if (obsEl) obsEl.textContent = data.testObsTs;
      if (deltaEl) deltaEl.textContent = `${data.testDeltaSec.toFixed(1)} s`;

      const pct = Math.min(100, (data.testDeltaSec / 6) * 100);
      if (barEl) barEl.style.width = `${pct}%`;

      if (badgeEl) {
        if (data.testDeltaSec <= 5.0) {
          badgeEl.textContent = 'Within target';
          badgeEl.className = 'soc-badge badge-resolved';
        } else {
          badgeEl.textContent = 'Exceeded 5s';
          badgeEl.className = 'soc-badge badge-critical';
        }
      }
    })
    .catch(() => {});
}

export function editScenarioRow(id) {
  fetch(`/api/scenarios/${id}/edit`)
    .then(r => r.json())
    .then(row => {
      state.editingScenarioId = id;
      document.getElementById('sc-technique').value = row.code;
      document.getElementById('sc-tool').value = row.tool;
      document.getElementById('sc-rule').value = row.rule;
      document.getElementById('sc-linked-alert').value = row.linkedEventId;
      document.getElementById('sc-detected-check').checked = row.detected;
      document.getElementById('sc-notes').value = row.notes;
      document.getElementById('sc-edit-id-input').value = row.id;

      updateComputedDeltaWell();

      document.getElementById('sc-form-heading').textContent = `Edit test (${row.code})`;
      document.getElementById('sc-submit-btn').textContent = 'Update test';
      document.getElementById('sc-cancel-edit-btn').classList.remove('hidden');
      document.getElementById('sc-editing-badge').classList.remove('hidden');

      const body = document.getElementById('sc-form-collapsible-body');
      const chevron = document.getElementById('sc-accordion-chevron');
      const btn = document.getElementById('sc-accordion-toggle-btn');
      const badgeMob = document.getElementById('sc-editing-badge-mobile');
      if (body) body.classList.add('expanded');
      if (chevron) chevron.style.transform = 'rotate(180deg)';
      if (btn) btn.setAttribute('aria-expanded', 'true');
      if (badgeMob) badgeMob.classList.remove('hidden');

      const card = document.getElementById('sc-form-card');
      if (card) card.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      document.getElementById('sc-notes')?.focus();
      showToast('light', `Loaded ${row.code} into editor`);
    })
    .catch(() => showToast('error', 'Failed to load test data'));
}

export function cancelScenarioEdit(silent = false) {
  state.editingScenarioId = null;
  const idInput = document.getElementById('sc-edit-id-input');
  if (idInput) idInput.value = '';

  document.getElementById('sc-form-heading').textContent = 'New test';
  document.getElementById('sc-submit-btn').textContent = 'Record test';
  document.getElementById('sc-cancel-edit-btn').classList.add('hidden');
  document.getElementById('sc-editing-badge').classList.add('hidden');
  const badgeMob = document.getElementById('sc-editing-badge-mobile');
  if (badgeMob) badgeMob.classList.add('hidden');

  if (!silent) {
    showToast('light', 'Canceled test edit');
  }
}

// Sign-in route navigation and auth guard
/**
 * Chuyển hướng người dùng tới trang Đăng nhập độc lập (/login).
 */
export function openSignInModal() {
  window.location.href = '/login';
}

export function closeSignInModal() {
  const modal = document.getElementById('signin-modal');
  if (modal) modal.classList.remove('active');
  if (window.location.hash === '#signin') {
    history.replaceState(null, '', window.location.pathname + window.location.search);
  }
}

/**
 * Tiếp tục phiên làm việc với tư cách Khách xem (Read-only Guest).
 * Ghi nhận cờ soc_guest_mode để ngăn chặn modal tự động bật lại khi chuyển trang hoặc F5.
 */
export function continueAsGuest() {
  sessionStorage.setItem('soc_guest_mode', 'true');
  closeSignInModal();
  const analystNameEl = document.getElementById('topbar-analyst-name');
  if (analystNameEl && !state.isAuthenticated) {
    analystNameEl.textContent = 'Guest';
  }
  const avatarCircle = document.getElementById('analyst-avatar-circle');
  if (avatarCircle && !state.isAuthenticated) {
    avatarCircle.textContent = 'G';
  }
  showToast('light', 'Viewing as Guest (Read-only mode)');
}

export function hideSignInError() {
  const err = document.getElementById('signin-err-banner');
  if (err) err.classList.add('hidden');
}

export function checkCapsLock(e) {
  const hint = document.getElementById('signin-capslock-hint');
  if (!hint || typeof e.getModifierState !== 'function') return;
  if (e.getModifierState('CapsLock')) {
    hint.classList.remove('hidden');
  } else {
    hint.classList.add('hidden');
  }
}

/**
 * Quản lý trạng thái hiển thị của nút Show/Hide mật khẩu.
 * Nút chỉ hiển thị khi ô mật khẩu có nội dung (value.length > 0)
 * theo chuẩn UX Enterprise, tránh hiển thị dư thừa khi ô còn trống.
 */
export function handleSignInPwdInput() {
  hideSignInError();
  const inp = document.getElementById('signin-pwd');
  const btn = document.getElementById('signin-pwd-btn');
  if (!inp || !btn) return;
  if (inp.value.length > 0) {
    btn.classList.remove('hidden');
  } else {
    btn.classList.add('hidden');
    inp.type = 'password';
    btn.textContent = 'Show';
  }
}

export function toggleSignInPwd() {
  const inp = document.getElementById('signin-pwd');
  const btn = document.getElementById('signin-pwd-btn');
  if (!inp || !btn) return;
  if (inp.type === 'password') {
    inp.type = 'text';
    btn.textContent = 'Hide';
  } else {
    inp.type = 'password';
    btn.textContent = 'Show';
  }
}

/**
 * Điền nhanh thông tin tài khoản demo cho người chấm hoặc giảng viên (Quick Demo Fill).
 * Hỗ trợ 3 phân quyền chuẩn SOC: SecOps Admin, Tier-2 Analyst, Tier-1 Responder.
 *
 * @param {'admin'|'tier2'|'tier1'} role - Vai trò cần điền tài khoản mẫu.
 */
export function fillDemoCredentials(role) {
  const userInp = document.getElementById('signin-user');
  const pwdInp = document.getElementById('signin-pwd');
  hideSignInError();

  const demoAccounts = {
    admin: { user: 'admin', pwd: 'vnpt-soc-2026', label: 'SecOps Admin' },
    tier2: { user: 'tier2', pwd: 'vnpt-soc-2026', label: 'Tier-2 Analyst' },
    tier1: { user: 'tier1', pwd: 'vnpt-soc-2026', label: 'Tier-1 Responder' }
  };

  const cred = demoAccounts[role] || demoAccounts.admin;
  if (userInp) userInp.value = cred.user;
  if (pwdInp) {
    pwdInp.value = cred.pwd;
    handleSignInPwdInput();
  }
  showToast('light', `Loaded demo credentials: ${cred.label}`);
}

/**
 * Hiển thị thông báo hỗ trợ khi người dùng chọn quên thông tin đăng nhập trong phiên demo.
 * Cung cấp hướng dẫn trực quan ngay trên modal và làm nổi bật cụm Quick Demo Fill.
 */
export function showForgotCredentialsHint() {
  showToast('dark', 'Demo Sandbox: Use Quick Demo Fill pills below or password: vnpt-soc-2026');
  const demoBox = document.querySelector('.signin-demo-box');
  if (demoBox) {
    demoBox.style.transition = 'all 0.3s ease';
    demoBox.style.borderColor = 'var(--color-accent-lime)';
    demoBox.style.boxShadow = '0 0 0 2px var(--color-accent-lime)';
    demoBox.style.backgroundColor = 'rgba(198, 241, 53, 0.18)';
    setTimeout(() => {
      demoBox.style.borderColor = 'var(--color-border-card)';
      demoBox.style.boxShadow = 'none';
      demoBox.style.backgroundColor = 'rgba(231, 228, 220, 0.45)';
    }, 1800);
  }
}

export async function submitSignInForm(e) {
  e.preventDefault();
  const user = (document.getElementById('signin-user')?.value || '').trim();
  const pwd = document.getElementById('signin-pwd')?.value || '';
  const csrf = document.getElementById('signin-csrf')?.value || state.csrfToken || '';

  if (!user || pwd.length < 4) {
    const err = document.getElementById('signin-err-banner');
    if (err) {
      err.textContent = 'Please enter a valid username and password (min 4 characters).';
      err.classList.remove('hidden');
    }
    return;
  }

  try {
    const formData = new FormData();
    formData.append('username', user);
    formData.append('password', pwd);
    if (csrf) formData.append('csrf_token', csrf);

    const res = await fetch('/api/auth/login', {
      method: 'POST',
      body: formData
    });

    const data = await res.json();
    if (!res.ok || !data.success) {
      const err = document.getElementById('signin-err-banner');
      if (err) {
        err.textContent = data.error || 'Invalid username or password';
        err.classList.remove('hidden');
      }
      return;
    }

    const assignedRole = data.role || (user.toLowerCase().includes('tier2') ? 'tier2' : (user.toLowerCase().includes('tier1') ? 'tier1' : 'admin'));
    sessionStorage.removeItem('soc_guest_mode');
    sessionStorage.setItem('soc_auth_user', data.username || user);
    sessionStorage.setItem('soc_auth_role', assignedRole);
    state.isAuthenticated = true;
    state.currentUser = data.username || user;

    const analystNameEl = document.getElementById('topbar-analyst-name');
    if (analystNameEl) analystNameEl.textContent = data.username || user;
    const avatarCircle = document.getElementById('analyst-avatar-circle');
    if (avatarCircle) {
      avatarCircle.textContent = (data.username || user).charAt(0).toUpperCase();
    }
    switchRole(assignedRole);
    closeSignInModal();
    showToast('dark', `Signed in as ${data.username || user} (${ROLE_LABELS[assignedRole] || assignedRole})`);
  } catch (err) {
    // Dual-Mode Fallback: Xử lý đăng nhập giả lập khi chạy xem trước tĩnh (file:// hoặc không chạy FastAPI cổng 8000)
    if (window.location.protocol === 'file:' || (window.location.port !== '8000' && window.location.port !== '')) {
      const assignedRole = user.toLowerCase().includes('tier2') ? 'tier2' : (user.toLowerCase().includes('tier1') ? 'tier1' : 'admin');
      sessionStorage.removeItem('soc_guest_mode');
      sessionStorage.setItem('soc_auth_user', user);
      sessionStorage.setItem('soc_auth_role', assignedRole);
      state.isAuthenticated = true;
      state.currentUser = user;

      const analystNameEl = document.getElementById('topbar-analyst-name');
      if (analystNameEl) analystNameEl.textContent = user;
      const avatarCircle = document.getElementById('analyst-avatar-circle');
      if (avatarCircle) {
        avatarCircle.textContent = user.charAt(0).toUpperCase();
      }
      switchRole(assignedRole);
      closeSignInModal();
      showToast('dark', `Signed in as ${user} (${ROLE_LABELS[assignedRole] || assignedRole})`);
      return;
    }
    const errEl = document.getElementById('signin-err-banner');
    if (errEl) {
      errEl.textContent = 'Authentication network error';
      errEl.classList.remove('hidden');
    }
  }
}

// Analyst menu and role switcher

const ROLE_HIERARCHY = { tier1: 1, tier2: 2, admin: 3 };
const ROLE_LABELS = { tier1: 'Tier-1 Responder', tier2: 'Tier-2 Analyst', admin: 'SecOps Admin' };

export function toggleAnalystMenu() {
  const dropdown = document.getElementById('analyst-dropdown');
  const btn = document.getElementById('analyst-avatar-btn');
  if (!dropdown) return;
  const isOpen = dropdown.style.display === 'block';
  dropdown.style.display = isOpen ? 'none' : 'block';
  btn?.setAttribute('aria-expanded', String(!isOpen));
}

export function closeAnalystMenu() {
  const dropdown = document.getElementById('analyst-dropdown');
  const btn = document.getElementById('analyst-avatar-btn');
  if (dropdown) dropdown.style.display = 'none';
  btn?.setAttribute('aria-expanded', 'false');
}

export function switchRole(role) {
  if (!ROLE_HIERARCHY[role]) return;
  state.currentRole = role;

  // Update checkmarks
  ['admin', 'tier2', 'tier1'].forEach(r => {
    const check = document.getElementById(`role-check-${r}`);
    const btn = document.querySelector(`[data-role="${r}"]`);
    if (check) check.classList.toggle('hidden', r !== role);
    if (btn) btn.classList.toggle('role-btn-active', r === role);
  });

  // Apply permissions to DOM
  applyRolePermissions(role);
  closeAnalystMenu();
  showToast('light', `Active Role: ${ROLE_LABELS[role]}`);
}

export function applyRolePermissions(role) {
  const level = ROLE_HIERARCHY[role] || 3;

  // Elements marked with data-min-role get hidden if current role < required
  document.querySelectorAll('[data-min-role]').forEach(el => {
    const minRole = el.getAttribute('data-min-role');
    const required = ROLE_HIERARCHY[minRole] || 1;
    el.classList.toggle('role-hidden', level < required);
  });
}

export function handleSignOut() {
  fetch('/api/auth/logout', { method: 'POST' })
    .catch(() => {})
    .finally(() => {
      closeAnalystMenu();
      sessionStorage.removeItem('soc_auth_user');
      sessionStorage.removeItem('soc_auth_role');
      sessionStorage.removeItem('soc_guest_mode');
      state.isAuthenticated = false;
      state.currentUser = null;

      const nameEl = document.getElementById('topbar-analyst-name');
      if (nameEl) nameEl.textContent = 'Guest';
      const avatarEl = document.getElementById('analyst-avatar-circle');
      if (avatarEl) avatarEl.textContent = 'G';

      showToast('light', 'Signed out successfully');
      openSignInModal();
    });
}

// Close dropdown when clicking outside
document.addEventListener('click', (e) => {
  const wrapper = document.getElementById('analyst-menu-wrapper');
  if (wrapper && !wrapper.contains(e.target)) {
    closeAnalystMenu();
  }
});

// Auto-refresh and heartbeat timer
export function toggleAutoRefresh() {
  state.autoRefreshOn = !state.autoRefreshOn;
  const btn = document.getElementById('btn-autorefresh');
  const dot = document.getElementById('live-status-dot');
  const text = document.getElementById('live-status-text');
  const label = document.getElementById('autorefresh-label');

  if (state.autoRefreshOn) {
    if (btn) {
      btn.setAttribute('aria-pressed', 'true');
      btn.className = 'soc-btn soc-btn-outline soc-btn-sm';
    }
    if (label) {
      label.textContent = 'Auto: ON';
    } else if (btn) {
      btn.textContent = 'Auto: ON';
    }
    if (dot) dot.className = 'status-dot dot-live pulse-dot';
    if (text) text.innerHTML = '<span>Live</span> · <span id="live-sec-counter" class="font-mono">1s</span> ago<span class="live-desktop-tz"> · GMT+7</span>';
    showToast('dark', 'Live auto-refresh enabled');
  } else {
    if (btn) {
      btn.setAttribute('aria-pressed', 'false');
      btn.className = 'soc-btn soc-btn-secondary soc-btn-sm';
    }
    if (label) {
      label.textContent = 'Auto: OFF';
    } else if (btn) {
      btn.textContent = 'Auto: OFF';
    }
    if (dot) dot.className = 'status-dot dot-paused';
    if (text) text.innerHTML = '<span>Paused</span><span class="live-desktop-tz"> · GMT+7</span>';
    showToast('light', 'Live auto-refresh paused');
  }
}

/**
 * Bật/tắt thanh bộ lọc thu gọn trên mobile ở trang Alerts
 */
export function toggleMobileFilterBar() {
  const panel = document.getElementById('alerts-collapsible-filters');
  const btn = document.getElementById('al-mobile-filter-btn');
  if (!panel) return;
  const isHidden = !panel.classList.contains('show-mobile');
  if (isHidden) {
    panel.classList.add('show-mobile');
    if (btn) btn.classList.add('active');
    if (btn) btn.setAttribute('aria-expanded', 'true');
  } else {
    panel.classList.remove('show-mobile');
    if (btn) btn.classList.remove('active');
    if (btn) btn.setAttribute('aria-expanded', 'false');
  }
}

/**
 * Bật/tắt accordion form New Test trên mobile ở trang Scenarios
 */
export function toggleScenarioFormAccordion() {
  const body = document.getElementById('sc-form-collapsible-body');
  const chevron = document.getElementById('sc-accordion-chevron');
  const btn = document.getElementById('sc-accordion-toggle-btn');
  if (!body) return;
  const isExpanded = body.classList.contains('expanded');
  if (isExpanded) {
    body.classList.remove('expanded');
    if (chevron) chevron.style.transform = 'rotate(0deg)';
    if (btn) btn.setAttribute('aria-expanded', 'false');
  } else {
    body.classList.add('expanded');
    if (chevron) chevron.style.transform = 'rotate(180deg)';
    if (btn) btn.setAttribute('aria-expanded', 'true');
  }
}


// Theme Controller (Light / Dark Mode for 24/7 SOC Video Wall)
export function getCurrentTheme() {
  return document.documentElement.getAttribute('data-theme') || 'light';
}

export function updateThemeToggleIcon(theme) {
  const icon = document.getElementById('theme-toggle-icon');
  const btn = document.getElementById('btn-theme-toggle');
  if (!icon) return;

  if (theme === 'dark') {
    icon.className = 'fa-solid fa-sun';
    if (btn) {
      btn.setAttribute('aria-label', 'Switch to Light Mode');
      btn.title = 'Switch to Light Mode';
    }
  } else {
    icon.className = 'fa-solid fa-moon';
    if (btn) {
      btn.setAttribute('aria-label', 'Switch to Dark Mode');
      btn.title = 'Switch to Dark Mode';
    }
  }
  if (typeof window.refreshLocalIcons === 'function') {
    window.refreshLocalIcons();
  }
}

export function setTheme(theme) {
  const targetTheme = (theme === 'dark') ? 'dark' : 'light';
  document.documentElement.setAttribute('data-theme', targetTheme);
  if (document.documentElement.style) {
    document.documentElement.style.colorScheme = targetTheme;
  }
  try {
    localStorage.setItem('soc-theme', targetTheme);
  } catch (e) {
    // Sandbox or private browsing storage error ignored
  }

  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) {
    meta.setAttribute('content', targetTheme === 'dark' ? '#0E0F0C' : '#F3F1EC');
  }

  updateThemeToggleIcon(targetTheme);

  // Phat su kien dong bo toi bieu do va cac thanh phan khac
  window.dispatchEvent(new CustomEvent('theme-changed', {
    detail: { theme: targetTheme }
  }));
}

export function toggleTheme() {
  const current = getCurrentTheme();
  const nextTheme = current === 'dark' ? 'light' : 'dark';
  setTheme(nextTheme);
}

window.toggleTheme = toggleTheme;
window.setTheme = setTheme;
window.getCurrentTheme = getCurrentTheme;
window.updateThemeToggleIcon = updateThemeToggleIcon;

// Seconds counter ticker & Quản lý trạng thái Visibility (Tối ưu RAM/Pin iOS Jetsam)
document.addEventListener('visibilitychange', () => {
  if (document.hidden) {
    state._pausedByVisibility = state.autoRefreshOn;
    state.autoRefreshOn = false;
  } else {
    if (state._pausedByVisibility) {
      state.autoRefreshOn = true;
      delete state._pausedByVisibility;
      state.secSinceRefresh = 5;
    }
  }
});

// Seconds counter ticker
setInterval(() => {
  if (!state.autoRefreshOn) return;
  state.secSinceRefresh = (state.secSinceRefresh % 5) + 1;
  const counterEl = document.getElementById('live-sec-counter');
  if (counterEl) counterEl.textContent = `${state.secSinceRefresh}s`;
}, 1000);

// Kích hoạt ngay lập tức CSS :active trên màn hình cảm ứng iOS WebKit
document.addEventListener('touchstart', () => {}, { passive: true });

// Phản hồi giao diện tức thì (Optimistic 0ms Active Indicator):
// Chuyển highlight tab ngay khi người dùng chạm, không phải chờ HTMX fetch xong mới đổi
document.addEventListener('click', (e) => {
  const tabBtn = e.target.closest('#mobile-bottom-bar .mob-tab-btn, #app-sidebar .nav-btn');
  if (tabBtn) {
    const targetHref = tabBtn.getAttribute('href') || tabBtn.getAttribute('hx-push-url');
    if (targetHref) {
      syncActiveNav(targetHref);
    }
  }
});

// Global event listeners and HTMX lifecycle hooks
// Centralized SOC Keyboard Controller (Guarded Navigation & Top-layer Escape Priority)
let selectedAlertRowIndex = -1;

export function handleCentralKeyDown(e) {
  // Bo qua neu co phim bo tro (Ctrl, Alt, Meta) hoac bo go IME dang kich hoat de tranh xung dot phim tat he dieu hanh
  if (e.ctrlKey || e.altKey || e.metaKey || e.isComposing) {
    return;
  }

  const target = e.target;
  const isEditing = target && (
    target.tagName === 'INPUT' ||
    target.tagName === 'TEXTAREA' ||
    target.tagName === 'SELECT' ||
    target.isContentEditable
  );

  // Phim Escape: Dong theo thu tu uu tien (Modal -> Dropup -> Drawer -> Dropdown -> Sidebar -> Blur Input -> Row Focus)
  if (e.key === 'Escape') {
    // 1. Sign-in modal (kiem tra class 'active')
    const signInModal = document.getElementById('signin-modal');
    if (signInModal && signInModal.classList.contains('active')) {
      closeSignInModal();
      return;
    }

    // 2. Disposition dropup
    const dispMenu = document.getElementById('dw-disposition-menu');
    if (dispMenu && !dispMenu.classList.contains('hidden') && dispMenu.style.display !== 'none') {
      closeDispositionMenu();
      return;
    }

    // 3. Alert detail drawer (kiem tra backdrop co class 'active')
    const drawerBackdrop = document.getElementById('alert-drawer-backdrop');
    if (drawerBackdrop && drawerBackdrop.classList.contains('active')) {
      closeAlertDrawer();
      return;
    }

    // 4. Analyst dropdown menu & Row action menus
    const analystDropdown = document.getElementById('analyst-dropdown');
    if (analystDropdown && analystDropdown.style.display === 'block') {
      closeAnalystMenu();
      return;
    }
    const hasOpenRowMenu = document.querySelector('.row-action-cell.menu-open') ||
                           document.querySelector('.row-action-menu:not(.hidden)');
    if (hasOpenRowMenu) {
      closeAllRowMenus();
      return;
    }

    // 5. Mobile sidebar
    const sidebar = document.getElementById('app-sidebar');
    if (sidebar && sidebar.classList.contains('show')) {
      closeMobileSidebar();
      return;
    }

    // 6. Blur active input / select / textarea khi khong co overlay
    if (isEditing) {
      target.blur();
      return;
    }

    // 7. Huy focus ban phim tren bang canh bao
    if (selectedAlertRowIndex >= 0) {
      const rows = Array.from(document.querySelectorAll('#al-table-body tr.clickable'));
      rows.forEach(r => r.classList.remove('kb-active-row'));
      selectedAlertRowIndex = -1;
      return;
    }

    return;
  }

  // Khong kich hoat cac phim tat con lai khi dang trong input / textarea / select
  if (isEditing) return;

  // Phim tat '/': Nhay nhanh con tro vao o tim kiem Alert Search
  if (e.key === '/') {
    const searchInput = document.getElementById('al-search') ||
                        document.querySelector('.soc-search-input');
    if (searchInput) {
      e.preventDefault();
      searchInput.focus();
      searchInput.select();
    }
    return;
  }

  // Phim tat 'j' va 'k': Di chuyen qua lai giua cac hang canh bao trong bang
  const rows = Array.from(document.querySelectorAll('#al-table-body tr.clickable'));
  if (rows.length > 0) {
    if (e.key === 'j') {
      e.preventDefault();
      selectedAlertRowIndex = Math.min(selectedAlertRowIndex + 1, rows.length - 1);
      highlightActiveAlertRow(rows, selectedAlertRowIndex);
      return;
    }
    if (e.key === 'k') {
      e.preventDefault();
      selectedAlertRowIndex = Math.max(selectedAlertRowIndex - 1, 0);
      highlightActiveAlertRow(rows, selectedAlertRowIndex);
      return;
    }
    // Phim tat 'Enter': Mo drawer cho hang dang duoc chon
    if (e.key === 'Enter' && selectedAlertRowIndex >= 0 && selectedAlertRowIndex < rows.length) {
      e.preventDefault();
      rows[selectedAlertRowIndex].click();
      return;
    }
  }
}

function highlightActiveAlertRow(rows, index) {
  rows.forEach((row, i) => {
    if (i === index) {
      row.classList.add('kb-active-row');
      row.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    } else {
      row.classList.remove('kb-active-row');
    }
  });
}

document.addEventListener('keydown', handleCentralKeyDown);


// Vòng đời HTMX & Khử rò rỉ bộ nhớ (Rule 3.1):
// HTMX hoán đổi phần tử #main-content mà không tải lại toàn trang.
// BẮT BUỘC phải hủy (destroy) biểu đồ Chart.js cũ trước khi khởi tạo lại,
// nếu không Chart.js sẽ bắn lỗi "Canvas is already in use by chart with id X"
// và gây rò rỉ bộ nhớ (memory leak) trên trình duyệt của analyst trực ca dài.
document.addEventListener('htmx:afterSwap', (evt) => {
  selectedAlertRowIndex = -1;
  syncActiveNav(window.location.pathname);
  updateThemeToggleIcon(getCurrentTheme());
  closeMobileSidebar();
  applyRolePermissions(state.currentRole);

  // Khử nhịp khựng (UI Jank Elimination):
  // Trì hoãn việc vẽ đồ họa Chart.js sang frame kế tiếp qua requestAnimationFrame,
  // cho phép trình duyệt ưu tiên paint toàn bộ DOM HTML ngay lập tức (16ms / 60fps),
  // tránh tình trạng treo main thread khi vừa đổi tab.
  if (document.getElementById('severityDonutChart')) {
    requestAnimationFrame(() => {
      initOverviewCharts();
    });
  }
});

// HTMX error handler
document.addEventListener('htmx:responseError', () => {
  showToast('error', 'Network error: could not fetch SOC data');
});

// Measurement verification helper
window.measureSOCAcceptance = function () {
  const sb = document.getElementById('app-sidebar')?.getBoundingClientRect();
  const kpi = document.getElementById('ov-kpi-strip')?.getBoundingClientRect();
  const rows = document.querySelectorAll('#ov-queue-container .queue-row');
  const r1 = rows[0]?.getBoundingClientRect();
  const r2 = rows[1]?.getBoundingClientRect();
  return {
    viewport: `${window.innerWidth}x${window.innerHeight}`,
    sidebarWidth: sb ? Math.round(sb.width * 10) / 10 : 0,
    kpiStrip: kpi ? { width: Math.round(kpi.width * 10) / 10, height: Math.round(kpi.height * 10) / 10 } : null,
    firstAlertRow: r1 ? { width: Math.round(r1.width * 10) / 10, height: Math.round(r1.height * 10) / 10, bottomY: Math.round(r1.bottom * 10) / 10 } : null,
    secondAlertRowBottomY: r2 ? Math.round(r2.bottom * 10) / 10 : null,
    hasHorizontalScroll: document.documentElement.scrollWidth > document.documentElement.clientWidth
  };
};

// Row Action Menu (Rule Section 5: Thao tác mỗi hàng gộp thành nút "⋯")
export function toggleRowMenu(menuId, event) {
  if (event) event.stopPropagation();
  const menu = document.getElementById(menuId);
  if (!menu) return;

  const wasHidden = menu.classList.contains('hidden');
  closeAllRowMenus();

  if (wasHidden) {
    menu.classList.remove('hidden');

    const tr = menu.closest('tr');
    const td = menu.closest('td');
    const wrap = menu.closest('.row-action-menu-wrap');

    // Elevate stacking context of current row & cell so it renders above other rows (z-index 50)
    if (tr) tr.classList.add('menu-open');
    if (td) td.classList.add('menu-open');
    if (wrap) wrap.classList.add('menu-open');

    // Collision detection: check if menu overflows bottom of table wrap or window
    const tableWrap = menu.closest('.soc-table-wrap');
    const btn = wrap ? wrap.querySelector('button') : menu.previousElementSibling;
    const btnRect = btn ? btn.getBoundingClientRect() : menu.parentElement.getBoundingClientRect();
    const menuHeight = menu.offsetHeight || 76;

    let shouldDropup = false;
    if (tableWrap) {
      const wrapRect = tableWrap.getBoundingClientRect();
      const spaceBelowWrap = wrapRect.bottom - btnRect.bottom;
      if (spaceBelowWrap < (menuHeight + 8)) {
        shouldDropup = true;
      }
    }
    const spaceBelowViewport = window.innerHeight - btnRect.bottom;
    if (spaceBelowViewport < (menuHeight + 8)) {
      shouldDropup = true;
    }

    if (tr && tr.parentElement) {
      const allRows = Array.from(tr.parentElement.children).filter(el => el.tagName === 'TR');
      const idx = allRows.indexOf(tr);
      // If it's among the last 2 rows and not the only row
      if (idx > 0 && idx >= allRows.length - 2) {
        shouldDropup = true;
      }
    }

    if (shouldDropup) {
      menu.classList.add('dropup');
    } else {
      menu.classList.remove('dropup');
    }
  }
}

export function closeAllRowMenus() {
  document.querySelectorAll('.row-menu-dropdown').forEach(m => {
    m.classList.add('hidden');
    m.classList.remove('dropup');
  });
  document.querySelectorAll('tr.menu-open, td.menu-open, .row-action-menu-wrap.menu-open').forEach(el => {
    el.classList.remove('menu-open');
  });
}

document.addEventListener('click', (e) => {
  if (!e.target.closest('.row-action-menu-wrap')) {
    closeAllRowMenus();
  }
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    closeAllRowMenus();
  }
});

// Export to window for inline HTML event handlers
window.toggleRowMenu = toggleRowMenu;
window.closeAllRowMenus = closeAllRowMenus;
window.openMobileSidebar = openMobileSidebar;
window.closeMobileSidebar = closeMobileSidebar;
window.openAlertDrawer = openAlertDrawer;
window.closeAlertDrawer = closeAlertDrawer;
window.copyDrawerPayload = copyDrawerPayload;
window.toggleSelectOneAlert = toggleSelectOneAlert;
window.toggleSelectAllAlerts = toggleSelectAllAlerts;
window.clearBulkSelection = clearBulkSelection;
window.executeBulkState = executeBulkState;
window.toggleAdvancedFilters = toggleAdvancedFilters;
window.resetAllAlertFilters = resetAllAlertFilters;
window.handleScenarioTechniqueChange = handleScenarioTechniqueChange;
window.handleScenarioRuleChange = handleScenarioRuleChange;
window.updateComputedDeltaWell = updateComputedDeltaWell;
window.editScenarioRow = editScenarioRow;
window.cancelScenarioEdit = cancelScenarioEdit;
window.openSignInModal = openSignInModal;
window.closeSignInModal = closeSignInModal;
window.continueAsGuest = continueAsGuest;
window.hideSignInError = hideSignInError;
window.checkCapsLock = checkCapsLock;
window.handleSignInPwdInput = handleSignInPwdInput;
window.toggleSignInPwd = toggleSignInPwd;
window.fillDemoCredentials = fillDemoCredentials;
window.showForgotCredentialsHint = showForgotCredentialsHint;
window.submitSignInForm = submitSignInForm;
window.toggleAutoRefresh = toggleAutoRefresh;
window.toggleMobileFilterBar = toggleMobileFilterBar;
window.toggleScenarioFormAccordion = toggleScenarioFormAccordion;
window.toggleAnalystMenu = toggleAnalystMenu;
window.closeAnalystMenu = closeAnalystMenu;
window.switchRole = switchRole;
window.switchTab = switchTab;
window.applyRolePermissions = applyRolePermissions;
window.handleSignOut = handleSignOut;

/**
 * Xử lý trạng thái khi người dùng chưa đăng nhập.
 * Nếu chưa từng chọn chế độ Guest, tự động chuyển hướng sang trang Sign In (/login).
 *
 * @param {boolean} isHashSignIn - Cờ nhận diện URL đã có hash #signin.
 */
function handleUnauthenticatedState(isHashSignIn) {
  state.isAuthenticated = false;
  state.currentUser = null;
  const isGuestMode = sessionStorage.getItem('soc_guest_mode') === 'true';

  const nameEl = document.getElementById('topbar-analyst-name');
  if (nameEl) nameEl.textContent = 'Guest';
  const avatarEl = document.getElementById('analyst-avatar-circle');
  if (avatarEl) avatarEl.textContent = 'G';
  applyRolePermissions(state.currentRole);

  if (!isGuestMode) {
    window.location.href = '/login';
  }
}

// Initialize when DOM is ready
window.addEventListener('DOMContentLoaded', () => {
  // Ghi nhận cờ guest nếu được chuyển hướng từ /login
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('guest') === '1') {
    sessionStorage.setItem('soc_guest_mode', 'true');
  }

  syncActiveNav(window.location.pathname);
  updateThemeToggleIcon(getCurrentTheme());
  if (document.getElementById('severityDonutChart')) {
    initOverviewCharts();
  }
  updateComputedDeltaWell();

  // Tự động đóng mobile sidebar khi click bất kỳ mục điều hướng nào trên di động
  document.querySelectorAll('#app-sidebar .nav-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      closeMobileSidebar();
    });
  });

  // Smart Auth Guard: Điều phối phiên trực ca và duy trì xác thực
  const isHashSignIn = window.location.hash === '#signin';

  if (isHashSignIn) {
    window.location.href = '/login';
    return;
  }

  fetch('/api/auth/me')
    .then(r => r.json())
    .then(data => {
      if (data.authenticated) {
        state.isAuthenticated = true;
        state.currentUser = data.username;
        sessionStorage.removeItem('soc_guest_mode');
        sessionStorage.setItem('soc_auth_user', data.username);
        if (data.role) sessionStorage.setItem('soc_auth_role', data.role);

        const nameEl = document.getElementById('topbar-analyst-name');
        if (nameEl) nameEl.textContent = data.username;
        const avatarEl = document.getElementById('analyst-avatar-circle');
        if (avatarEl) avatarEl.textContent = data.username.charAt(0).toUpperCase();

        if (data.role && ROLE_HIERARCHY[data.role]) {
          switchRole(data.role);
          return;
        }
        applyRolePermissions(state.currentRole);
      } else {
        handleUnauthenticatedState(isHashSignIn);
      }
    })
    .catch(() => {
      // Static Offline / Dual-Mode Preview Fallback
      const savedUser = sessionStorage.getItem('soc_auth_user');
      const savedRole = sessionStorage.getItem('soc_auth_role');
      if (savedUser) {
        state.isAuthenticated = true;
        state.currentUser = savedUser;
        const nameEl = document.getElementById('topbar-analyst-name');
        if (nameEl) nameEl.textContent = savedUser;
        const avatarEl = document.getElementById('analyst-avatar-circle');
        if (avatarEl) avatarEl.textContent = savedUser.charAt(0).toUpperCase();
        if (savedRole && ROLE_HIERARCHY[savedRole]) {
          switchRole(savedRole);
          return;
        }
        applyRolePermissions(state.currentRole);
      } else {
        handleUnauthenticatedState(isHashSignIn);
      }
    });
});

// Đăng ký Service Worker cho PWA (Tối ưu Cache Storage & Offline Fallback)
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js', { scope: '/' })
      .catch((err) => console.debug('Service Worker registration skipped:', err));
  });
}

/**
 * Quản lý tương tác Dropup Select phân loại kết quả đóng án (Alert Disposition) trong Drawer.
 */
export function toggleDispositionMenu(e) {
  if (e) {
    e.preventDefault();
    e.stopPropagation();
  }
  const trigger = document.getElementById('dw-disposition-trigger');
  const menu = document.getElementById('dw-disposition-menu');
  if (!trigger || !menu) return;
  const isExpanded = trigger.getAttribute('aria-expanded') === 'true';
  trigger.setAttribute('aria-expanded', String(!isExpanded));
  menu.classList.toggle('hidden', isExpanded);
}

export function selectDispositionOption(e, value, label) {
  if (e) {
    e.preventDefault();
    e.stopPropagation();
  }
  // Cập nhật giá trị thẻ hidden input phục vụ HTMX hx-include
  const hiddenInput = document.getElementById('dw-disposition-select');
  if (hiddenInput) {
    hiddenInput.value = value;
    hiddenInput.dispatchEvent(new Event('change', { bubbles: true }));
  }

  // Cập nhật nhãn hiển thị trên trigger button
  const labelEl = document.querySelector('#dw-disposition-trigger .dw-disposition-label');
  if (labelEl) {
    labelEl.textContent = label;
  }

  // Đánh dấu mục đang chọn
  const menu = document.getElementById('dw-disposition-menu');
  if (menu) {
    menu.querySelectorAll('.soc-custom-select-item').forEach((item) => {
      const isSelected = item.getAttribute('data-value') === value;
      item.classList.toggle('selected', isSelected);
      item.setAttribute('aria-selected', String(isSelected));
    });
    menu.classList.add('hidden');
  }

  const trig = document.getElementById('dw-disposition-trigger');
  if (trig) trig.setAttribute('aria-expanded', 'false');
}

export function closeDispositionMenu() {
  const menu = document.getElementById('dw-disposition-menu');
  if (menu && !menu.classList.contains('hidden')) {
    menu.classList.add('hidden');
    const trig = document.getElementById('dw-disposition-trigger');
    if (trig) trig.setAttribute('aria-expanded', 'false');
  }
}

window.toggleDispositionMenu = toggleDispositionMenu;
window.selectDispositionOption = selectDispositionOption;
window.closeDispositionMenu = closeDispositionMenu;

// Đóng Dropup khi nhấp chuột ra ngoài vùng dropup (Capture phase)
document.addEventListener('click', (e) => {
  if (!e.target.closest('#dw-disposition-wrap')) {
    closeDispositionMenu();
  }
}, true);

// Dropup Escape handled by centralized KeyboardController
