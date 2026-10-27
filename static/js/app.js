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

// =========================================================================
// 1. NAVIGATION & MOBILE DRAWER
// =========================================================================
export function openMobileSidebar() {
  const sb = document.getElementById('app-sidebar');
  const bd = document.getElementById('sidebar-backdrop');
  if (sb) sb.classList.add('mobile-open');
  if (bd) bd.classList.remove('hidden');
}

export function closeMobileSidebar() {
  const sb = document.getElementById('app-sidebar');
  const bd = document.getElementById('sidebar-backdrop');
  if (sb) sb.classList.remove('mobile-open');
  if (bd) bd.classList.add('hidden');
}

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

// =========================================================================
// 2. ALERT DRAWER (SLIDE-OVER)
// =========================================================================
export function openAlertDrawer(eventId) {
  state.activeDrawerAlertId = eventId;
  const backdrop = document.getElementById('alert-drawer-backdrop');
  const drawerContainer = document.getElementById('alert-drawer-container');

  if (backdrop) {
    backdrop.classList.add('active');
  }

  // If HTMX is used, load the drawer content via API
  if (typeof htmx !== 'undefined' && drawerContainer) {
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

// =========================================================================
// 3. BULK ACTIONS & SELECTION
// =========================================================================
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

// =========================================================================
// 4. ADVANCED FILTERS PANEL
// =========================================================================
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

// =========================================================================
// 5. ATTACK SCENARIOS LOGIC
// =========================================================================
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

  if (!silent) {
    showToast('light', 'Canceled test edit');
  }
}

// =========================================================================
// 6. SIGN-IN MODAL (ASSUMPTION-02)
// =========================================================================
export async function openSignInModal() {
  hideSignInError();
  const modal = document.getElementById('signin-modal');
  if (modal) modal.classList.add('active');
  const userInp = document.getElementById('signin-user');
  if (userInp) userInp.focus();

  // Fetch fresh CSRF token (ASSUMPTION-02)
  try {
    const res = await fetch('/api/auth/csrf-token');
    if (res.ok) {
      const data = await res.json();
      state.csrfToken = data.csrf_token;
      const csrfInput = document.getElementById('signin-csrf');
      if (csrfInput) csrfInput.value = data.csrf_token;
    }
  } catch (err) {
    // Best effort
  }
}

export function closeSignInModal() {
  const modal = document.getElementById('signin-modal');
  if (modal) modal.classList.remove('active');
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

    const analystNameEl = document.getElementById('topbar-analyst-name');
    if (analystNameEl) analystNameEl.textContent = data.username || user;
    closeSignInModal();
    showToast('dark', `Signed in as ${data.username || user}`);
  } catch (err) {
    // Client-side fallback for static preview / file: context
    if (window.location.protocol === 'file:' || (window.location.port !== '8000' && window.location.port !== '')) {
      const analystNameEl = document.getElementById('topbar-analyst-name');
      if (analystNameEl) analystNameEl.textContent = user;
      closeSignInModal();
      showToast('dark', `Signed in as ${user}`);
      return;
    }
    const errEl = document.getElementById('signin-err-banner');
    if (errEl) {
      errEl.textContent = 'Authentication network error';
      errEl.classList.remove('hidden');
    }
  }
}

// =========================================================================
// 6B. ANALYST MENU & ROLE SWITCHER (ASSUMPTION-03)
// =========================================================================

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
      const nameEl = document.getElementById('topbar-analyst-name');
      if (nameEl) nameEl.textContent = 'Guest';
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

// =========================================================================
// 7. AUTO-REFRESH & HEARTBEAT TIMER
// =========================================================================
export function toggleAutoRefresh() {
  state.autoRefreshOn = !state.autoRefreshOn;
  const btn = document.getElementById('btn-autorefresh');
  const dot = document.getElementById('live-status-dot');
  const text = document.getElementById('live-status-text');

  if (state.autoRefreshOn) {
    if (btn) {
      btn.textContent = 'Auto-refresh: on';
      btn.setAttribute('aria-pressed', 'true');
      btn.className = 'soc-btn soc-btn-outline soc-btn-sm';
    }
    if (dot) dot.className = 'status-dot dot-live';
    if (text) text.innerHTML = 'Live · updated <span id="live-sec-counter" class="font-mono">1s</span> ago · GMT+7';
    showToast('dark', 'Live auto-refresh enabled');
  } else {
    if (btn) {
      btn.textContent = 'Auto-refresh: off';
      btn.setAttribute('aria-pressed', 'false');
      btn.className = 'soc-btn soc-btn-secondary soc-btn-sm';
    }
    if (dot) dot.className = 'status-dot dot-paused';
    if (text) text.textContent = 'Paused · GMT+7';
    showToast('light', 'Live auto-refresh paused');
  }
}

// Seconds counter ticker
setInterval(() => {
  if (!state.autoRefreshOn) return;
  state.secSinceRefresh = (state.secSinceRefresh % 5) + 1;
  const counterEl = document.getElementById('live-sec-counter');
  if (counterEl) counterEl.textContent = `${state.secSinceRefresh}s`;
}, 1000);

// =========================================================================
// 8. GLOBAL EVENT LISTENERS & HTMX HOOKS
// =========================================================================
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    closeSignInModal();
    closeAlertDrawer();
    closeMobileSidebar();
  }
});

// HTMX afterSwap Hook: auto-sync sidebar active nav & re-init Chart.js if on overview
document.addEventListener('htmx:afterSwap', (evt) => {
  syncActiveNav(window.location.pathname);
  closeMobileSidebar();
  applyRolePermissions(state.currentRole);

  // If new content contains overview charts, initialize them
  if (document.getElementById('severityDonutChart')) {
    initOverviewCharts();
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
window.hideSignInError = hideSignInError;
window.checkCapsLock = checkCapsLock;
window.toggleSignInPwd = toggleSignInPwd;
window.submitSignInForm = submitSignInForm;
window.toggleAutoRefresh = toggleAutoRefresh;
window.toggleAnalystMenu = toggleAnalystMenu;
window.closeAnalystMenu = closeAnalystMenu;
window.switchRole = switchRole;
window.switchTab = switchTab;
window.applyRolePermissions = applyRolePermissions;
window.handleSignOut = handleSignOut;

// Initialize when DOM is ready
window.addEventListener('DOMContentLoaded', () => {
  syncActiveNav(window.location.pathname);
  if (document.getElementById('severityDonutChart')) {
    initOverviewCharts();
  }
  updateComputedDeltaWell();

  // Initialize auth state from session (ASSUMPTION-02 & ASSUMPTION-03)
  fetch('/api/auth/me')
    .then(r => r.json())
    .then(data => {
      if (data.authenticated) {
        const nameEl = document.getElementById('topbar-analyst-name');
        if (nameEl) nameEl.textContent = data.username;
        if (data.role && ROLE_HIERARCHY[data.role]) {
          switchRole(data.role);
          return;
        }
      }
      applyRolePermissions(state.currentRole);
    })
    .catch(() => {
      applyRolePermissions(state.currentRole);
    });
});
