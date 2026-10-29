/**
 * Theme Initializer Script
 * 
 * Script nap dong bo ngay trong the head truoc khi trinh duyet render stylesheet
 * nham ngan ngua hien tuong Flash of Unstyled Content (FOUC).
 * 
 * Thu tu uu tien xac dinh theme:
 * 1. Gia tri nguoi dung da luu trong localStorage ('soc-theme')
 * 2. Thiet lap prefers-color-scheme cua he dieu hanh
 * 3. Mac dinh 'light' (Warm Stone canvas)
 */
(function() {
  'use strict';

  var THEME_STORAGE_KEY = 'soc-theme';
  var theme = 'light';

  try {
    var savedTheme = localStorage.getItem(THEME_STORAGE_KEY);
    if (savedTheme === 'dark' || savedTheme === 'light') {
      theme = savedTheme;
    } else if (window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches) {
      theme = 'dark';
    }
  } catch (err) {
    // Phong truong hop cookies/storage bi chan boi sandbox security
    theme = 'light';
  }

  // Gan data-theme len the root html ngay lap tuc
  document.documentElement.setAttribute('data-theme', theme);
  if (document.documentElement.style) {
    document.documentElement.style.colorScheme = theme;
  }

  // Dong bo the meta theme-color cho PWA va trinh duyet di dong
  function syncThemeColor(activeTheme) {
    var color = activeTheme === 'dark' ? '#0E0F0C' : '#F3F1EC';
    var meta = document.querySelector('meta[name="theme-color"]');
    if (meta) {
      meta.setAttribute('content', color);
    } else if (document.head) {
      meta = document.createElement('meta');
      meta.setAttribute('name', 'theme-color');
      meta.setAttribute('content', color);
      document.head.appendChild(meta);
    }
  }

  syncThemeColor(theme);

  // Dam bao dong bo sau khi parser hoan tat the head
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function() {
      var currentTheme = document.documentElement.getAttribute('data-theme') || theme;
      syncThemeColor(currentTheme);
    });
  }
})();
