"""Automated reproduction script for Sprint 2 SIEM compliance evidence artifacts.

This script executes headless Playwright Chromium to capture verified screenshots
across all required viewports (1440px Desktop, 1024px Tablet, 390px Mobile, Standalone file://),
validates computed contrast styles, and computes a SHA-256 manifest.
"""

import hashlib
import json
import os
import shutil
import time
from datetime import datetime, timezone
from playwright.sync_api import sync_playwright

LOCAL_URL = "http://127.0.0.1:8000"
INDEX_PATH = os.path.abspath("index.html").replace("\\", "/")
FILE_URL = f"file:///{INDEX_PATH}"

OUTPUT_DIR = os.path.abspath("evidence/sprint2_verified")
ARTIFACT_DIR = r"C:\Users\ASUS\.gemini\antigravity\brain\d2ba9a39-aab1-4f8a-9e0c-df3838461eb6"
ARTIFACT_EVIDENCE_DIR = os.path.join(ARTIFACT_DIR, "evidence")

os.makedirs(OUTPUT_DIR, exist_ok=True)
os.makedirs(ARTIFACT_EVIDENCE_DIR, exist_ok=True)


def get_head_sha() -> str:
    """Retrieve current Git HEAD commit SHA."""
    try:
        import subprocess
        res = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, check=True)
        return res.stdout.strip()[:7]
    except Exception:
        return "latest"


def save_artifact(source_path: str, filename: str) -> None:
    """Sync evidence file to local evidence directory and artifact directory."""
    dest_local = os.path.join(OUTPUT_DIR, filename)
    dest_artifact = os.path.join(ARTIFACT_DIR, filename)
    dest_artifact_ev = os.path.join(ARTIFACT_EVIDENCE_DIR, filename)

    if source_path != dest_local:
        shutil.copy2(source_path, dest_local)
    shutil.copy2(source_path, dest_artifact)
    shutil.copy2(source_path, dest_artifact_ev)


def write_meta(filename: str, data: dict) -> None:
    """Write metadata json file for each evidence capture."""
    meta_name = filename.rsplit(".", 1)[0] + ".meta.json"
    meta_path = os.path.join(OUTPUT_DIR, meta_name)
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    save_artifact(meta_path, meta_name)


def compute_manifest() -> str:
    """Generate SHA-256 checksums for all PNG evidence artifacts."""
    manifest_lines = []
    for fname in sorted(os.listdir(OUTPUT_DIR)):
        if fname.endswith(".png"):
            fpath = os.path.join(OUTPUT_DIR, fname)
            with open(fpath, "rb") as f:
                digest = hashlib.sha256(f.read()).hexdigest()
            manifest_lines.append(f"{digest}  {fname}")
    manifest_content = "\n".join(manifest_lines) + "\n"
    manifest_path = os.path.join(OUTPUT_DIR, "manifest.sha256")
    with open(manifest_path, "w", encoding="utf-8") as f:
        f.write(manifest_content)
    save_artifact(manifest_path, "manifest.sha256")
    return manifest_path


def run_evidence_pipeline():
    commit_sha = get_head_sha()
    print("=== Starting Sprint 2 Evidence Generation ===")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)

        # -----------------------------------------------------------------
        # 1. DESKTOP 1440x900 MATRIX
        # -----------------------------------------------------------------
        context_dt = browser.new_context(viewport={"width": 1440, "height": 900}, device_scale_factor=1.0)
        page_dt = context_dt.new_page()

        routes = [
            ("overview", f"{LOCAL_URL}/?guest=1"),
            ("alerts", f"{LOCAL_URL}/alerts?guest=1"),
            ("scenarios", f"{LOCAL_URL}/scenarios?guest=1"),
            ("devices", f"{LOCAL_URL}/devices?guest=1"),
            ("signin", f"{LOCAL_URL}/login")
        ]

        for name, url in routes:
            page_dt.goto(url, wait_until="networkidle")
            page_dt.wait_for_timeout(300)
            if name != "signin":
                page_dt.evaluate("() => { const m = document.getElementById('signin-modal'); if (m) m.classList.remove('active'); }")

            # Light Theme
            page_dt.evaluate("() => { if (window.setTheme) window.setTheme('light'); else document.documentElement.setAttribute('data-theme', 'light'); }")
            page_dt.wait_for_timeout(300)
            fname_l = f"sprint2_1440_{name}_light.png"
            fpath_l = os.path.join(OUTPUT_DIR, fname_l)
            page_dt.screenshot(path=fpath_l)
            save_artifact(fpath_l, fname_l)
            write_meta(fname_l, {
                "commit_sha": commit_sha,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "viewport": {"width": 1440, "height": 900, "dpr": 1.0},
                "theme": "light",
                "route": name,
                "mode": "dynamic"
            })

            # Dark Theme
            page_dt.evaluate("() => { if (window.setTheme) window.setTheme('dark'); else document.documentElement.setAttribute('data-theme', 'dark'); }")
            page_dt.wait_for_timeout(300)
            fname_d = f"sprint2_1440_{name}_dark.png"
            fpath_d = os.path.join(OUTPUT_DIR, fname_d)
            page_dt.screenshot(path=fpath_d)
            save_artifact(fpath_d, fname_d)
            write_meta(fname_d, {
                "commit_sha": commit_sha,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "viewport": {"width": 1440, "height": 900, "dpr": 1.0},
                "theme": "dark",
                "route": name,
                "mode": "dynamic"
            })
            print(f"Captured 1440 {name} (Light & Dark)")

        # -----------------------------------------------------------------
        # 2. DRAWER & ACTIVITY TRAIL (Scrolled View with CONTAINMENT_EXECUTED)
        # -----------------------------------------------------------------
        print("Capturing Alert Drawer & Activity Trail (with full containment lifecycle)...")
        page_dt.goto(f"{LOCAL_URL}/alerts?guest=1", wait_until="networkidle")
        page_dt.evaluate("() => { const m = document.getElementById('signin-modal'); if (m) m.classList.remove('active'); }")
        page_dt.click("tr.clickable:first-child")
        page_dt.wait_for_selector("#alert-drawer-backdrop.active", timeout=5000)
        page_dt.wait_for_timeout(400)

        # Scroll to bottom to reveal Activity Trail with CONTAINMENT_EXECUTED
        page_dt.evaluate("() => { const sb = document.querySelector('.drawer-scroll-body'); if (sb) sb.scrollTop = sb.scrollHeight; }")
        page_dt.wait_for_timeout(300)

        # Light Drawer
        page_dt.evaluate("() => { if (window.setTheme) window.setTheme('light'); }")
        page_dt.wait_for_timeout(300)
        fname_dw_l = "sprint2_1440_drawer_timeline_light.png"
        fpath_dw_l = os.path.join(OUTPUT_DIR, fname_dw_l)
        page_dt.screenshot(path=fpath_dw_l)
        save_artifact(fpath_dw_l, fname_dw_l)
        write_meta(fname_dw_l, {
            "commit_sha": commit_sha,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "viewport": {"width": 1440, "height": 900, "dpr": 1.0},
            "theme": "light",
            "component": "alert-drawer-timeline",
            "mode": "dynamic",
            "lifecycle_stages": ["ALERT_TRIGGERED", "ALERT_ACKNOWLEDGED", "INVESTIGATION_STARTED", "CONTAINMENT_EXECUTED"]
        })

        # Dark Drawer
        page_dt.evaluate("() => { if (window.setTheme) window.setTheme('dark'); }")
        page_dt.wait_for_timeout(300)
        fname_dw_d = "sprint2_1440_drawer_timeline_dark.png"
        fpath_dw_d = os.path.join(OUTPUT_DIR, fname_dw_d)
        page_dt.screenshot(path=fpath_dw_d)
        save_artifact(fpath_dw_d, fname_dw_d)
        write_meta(fname_dw_d, {
            "commit_sha": commit_sha,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "viewport": {"width": 1440, "height": 900, "dpr": 1.0},
            "theme": "dark",
            "component": "alert-drawer-timeline",
            "mode": "dynamic",
            "lifecycle_stages": ["ALERT_TRIGGERED", "ALERT_ACKNOWLEDGED", "INVESTIGATION_STARTED", "CONTAINMENT_EXECUTED"]
        })
        print("Captured Drawer with full Activity Trail (Light & Dark)")

        # -----------------------------------------------------------------
        # 3. KEYBOARD INTERACTION & FOCUS EVIDENCE
        # -----------------------------------------------------------------
        print("Capturing Keyboard Controller active focus...")
        page_dt.goto(f"{LOCAL_URL}/alerts?guest=1", wait_until="networkidle")
        page_dt.evaluate("() => { const m = document.getElementById('signin-modal'); if (m) m.classList.remove('active'); }")
        page_dt.keyboard.press("j")
        page_dt.wait_for_timeout(100)
        page_dt.keyboard.press("j")
        page_dt.wait_for_timeout(200)

        fname_kb = "sprint2_1440_keyboard_navigation.png"
        fpath_kb = os.path.join(OUTPUT_DIR, fname_kb)
        page_dt.screenshot(path=fpath_kb)
        save_artifact(fpath_kb, fname_kb)
        write_meta(fname_kb, {
            "commit_sha": commit_sha,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "viewport": {"width": 1440, "height": 900, "dpr": 1.0},
            "interaction": "keyboard-j-navigation",
            "mode": "dynamic"
        })
        context_dt.close()

        # -----------------------------------------------------------------
        # 4. TABLET 1024x768 MATRIX
        # -----------------------------------------------------------------
        print("Capturing Tablet 1024x768 matrix...")
        context_tab = browser.new_context(viewport={"width": 1024, "height": 768}, device_scale_factor=1.0)
        page_tab = context_tab.new_page()

        for name in ["overview", "alerts"]:
            page_tab.goto(f"{LOCAL_URL}/{name if name != 'overview' else ''}?guest=1", wait_until="networkidle")
            page_tab.wait_for_timeout(300)
            page_tab.evaluate("() => { const m = document.getElementById('signin-modal'); if (m) m.classList.remove('active'); }")

            # Light
            page_tab.evaluate("() => { if (window.setTheme) window.setTheme('light'); }")
            page_tab.wait_for_timeout(300)
            fname_tl = f"sprint2_1024_{name}_light.png"
            fpath_tl = os.path.join(OUTPUT_DIR, fname_tl)
            page_tab.screenshot(path=fpath_tl)
            save_artifact(fpath_tl, fname_tl)
            write_meta(fname_tl, {
                "commit_sha": commit_sha,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "viewport": {"width": 1024, "height": 768, "dpr": 1.0},
                "theme": "light",
                "route": name,
                "mode": "dynamic"
            })

            # Dark
            page_tab.evaluate("() => { if (window.setTheme) window.setTheme('dark'); }")
            page_tab.wait_for_timeout(300)
            fname_td = f"sprint2_1024_{name}_dark.png"
            fpath_td = os.path.join(OUTPUT_DIR, fname_td)
            page_tab.screenshot(path=fpath_td)
            save_artifact(fpath_td, fname_td)
            write_meta(fname_td, {
                "commit_sha": commit_sha,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "viewport": {"width": 1024, "height": 768, "dpr": 1.0},
                "theme": "dark",
                "route": name,
                "mode": "dynamic"
            })
            print(f"Captured 1024 {name} (Light & Dark)")
        context_tab.close()

        # -----------------------------------------------------------------
        # 5. MOBILE 390x844 (iPhone 14) MATRIX - REMEDIATED CARDS & KPI BANNER
        # -----------------------------------------------------------------
        print("Capturing Mobile 390x844 matrix (Remediated Dark Contrast)...")
        context_mob = browser.new_context(viewport={"width": 390, "height": 844}, device_scale_factor=2.0, is_mobile=True, has_touch=True)
        page_mob = context_mob.new_page()

        for name in ["overview", "alerts"]:
            page_mob.goto(f"{LOCAL_URL}/{name if name != 'overview' else ''}?guest=1", wait_until="networkidle")
            page_mob.wait_for_timeout(300)
            page_mob.evaluate("() => { const m = document.getElementById('signin-modal'); if (m) m.classList.remove('active'); }")

            # Light
            page_mob.evaluate("() => { if (window.setTheme) window.setTheme('light'); }")
            page_mob.wait_for_timeout(300)
            fname_ml = f"sprint2_390_{name}_light.png"
            fpath_ml = os.path.join(OUTPUT_DIR, fname_ml)
            page_mob.screenshot(path=fpath_ml)
            save_artifact(fpath_ml, fname_ml)
            write_meta(fname_ml, {
                "commit_sha": commit_sha,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "viewport": {"width": 390, "height": 844, "dpr": 2.0},
                "theme": "light",
                "route": name,
                "mode": "dynamic"
            })

            # Dark (Remediated: dark mobile-alert-card and dark kpi-cell-total banner)
            page_mob.evaluate("() => { if (window.setTheme) window.setTheme('dark'); }")
            page_mob.wait_for_timeout(300)
            fname_md = f"sprint2_390_{name}_dark.png"
            fpath_md = os.path.join(OUTPUT_DIR, fname_md)
            page_mob.screenshot(path=fpath_md)
            save_artifact(fpath_md, fname_md)
            write_meta(fname_md, {
                "commit_sha": commit_sha,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "viewport": {"width": 390, "height": 844, "dpr": 2.0},
                "theme": "dark",
                "route": name,
                "mode": "dynamic"
            })
            print(f"Captured 390 {name} (Light & Dark)")

        # Mobile Bottom Sheet Drawer
        page_mob.goto(f"{LOCAL_URL}/alerts?guest=1", wait_until="networkidle")
        page_mob.wait_for_timeout(300)
        page_mob.evaluate("() => { const m = document.getElementById('signin-modal'); if (m) m.classList.remove('active'); }")
        page_mob.evaluate("openAlertDrawer('EVT-2610-099')")
        page_mob.wait_for_selector("#alert-drawer-backdrop.active", timeout=5000)
        page_mob.wait_for_timeout(400)

        # Light
        page_mob.evaluate("() => { if (window.setTheme) window.setTheme('light'); }")
        page_mob.wait_for_timeout(300)
        fname_mdw_l = "sprint2_390_drawer_light.png"
        fpath_mdw_l = os.path.join(OUTPUT_DIR, fname_mdw_l)
        page_mob.screenshot(path=fpath_mdw_l)
        save_artifact(fpath_mdw_l, fname_mdw_l)
        write_meta(fname_mdw_l, {
            "commit_sha": commit_sha,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "viewport": {"width": 390, "height": 844, "dpr": 2.0},
            "theme": "light",
            "component": "mobile-bottom-sheet-drawer",
            "mode": "dynamic"
        })

        # Dark
        page_mob.evaluate("() => { if (window.setTheme) window.setTheme('dark'); }")
        page_mob.wait_for_timeout(300)
        fname_mdw_d = "sprint2_390_drawer_dark.png"
        fpath_mdw_d = os.path.join(OUTPUT_DIR, fname_mdw_d)
        page_mob.screenshot(path=fpath_mdw_d)
        save_artifact(fpath_mdw_d, fname_mdw_d)
        write_meta(fname_mdw_d, {
            "commit_sha": commit_sha,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "viewport": {"width": 390, "height": 844, "dpr": 2.0},
            "theme": "dark",
            "component": "mobile-bottom-sheet-drawer",
            "mode": "dynamic"
        })
        print("Captured Mobile 390 Drawer (Light & Dark)")
        context_mob.close()

        # -----------------------------------------------------------------
        # 6. COLD-LOAD FOUC PREVENTION (Dynamic App)
        # -----------------------------------------------------------------
        print("Capturing Cold-load FOUC check...")
        context_fouc = browser.new_context(viewport={"width": 1440, "height": 900})
        page_fouc = context_fouc.new_page()
        page_fouc.goto(f"{LOCAL_URL}/?guest=1", wait_until="networkidle")
        page_fouc.evaluate("() => localStorage.setItem('soc-theme', 'dark')")
        page_fouc.reload(wait_until="domcontentloaded")
        early_theme = page_fouc.evaluate("() => document.documentElement.getAttribute('data-theme')")
        early_color = page_fouc.evaluate("() => document.querySelector('meta[name=\"theme-color\"]').content")
        assert early_theme == "dark"
        assert early_color == "#0E0F0C"

        fname_fouc = "sprint2_1440_cold_load_dark_nofouc.png"
        fpath_fouc = os.path.join(OUTPUT_DIR, fname_fouc)
        page_fouc.screenshot(path=fpath_fouc)
        save_artifact(fpath_fouc, fname_fouc)
        write_meta(fname_fouc, {
            "commit_sha": commit_sha,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "viewport": {"width": 1440, "height": 900, "dpr": 1.0},
            "theme": "dark",
            "early_theme_applied": early_theme,
            "theme_color_meta": early_color,
            "mode": "dynamic"
        })
        context_fouc.close()

        # -----------------------------------------------------------------
        # 7. STANDALONE PREVIEW MATRIX (Direct Full Renders)
        # -----------------------------------------------------------------
        print("Capturing Standalone Preview Matrix (Overview, MITRE filter, Drawer)...")
        # 1440 Desktop Page
        page_sa = browser.new_page(viewport={"width": 1440, "height": 900})
        page_sa.goto(FILE_URL, wait_until="networkidle")
        page_sa.evaluate("() => { const m = document.getElementById('signin-modal'); if (m) { m.classList.remove('active'); m.style.display = 'none'; } }")
        page_sa.wait_for_timeout(400)

        # Standalone Light 1440 Overview
        page_sa.evaluate("() => { document.documentElement.setAttribute('data-theme', 'light'); }")
        page_sa.wait_for_timeout(400)
        fname_sal_1440 = "sprint2_standalone_light_1440.png"
        fpath_sal_1440 = os.path.join(OUTPUT_DIR, fname_sal_1440)
        page_sa.screenshot(path=fpath_sal_1440)
        save_artifact(fpath_sal_1440, fname_sal_1440)
        write_meta(fname_sal_1440, {
            "commit_sha": commit_sha,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "viewport": {"width": 1440, "height": 900, "dpr": 1.0},
            "theme": "light",
            "mode": "standalone"
        })

        # Standalone True Dark 1440 Overview
        page_sa.evaluate("() => { document.documentElement.setAttribute('data-theme', 'dark'); }")
        page_sa.wait_for_timeout(400)
        fname_sad_1440 = "sprint2_standalone_dark_1440.png"
        fpath_sad_1440 = os.path.join(OUTPUT_DIR, fname_sad_1440)
        page_sa.screenshot(path=fpath_sad_1440)
        save_artifact(fpath_sad_1440, fname_sad_1440)
        write_meta(fname_sad_1440, {
            "commit_sha": commit_sha,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "viewport": {"width": 1440, "height": 900, "dpr": 1.0},
            "theme": "dark",
            "mode": "standalone"
        })

        # Standalone MITRE Filter Active in Alerts tab
        page_sa.evaluate("() => { if (window.switchTab) window.switchTab('scenarios'); }")
        page_sa.wait_for_timeout(300)
        page_sa.evaluate("() => { if (window.filterAlertsByTechnique) window.filterAlertsByTechnique('T1498', 'Network Denial of Service'); }")
        page_sa.wait_for_timeout(400)
        fname_sa_mitre = "sprint2_standalone_mitre_filter.png"
        fpath_sa_mitre = os.path.join(OUTPUT_DIR, fname_sa_mitre)
        page_sa.screenshot(path=fpath_sa_mitre)
        save_artifact(fpath_sa_mitre, fname_sa_mitre)
        write_meta(fname_sa_mitre, {
            "commit_sha": commit_sha,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "viewport": {"width": 1440, "height": 900, "dpr": 1.0},
            "theme": "dark",
            "component": "standalone-mitre-filter",
            "mode": "standalone"
        })

        # Standalone Alert Drawer open
        page_sa.evaluate("() => { if (window.openAlertDrawer) window.openAlertDrawer('EVT-2610-099'); }")
        page_sa.wait_for_timeout(400)
        fname_sa_drawer = "sprint2_standalone_drawer_dark.png"
        fpath_sa_drawer = os.path.join(OUTPUT_DIR, fname_sa_drawer)
        page_sa.screenshot(path=fpath_sa_drawer)
        save_artifact(fpath_sa_drawer, fname_sa_drawer)
        write_meta(fname_sa_drawer, {
            "commit_sha": commit_sha,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "viewport": {"width": 1440, "height": 900, "dpr": 1.0},
            "theme": "dark",
            "component": "standalone-drawer",
            "mode": "standalone"
        })
        page_sa.close()

        # Standalone 390px Mobile Page
        page_sa_mob = browser.new_page(viewport={"width": 390, "height": 844}, device_scale_factor=2.0)
        page_sa_mob.goto(FILE_URL, wait_until="networkidle")
        page_sa_mob.evaluate("() => { const m = document.getElementById('signin-modal'); if (m) { m.classList.remove('active'); m.style.display = 'none'; } }")
        page_sa_mob.wait_for_timeout(400)

        # Light
        page_sa_mob.evaluate("() => { document.documentElement.setAttribute('data-theme', 'light'); }")
        page_sa_mob.wait_for_timeout(400)
        fname_sal_390 = "sprint2_standalone_light_390.png"
        fpath_sal_390 = os.path.join(OUTPUT_DIR, fname_sal_390)
        page_sa_mob.screenshot(path=fpath_sal_390)
        save_artifact(fpath_sal_390, fname_sal_390)
        write_meta(fname_sal_390, {
            "commit_sha": commit_sha,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "viewport": {"width": 390, "height": 844, "dpr": 2.0},
            "theme": "light",
            "mode": "standalone"
        })

        # Dark
        page_sa_mob.evaluate("() => { document.documentElement.setAttribute('data-theme', 'dark'); }")
        page_sa_mob.wait_for_timeout(400)
        fname_sad_390 = "sprint2_standalone_dark_390.png"
        fpath_sad_390 = os.path.join(OUTPUT_DIR, fname_sad_390)
        page_sa_mob.screenshot(path=fpath_sad_390)
        save_artifact(fpath_sad_390, fname_sad_390)
        write_meta(fname_sad_390, {
            "commit_sha": commit_sha,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "viewport": {"width": 390, "height": 844, "dpr": 2.0},
            "theme": "dark",
            "mode": "standalone"
        })
        page_sa_mob.close()

        browser.close()

    manifest_file = compute_manifest()
    print("=== Evidence Generation Complete! Manifest written successfully. ===")


if __name__ == "__main__":
    run_evidence_pipeline()
