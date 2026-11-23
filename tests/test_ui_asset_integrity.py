"""Guardrails for local UI assets and responsive icon coverage."""

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_every_font_awesome_compat_class_has_a_local_svg_definition():
    """Prevent a newly introduced fa-* class from silently rendering blank."""
    sources = [ROOT / "index.html", ROOT / "app/main.py"]
    sources.extend((ROOT / "templates").rglob("*.html"))
    combined = "\n".join(path.read_text(encoding="utf-8") for path in sources)

    used = set(re.findall(r"\bfa-([a-z][a-z0-9-]*)\b", combined))
    used.difference_update({"solid", "regular", "brands"})

    icon_script = (ROOT / "static/js/icons.js").read_text(encoding="utf-8")
    available = set(re.findall(r"^\s+'([a-z0-9-]+)':", icon_script, flags=re.MULTILINE))

    assert used <= available, f"Missing local SVG definitions: {sorted(used - available)}"


def test_dashboard_and_standalone_have_no_runtime_cdn_dependencies():
    """Fonts, icons and core engines must remain usable without the internet."""
    checked = [ROOT / "templates/base.html", ROOT / "index.html"]
    forbidden_hosts = (
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "cdnjs.cloudflare.com",
        "cdn.jsdelivr.net",
        "unpkg.com",
    )

    for path in checked:
        content = path.read_text(encoding="utf-8")
        for host in forbidden_hosts:
            assert host not in content, f"{path.name} still depends on {host}"


def test_dynamic_client_does_not_embed_demo_credentials_or_guest_bypass():
    """Keep authentication proof and demo secrets on the server side."""
    dynamic_sources = [ROOT / "static/js/app.js"]
    dynamic_sources.extend((ROOT / "templates").rglob("*.html"))
    combined = "\n".join(path.read_text(encoding="utf-8") for path in dynamic_sources)

    assert "vnpt-soc-2026" not in combined
    assert "?guest=1" not in combined
    assert "auth/guest" not in combined


def test_theme_toggle_and_navigation_icons_have_valid_svg_geometry():
    """Ensure key icons (moon, sun, border-all, triangle-exclamation) have valid SVG geometry."""
    icon_script = (ROOT / "static/js/icons.js").read_text(encoding="utf-8")
    icons = dict(re.findall(r"^\s+'([a-z0-9-]+)':\s*'([^']+)'", icon_script, flags=re.MULTILINE))

    assert "moon" in icons
    assert "sun" in icons
    assert "border-all" in icons
    assert "triangle-exclamation" in icons

    # Moon must use valid, centered crescent path and not broken coordinates
    assert "M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z" in icons["moon"]
    # Border-all must use distinct grid squares, not overlapping thick strokes
    assert 'rect width="7"' in icons["border-all"]
