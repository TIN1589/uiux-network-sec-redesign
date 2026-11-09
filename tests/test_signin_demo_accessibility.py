"""Browser regressions for the sign-in demo credential controls."""

import re
from pathlib import Path

import pytest
from playwright.sync_api import sync_playwright

REPO_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_ROOT = REPO_ROOT / "evidence" / "04_standalone_preview"


def _parse_rgb(value: str) -> tuple[int, int, int]:
    """Parse the RGB channels returned by browser computed styles."""
    match = re.search(r"rgba?\((\d+),\s*(\d+),\s*(\d+)", value)
    if not match:
        raise AssertionError(f"Unsupported computed color: {value}")
    return tuple(int(match.group(index)) for index in range(1, 4))


def _relative_luminance(value: str) -> float:
    """Calculate WCAG relative luminance for a computed RGB color."""
    channels = [channel / 255 for channel in _parse_rgb(value)]
    linear = [
        channel / 12.92
        if channel <= 0.03928
        else ((channel + 0.055) / 1.055) ** 2.4
        for channel in channels
    ]
    return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2]


def _contrast_ratio(foreground: str, background: str) -> float:
    """Return the WCAG contrast ratio between two computed colors."""
    values = sorted((_relative_luminance(foreground), _relative_luminance(background)))
    return (values[1] + 0.05) / (values[0] + 0.05)


@pytest.mark.parametrize(
    "width",
    [
        390,
        1440,
    ],
)
def test_dark_standalone_demo_controls_remain_readable_and_operable(width: int):
    """Standalone demo controls must retain WCAG AA contrast and usable height."""
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        context = browser.new_context(viewport={"width": width, "height": 900})
        page = context.new_page()
        page.goto((REPO_ROOT / "index.html").as_uri(), wait_until="domcontentloaded")
        page.evaluate(
            """() => {
              document.documentElement.setAttribute('data-theme', 'dark');
              if (window.setTheme) window.setTheme('dark');
            }"""
        )
        page.wait_for_selector(".signin-demo-box", state="visible")
        page.wait_for_timeout(200)

        styles = page.evaluate(
            """() => {
              const box = document.querySelector('.signin-demo-box');
              const title = box.querySelector('.signin-demo-title');
              const hint = box.querySelector('.signin-demo-pwd-hint');
              const pills = [...box.querySelectorAll('.signin-demo-pill')];
              const boxStyle = getComputedStyle(box);
              return {
                boxBackground: boxStyle.backgroundColor,
                titleColor: getComputedStyle(title).color,
                hintColor: getComputedStyle(hint).color,
                pills: pills.map((pill) => {
                  const style = getComputedStyle(pill);
                  return {
                    label: pill.textContent.trim(),
                    color: style.color,
                    background: style.backgroundColor,
                    height: pill.getBoundingClientRect().height
                  };
                })
              };
            }"""
        )

        assert _contrast_ratio(styles["titleColor"], styles["boxBackground"]) >= 4.5
        assert _contrast_ratio(styles["hintColor"], styles["boxBackground"]) >= 4.5
        assert len(styles["pills"]) == 3
        for pill in styles["pills"]:
            ratio = _contrast_ratio(pill["color"], pill["background"])
            assert ratio >= 4.5, f"{pill['label']} contrast is only {ratio:.2f}:1"
            assert pill["height"] >= 34, f"{pill['label']} is only {pill['height']}px high"

        EVIDENCE_ROOT.mkdir(parents=True, exist_ok=True)
        page.screenshot(
            path=EVIDENCE_ROOT / f"2026-10-31_signin-demo-dark-{width}.png",
            full_page=False,
        )
        context.close()
        browser.close()
