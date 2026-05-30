"""Robot verification page handling after Google email submission."""

import os
import re
import time
from collections.abc import Callable

from src.batch_generate_pages.password import is_password_page


ProgressLogger = Callable[[str, str], None]
EmitProgress = Callable[[str, str, ProgressLogger | None], None]

ROBOT_VERIFICATION_WAIT_SECONDS = 3600
ROBOT_VERIFICATION_MARKERS = (
    "confirm you're not a robot",
    "confirm you’re not a robot",
    "i'm not a robot",
    "i’m not a robot",
    "recaptcha",
)


def _robot_verification_wait_seconds() -> int:
    raw = os.getenv("BATCH_GENERATE_ROBOT_VERIFICATION_WAIT_SECONDS")
    if raw is None:
        return ROBOT_VERIFICATION_WAIT_SECONDS
    try:
        return max(0, int(str(raw).strip() or "0"))
    except Exception:
        return ROBOT_VERIFICATION_WAIT_SECONDS


def _page_text(page) -> str:
    try:
        return str(page.locator("body").inner_text(timeout=1000) or "")
    except Exception:
        return ""


def _has_recaptcha_element(page) -> bool:
    try:
        return bool(
            page.evaluate(
                """() => {
                    const visible = (el) => {
                        const rect = el.getBoundingClientRect();
                        const style = window.getComputedStyle(el);
                        return Boolean(rect.width && rect.height) &&
                            style.visibility !== 'hidden' &&
                            style.display !== 'none';
                    };
                    const elements = Array.from(document.querySelectorAll('iframe, div, span'));
                    return elements.some((el) => {
                        if (!visible(el)) return false;
                        const attrs = [
                            el.id,
                            el.className,
                            el.getAttribute('title'),
                            el.getAttribute('aria-label'),
                            el.getAttribute('src'),
                            el.getAttribute('data-sitekey')
                        ].filter(Boolean).join(' ').toLowerCase();
                        return attrs.includes('recaptcha') || attrs.includes('g-recaptcha');
                    });
                }"""
            )
        )
    except Exception:
        return False


def is_robot_verification_page(page) -> bool:
    normalized_text = re.sub(r"\s+", " ", _page_text(page).lower()).strip()
    if any(marker in normalized_text for marker in ROBOT_VERIFICATION_MARKERS):
        return True
    return _has_recaptcha_element(page)


def wait_for_robot_verification_if_present(
    page,
    *,
    emit_progress: EmitProgress,
    progress_logger: ProgressLogger | None = None,
    probe_seconds: float = 5,
) -> str:
    probe_seconds = max(0.0, float(probe_seconds or 0))
    probe_deadline = time.monotonic() + probe_seconds
    while True:
        if is_robot_verification_page(page):
            break
        if is_password_page(page):
            return "password_ready"
        if time.monotonic() >= probe_deadline:
            return ""
        page.wait_for_timeout(300)

    wait_seconds = _robot_verification_wait_seconds()
    if wait_seconds <= 0:
        emit_progress("检测到机器人验证页面，但等待时间为 0，继续后续流程", "warning", progress_logger)
        return "robot_detected"

    emit_progress(
        f"检测到机器人验证页面，请在浏览器中完成 reCAPTCHA 并点击 Next；最多等待 {wait_seconds} 秒",
        "warning",
        progress_logger,
    )

    deadline = time.monotonic() + wait_seconds
    last_wait_log_at = 0.0
    while time.monotonic() < deadline:
        if is_password_page(page):
            emit_progress("机器人验证已完成，检测到密码输入页", "info", progress_logger)
            return "password_ready"

        if not is_robot_verification_page(page):
            transition_deadline = time.monotonic() + 10
            while time.monotonic() < transition_deadline:
                if is_password_page(page):
                    emit_progress("机器人验证已完成，检测到密码输入页", "info", progress_logger)
                    return "password_ready"
                page.wait_for_timeout(500)
            emit_progress("机器人验证页面已离开，将继续后续流程", "info", progress_logger)
            return "left_robot_page"

        now = time.monotonic()
        if now - last_wait_log_at >= 30:
            last_wait_log_at = now
            emit_progress("仍在等待用户完成机器人验证页面", "info", progress_logger)
        page.wait_for_timeout(1000)

    emit_progress(
        "等待机器人验证完成超时，将继续尝试查找密码输入页",
        "warning",
        progress_logger,
    )
    return "timeout"
