"""Authenticator code input page handling for batch generation."""

import re
import time
from collections.abc import Callable
from urllib.parse import urlparse


ProgressLogger = Callable[[str, str], None]
EmitProgress = Callable[[str, str, ProgressLogger | None], None]
FillFirst = Callable[[object, list[str], str, int], str | None]
ClickFirst = Callable[[object, list[str], int], str | None]
GetTwoFaCode = Callable[[str, ProgressLogger | None], str]
ClickLaterIfPresent = Callable[[object, ProgressLogger | None], bool]

AUTHENTICATOR_CODE_INPUT_SELECTORS = [
    "#totpPin",
    "input[name='totpPin']",
]
AUTHENTICATOR_CODE_NEXT_SELECTORS = [
    "#totpNext button",
    "button:has-text('Next')",
    "button:has-text('下一步')",
]
AUTHENTICATOR_CODE_TEXT_MARKERS = (
    "两步验证",
    "two-step verification",
    "two-factor authentication",
    "2fa",
    "verification code",
)


def _submission_cache_key(page) -> str:
    current_url = str(getattr(page, "url", "") or "")
    parsed = urlparse(current_url)
    return f"{parsed.hostname or ''}{parsed.path or ''}"


def was_authenticator_code_submitted_recently(page, cooldown_seconds: int = 8) -> bool:
    last_submission = getattr(page, "_batch_authenticator_code_last_submission", None)
    if not isinstance(last_submission, dict):
        return False

    current_key = _submission_cache_key(page)
    last_key = str(last_submission.get("key") or "")
    last_at = float(last_submission.get("at") or 0.0)
    if not current_key or current_key != last_key:
        return False
    return (time.monotonic() - last_at) < cooldown_seconds


def mark_authenticator_code_submitted(page) -> None:
    setattr(
        page,
        "_batch_authenticator_code_last_submission",
        {"key": _submission_cache_key(page), "at": time.monotonic()},
    )


def has_authenticator_code_input(page) -> bool:
    for selector in AUTHENTICATOR_CODE_INPUT_SELECTORS:
        try:
            if page.locator(selector).count() > 0:
                return True
        except Exception:
            continue
    return False


def has_authenticator_code_prompt(page) -> bool:
    try:
        page_text = page.locator("body").inner_text(timeout=3000).lower()
    except Exception:
        return False

    normalized_text = re.sub(r"\s+", " ", page_text).strip()
    return any(marker in normalized_text for marker in AUTHENTICATOR_CODE_TEXT_MARKERS)


def submit_authenticator_code_page(
    page,
    two_fa_key: str,
    *,
    get_2fa_code: GetTwoFaCode,
    fill_first: FillFirst,
    click_first: ClickFirst,
    click_later_if_present: ClickLaterIfPresent,
    emit_progress: EmitProgress,
    progress_logger: ProgressLogger | None = None,
) -> bool:
    if not (has_authenticator_code_input(page) or has_authenticator_code_prompt(page)):
        return False

    emit_progress("检测到2FA，正在获取验证码", "info", progress_logger)
    code = get_2fa_code(two_fa_key, progress_logger)
    if not code:
        emit_progress("检测到2FA，但未获取到验证码", "warning", progress_logger)
        return False

    emit_progress("正在填充2FA验证码", "info", progress_logger)
    selector = fill_first(
        page,
        AUTHENTICATOR_CODE_INPUT_SELECTORS,
        code,
        8000,
    )
    if not selector:
        emit_progress("未找到可填充的2FA验证码输入框", "warning", progress_logger)
        return False

    emit_progress(f"2FA验证码已填充，输入框: {selector}", "info", progress_logger)
    clicked_selector = click_first(page, AUTHENTICATOR_CODE_NEXT_SELECTORS, 8000)
    if clicked_selector:
        mark_authenticator_code_submitted(page)
        emit_progress(f"2FA验证码已提交，按钮: {clicked_selector}", "info", progress_logger)
        page.wait_for_timeout(1500)
        click_later_if_present(page, progress_logger)
    else:
        emit_progress("2FA验证码已填充，但未找到下一步按钮", "warning", progress_logger)

    return True
