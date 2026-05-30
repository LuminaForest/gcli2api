"""Page validation and page-state detection helpers for batch generation."""

import re
import time
from collections.abc import Callable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from log import log
from src.batch_generate_pages.phone_number_entry import (
    has_phone_number_entry_prompt as _validation_page_has_phone_number_entry_prompt,
)


ProgressLogger = Callable[[str, str], None]

_PHONE_RATE_LIMIT_MARKERS = (
    "too many failed attempts",
    "too many attempts",
    "too many tries",
    "you've tried too many times",
    "you have tried too many times",
    "this phone number has already been used too many times for verification",
    "phone number has already been used too many times for verification",
)
_SERVICE_UNAVAILABLE_MARKERS = (
    "entire service unavailable",
    "the entire service is unavailable",
)
_PAGE_LOAD_FAILURE_MARKERS = (
    "page.goto",
    "net::err_",
    "err_connection",
    "err_tunnel",
    "err_proxy",
    "proxyerror",
    "connecterror",
    "proxy authentication required",
    "407 proxy authentication required",
    "invalid full account format",
    "connection closed",
    "connection reset",
    "connection timed out",
    "navigation timeout",
)
_PAGE_LOAD_FAILURE_STATUSES = {
    "page_load_failed",
    "open_failed",
    "page_load_timeout",
}


class AccountUnusableError(RuntimeError):
    def __init__(self, status: str, message: str):
        super().__init__(message)
        self.status = str(status or "account_unusable").strip() or "account_unusable"
        self.message = str(message or "").strip()


def _emit_progress(
    message: str,
    level: str = "info",
    progress_logger: ProgressLogger | None = None,
) -> None:
    if level == "warning":
        log.warning(f"[BATCH_GENERATE] {message}")
    elif level == "error":
        log.error(f"[BATCH_GENERATE] {message}")
    else:
        log.info(f"[BATCH_GENERATE] {message}")

    if progress_logger:
        progress_logger(message, level)


def _mask_value(value: str, keep_start: int = 4, keep_end: int = 4) -> str:
    value = str(value or "")
    if len(value) <= keep_start + keep_end:
        return "*" * len(value)
    return f"{value[:keep_start]}...{value[-keep_end:]}"


def _redact_query_value(url: str, keys: set[str]) -> str:
    parsed = urlparse(str(url or ""))
    if not parsed.query:
        return url

    query = parse_qs(parsed.query, keep_blank_values=True)
    for key in keys:
        if key in query:
            query[key] = [_mask_value(query[key][0])]

    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def _is_page_load_failure_error(error: str) -> bool:
    error_text = str(error or "").lower()
    return any(marker in error_text for marker in _PAGE_LOAD_FAILURE_MARKERS)


def _is_page_load_failure_result(result: dict) -> bool:
    status = str((result or {}).get("status") or "").strip()
    validation_status = str(((result or {}).get("validation") or {}).get("status") or "").strip()
    return status in _PAGE_LOAD_FAILURE_STATUSES or validation_status in _PAGE_LOAD_FAILURE_STATUSES


def _wait_before_page_judgement(
    page,
    label: str,
    progress_logger: ProgressLogger | None = None,
) -> int:
    return 0


def _page_body_text(page, timeout: int = 3000) -> str:
    try:
        return page.locator("body").inner_text(timeout=timeout)
    except Exception:
        return ""


def _contains_service_unavailable_message(text: str) -> bool:
    normalized = str(text or "").lower()
    return any(marker in normalized for marker in _SERVICE_UNAVAILABLE_MARKERS)


def _page_has_service_unavailable(page) -> bool:
    return _contains_service_unavailable_message(_page_body_text(page, timeout=2000))


def _page_has_recover_account(page) -> bool:
    normalized = re.sub(r"\s+", " ", _page_body_text(page, timeout=2000).lower()).strip()
    return "recover account" in normalized


def _raise_if_recover_account_page(
    page,
    progress_logger: ProgressLogger | None = None,
) -> None:
    if not _page_has_recover_account(page):
        return

    message = "页面提示 Recover account，该账号不可用"
    _emit_progress(message, level="error", progress_logger=progress_logger)
    raise AccountUnusableError("recover_account_required", message)


def _raise_if_service_unavailable_page(
    page,
    progress_logger: ProgressLogger | None = None,
) -> None:
    if not _page_has_service_unavailable(page):
        return

    message = "页面提示 Entire service unavailable，该账号不可用"
    _emit_progress(message, level="error", progress_logger=progress_logger)
    try:
        page.wait_for_timeout(3000)
    except Exception:
        time.sleep(3)
    raise AccountUnusableError("service_unavailable", message)


def _is_verify_info_selection_page(page) -> bool:
    current_url = str(getattr(page, "url", "") or "")
    parsed = urlparse(current_url)
    if parsed.hostname == "accounts.google.com" and parsed.path.rstrip("/") == "/uplevelingstep/selection":
        return True

    try:
        return bool(
            page.evaluate(
                """() => {
                    const normalize = (value) => String(value || '').replace(/\\s+/g, ' ').trim().toLowerCase();
                    const bodyText = normalize(document.body ? document.body.innerText : '');
                    return bodyText.includes('verify your info to continue');
                }"""
            )
        )
    except Exception:
        return False


def _validation_page_has_qr_code(page) -> bool:
    if _validation_page_has_phone_prompt(page):
        return False

    try:
        return bool(
            page.evaluate(
                """() => {
                    const visible = (el) => {
                        const rect = el.getBoundingClientRect();
                        const style = window.getComputedStyle(el);
                        return Boolean(rect.width && rect.height) &&
                            style.visibility !== 'hidden' &&
                            style.display !== 'none' &&
                            style.opacity !== '0';
                    };
                    const media = Array.from(document.querySelectorAll('img, canvas, svg'));
                    return media.some((el) => {
                        if (!visible(el)) return false;
                        const rect = el.getBoundingClientRect();
                        if (rect.width < 180 || rect.height < 180) return false;
                        if (rect.width > 520 || rect.height > 520) return false;
                        const ratio = rect.width / Math.max(rect.height, 1);
                        if (ratio < 0.8 || ratio > 1.2) return false;
                        const viewportWidth = window.innerWidth || document.documentElement.clientWidth || 0;
                        const viewportHeight = window.innerHeight || document.documentElement.clientHeight || 0;
                        const centerX = rect.left + rect.width / 2;
                        const centerY = rect.top + rect.height / 2;
                        return (
                            centerX > viewportWidth * 0.2 &&
                            centerX < viewportWidth * 0.8 &&
                            centerY > viewportHeight * 0.15 &&
                            centerY < viewportHeight * 0.85
                        );
                    });
                }"""
            )
        )
    except Exception:
        return False


def _validation_page_has_phone_prompt(page) -> bool:
    if _validation_page_has_phone_number_entry_prompt(page):
        return True

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
                    const inputs = Array.from(document.querySelectorAll('input'));
                    const hasPhoneInput = inputs.some((el) => {
                        if (!visible(el)) return false;
                        const autocomplete = String(el.autocomplete || '').toLowerCase();
                        const attrs = [
                            el.name,
                            el.id,
                            autocomplete,
                            el.className,
                            el.getAttribute('jsname'),
                            el.getAttribute('aria-label'),
                            el.getAttribute('placeholder')
                        ].join(' ').toLowerCase();
                        if (
                            attrs.includes('totp') ||
                            attrs.includes('code') ||
                            attrs.includes('idv') ||
                            attrs.includes('pin')
                        ) {
                            return false;
                        }
                        return (
                            el.id === 'phoneNumberId' ||
                            autocomplete === 'tel' ||
                            attrs.includes('phone') ||
                            attrs.includes('mobile') ||
                            attrs.includes('电话') ||
                            attrs.includes('手機') ||
                            attrs.includes('số điện thoại')
                        );
                    });

                    if (hasPhoneInput) return true;

                    const phoneSelectors = [
                        '#phoneNumberId',
                        '#idvPreregisteredPhoneNext',
                        '#idvPreregisteredPhonePin',
                        '#idvAnyPhonePin',
                        '#idvPin',
                        '#idvAnyPhonePinNext',
                        '#idvPinNext'
                    ];
                    for (const selector of phoneSelectors) {
                        const el = document.querySelector(selector);
                        if (el && visible(el)) return true;
                    }

                    const phoneAttrPattern = /(phone|mobile|sms|tel|preregisteredphone|anyphone|idvpin|idvphone)/i;
                    const interactive = Array.from(document.querySelectorAll(
                        "button, [role='button'], a, [role='link'], div, section"
                    ));
                    return interactive.some((el) => {
                        if (!visible(el)) return false;
                        const attrs = [
                            el.id,
                            el.className,
                            el.getAttribute('jsname'),
                            el.getAttribute('aria-controls'),
                            el.getAttribute('data-secondary-action-label')
                        ].filter(Boolean).join(' ');
                        return phoneAttrPattern.test(attrs);
                    });
                }"""
            )
        )
    except Exception:
        return False


def _validation_page_has_phone_input(page) -> bool:
    if _validation_page_has_phone_number_entry_prompt(page):
        try:
            return bool(
                page.evaluate(
                    """() => Array.from(document.querySelectorAll('input')).some((el) => {
                        const rect = el.getBoundingClientRect();
                        const type = String(el.type || '').toLowerCase();
                        return Boolean(rect.width && rect.height) &&
                            type !== 'hidden' &&
                            type !== 'password';
                    })"""
                )
            )
        except Exception:
            return False

    try:
        return bool(
            page.evaluate(
                """() => {
                    const inputs = Array.from(document.querySelectorAll('input'));
                    return inputs.some((el) => {
                        const rect = el.getBoundingClientRect();
                        if (!rect.width || !rect.height) return false;
                        const autocomplete = String(el.autocomplete || '').toLowerCase();
                        const attrs = [
                            el.name,
                            el.id,
                            autocomplete,
                            el.getAttribute('aria-label'),
                            el.getAttribute('placeholder')
                        ].join(' ').toLowerCase();
                        if (
                            attrs.includes('totp') ||
                            attrs.includes('code') ||
                            attrs.includes('idv') ||
                            attrs.includes('pin')
                        ) {
                            return false;
                        }
                        return (
                            el.id === 'phoneNumberId' ||
                            autocomplete === 'tel' ||
                            attrs.includes('phone') ||
                            attrs.includes('mobile') ||
                            attrs.includes('电话') ||
                            attrs.includes('手機') ||
                            attrs.includes('số điện thoại')
                        );
                    });
                }"""
            )
        )
    except Exception:
        return False


def _validation_page_diagnostic_snapshot(page) -> str:
    try:
        return str(
            page.evaluate(
                """() => {
                    const normalize = (value) => String(value || '').replace(/\\s+/g, ' ').trim();
                    const bodyText = normalize(document.body ? document.body.innerText : '');
                    const inputs = Array.from(document.querySelectorAll('input'))
                        .filter((el) => {
                            const rect = el.getBoundingClientRect();
                            return Boolean(rect.width && rect.height);
                        })
                        .slice(0, 6)
                        .map((el) => [
                            el.type,
                            el.name,
                            el.id,
                            el.autocomplete,
                            el.getAttribute('aria-label'),
                            el.getAttribute('placeholder')
                        ].filter(Boolean).join('/'));
                    const actions = Array.from(document.querySelectorAll('button, [role="button"], a'))
                        .filter((el) => {
                            const rect = el.getBoundingClientRect();
                            return Boolean(rect.width && rect.height);
                        })
                        .slice(0, 8)
                        .map((el) => normalize(el.innerText || el.textContent || el.getAttribute('aria-label') || el.getAttribute('title')))
                        .filter(Boolean);
                    return `text=${bodyText.slice(0, 300)} | inputs=${inputs.join(' || ')} | actions=${actions.join(' || ')}`;
                }"""
            )
        )
    except Exception as exc:
        return f"诊断失败: {exc}"


def _validation_page_success(page) -> bool:
    current_url = str(getattr(page, "url", "") or "")
    parsed_url = urlparse(current_url)
    if (
        parsed_url.hostname == "developers.google.com"
        and parsed_url.path.rstrip("/") == "/gemini-code-assist/auth/auth_success_gemini"
    ):
        return True

    text = _page_body_text(page, timeout=2000).lower()
    return any(
        marker in text
        for marker in (
            "you’re all set",
            "you're all set",
            "verification complete",
            "verified",
            "success",
            "验证完成",
            "已验证",
            "hoàn tất",
            "thành công",
        )
    )


def _contains_phone_rate_limit_message(text: str) -> bool:
    normalized = str(text or "").lower()
    return any(marker in normalized for marker in _PHONE_RATE_LIMIT_MARKERS)


def _validation_page_has_phone_rate_limit(page) -> bool:
    try:
        return bool(
            page.evaluate(
                """() => {
                    const normalize = (value) => String(value || '').replace(/\\s+/g, ' ').trim().toLowerCase();
                    const visible = (el) => {
                        const rect = el.getBoundingClientRect();
                        const style = window.getComputedStyle(el);
                        return Boolean(rect.width && rect.height) &&
                            style.visibility !== 'hidden' &&
                            style.display !== 'none';
                    };
                    const texts = Array.from(document.querySelectorAll(
                        "[role='alert'], [aria-live], [data-error], div, span, p, h1, h2, h3"
                    ))
                        .filter((el) => visible(el))
                        .map((el) => normalize(
                            el.innerText ||
                            el.textContent ||
                            el.getAttribute('aria-label') ||
                            el.getAttribute('title')
                        ))
                        .filter(Boolean);
                    texts.push(normalize(document.body ? document.body.innerText : ''));
                    return texts.some((text) =>
                        text.includes('too many failed attempts') ||
                        text.includes('too many attempts') ||
                        text.includes('too many tries') ||
                        text.includes("you've tried too many times") ||
                        text.includes('you have tried too many times') ||
                        text.includes('this phone number has already been used too many times for verification') ||
                        text.includes('phone number has already been used too many times for verification')
                    );
                }"""
            )
        )
    except Exception:
        return _contains_phone_rate_limit_message(_page_body_text(page, timeout=2000))


def _validation_page_has_send_button(page) -> bool:
    try:
        return bool(
            page.evaluate(
                """() => {
                    const normalize = (value) => String(value || '').replace(/\\s+/g, ' ').trim();
                    const visible = (el) => {
                        const rect = el.getBoundingClientRect();
                        const style = window.getComputedStyle(el);
                        return Boolean(rect.width && rect.height) &&
                            style.visibility !== 'hidden' &&
                            style.display !== 'none' &&
                            style.opacity !== '0';
                    };
                    const elements = Array.from(document.querySelectorAll(
                        "button, [role='button'], input[type='button'], input[type='submit']"
                    ));
                    return elements.some((el) => {
                        if (!visible(el)) return false;
                        if (el.disabled || el.getAttribute('aria-disabled') === 'true') return false;
                        const text = normalize(
                            el.innerText ||
                            el.textContent ||
                            el.value ||
                            el.getAttribute('aria-label') ||
                            el.getAttribute('title')
                        );
                        return text.toLowerCase() === 'send';
                    });
                }"""
            )
        )
    except Exception:
        return False
