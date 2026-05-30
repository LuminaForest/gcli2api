"""SMS verification code page handling for Google verification."""

import re
import time
from collections.abc import Callable

from src.batch_generate_pages.phone_number_entry import has_phone_number_entry_prompt


ProgressLogger = Callable[[str, str], None]
EmitProgress = Callable[[str, str, ProgressLogger | None], None]
FillFirst = Callable[[object, list[str], str, int], str | None]
ClickFirstVisible = Callable[[object, list[str], int, int], str | None]
ClickValidationAction = Callable[[object, list[str], ProgressLogger | None], bool]
PageStatusCheck = Callable[[object], bool]
DiagnosticSnapshot = Callable[[object], str]

PHONE_CODE_SENT_PROMPT = "a text message with a 6-digit verification code was just sent"
PHONE_CODE_TEXT_MARKERS = (
    PHONE_CODE_SENT_PROMPT,
    "verification code",
    "enter the code",
    "enter your code",
    "security code",
    "code was sent",
    "text message",
    "sms",
    "验证码",
    "短信",
    "mã xác minh",
    "tin nhắn",
)
PHONE_CODE_INPUT_SELECTORS = [
    "#idvPin",
    "#idvAnyPhonePin",
    "input[name='idvPin']",
    "input[name='pin']",
    "input[autocomplete='one-time-code']",
    "input[id*='idv' i]",
    "input[id*='pin' i]",
    "input[name*='pin' i]",
    "input[name*='code' i]",
    "input[id*='code' i]",
    "input[aria-label*='code' i]",
    "input[placeholder*='code' i]",
    "input[aria-label*='验证码' i]",
    "input[placeholder*='验证码' i]",
    "input[type='tel']:not(#phoneNumberId):not(#totpPin)",
    "input[type='number']",
    "input[type='text']",
]
PHONE_CODE_NEXT_SELECTORS = [
    "#idvAnyPhonePinNext button",
    "#idvAnyPhonePinNext",
    "#idvPinNext button",
    "#idvPinNext",
    "#next button",
    "#next",
    "button:has-text('Next')",
    "div[role='button']:has-text('Next')",
    "button:has-text('Continue')",
    "div[role='button']:has-text('Continue')",
    "button:has-text('Verify')",
    "div[role='button']:has-text('Verify')",
    "button:has-text('Submit')",
    "div[role='button']:has-text('Submit')",
    "button:has-text('Done')",
    "div[role='button']:has-text('Done')",
    "button:has-text('下一步')",
    "div[role='button']:has-text('下一步')",
    "button:has-text('继续')",
    "div[role='button']:has-text('继续')",
    "button:has-text('验证')",
    "div[role='button']:has-text('验证')",
    "button:has-text('提交')",
    "div[role='button']:has-text('提交')",
    "button:has-text('Tiếp tục')",
    "div[role='button']:has-text('Tiếp tục')",
    "button:has-text('Xác minh')",
    "div[role='button']:has-text('Xác minh')",
]
PHONE_CODE_NEXT_TEXTS = [
    "Next",
    "Continue",
    "Verify",
    "Submit",
    "Done",
    "下一步",
    "继续",
    "验证",
    "提交",
    "完成",
    "Tiếp tục",
    "Xác minh",
    "Hoàn tất",
]


def _page_body_text(page, timeout: int = 2000) -> str:
    try:
        return str(page.locator("body").inner_text(timeout=timeout) or "")
    except Exception:
        return ""


def has_phone_verification_code_sent_prompt(page) -> bool:
    text = re.sub(r"\s+", " ", _page_body_text(page).lower()).strip()
    return PHONE_CODE_SENT_PROMPT in text


def has_phone_verification_code_input(page) -> bool:
    if has_phone_number_entry_prompt(page):
        return False

    text = re.sub(r"\s+", " ", _page_body_text(page).lower()).strip()
    has_code_text = any(marker in text for marker in PHONE_CODE_TEXT_MARKERS)
    try:
        has_code_input = bool(
            page.evaluate(
                """(hasCodeText) => {
                    const visibleInputs = Array.from(document.querySelectorAll('input'))
                        .filter((el) => {
                            const rect = el.getBoundingClientRect();
                            const type = String(el.type || '').toLowerCase();
                            return Boolean(rect.width && rect.height) &&
                                type !== 'hidden' &&
                                type !== 'password';
                        });

                    const nonPhoneInputs = visibleInputs.filter((el) => {
                        const autocomplete = String(el.autocomplete || '').toLowerCase();
                        const attrs = [
                            el.type,
                            el.name,
                            el.id,
                            autocomplete,
                            el.getAttribute('aria-label'),
                            el.getAttribute('placeholder')
                        ].join(' ').toLowerCase();
                        const codeLike =
                            attrs.includes('idv') ||
                            attrs.includes('one-time-code') ||
                            attrs.includes('verification') ||
                            attrs.includes('security code') ||
                            attrs.includes('enter code') ||
                            attrs.includes('code') ||
                            attrs.includes('pin') ||
                            attrs.includes('验证码');
                        const phoneLike =
                            !codeLike &&
                            (
                                el.id === 'phoneNumberId' ||
                                autocomplete === 'tel' ||
                                attrs.includes('phone') ||
                                attrs.includes('mobile') ||
                                attrs.includes('电话') ||
                                attrs.includes('手機') ||
                                attrs.includes('số điện thoại')
                            );
                        const totpLike = attrs.includes('totp') || el.id === 'totpPin';
                        return !phoneLike && !totpLike;
                    });

                    const explicitCodeInput = nonPhoneInputs.some((el) => {
                        const attrs = [
                            el.type,
                            el.name,
                            el.id,
                            el.autocomplete,
                            el.getAttribute('aria-label'),
                            el.getAttribute('placeholder')
                        ].join(' ').toLowerCase();
                        return (
                            attrs.includes('idvpin') ||
                            attrs.includes('one-time-code') ||
                            attrs.includes('verification') ||
                            attrs.includes('security code') ||
                            attrs.includes('enter code') ||
                            attrs.includes('code') ||
                            attrs.includes('pin') ||
                            attrs.includes('验证码')
                        );
                    });
                    if (explicitCodeInput) return true;
                    if (!hasCodeText) return false;

                    return nonPhoneInputs.some((el) => {
                        const type = String(el.type || '').toLowerCase();
                        return ['tel', 'text', 'number'].includes(type || 'text');
                    });
                }""",
                has_code_text,
            )
        )
    except Exception:
        has_code_input = False

    return bool(has_code_text and has_code_input)


def wait_for_phone_verification_code_input(page, timeout_seconds: int = 90) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if has_phone_verification_code_sent_prompt(page):
            return True
        if has_phone_verification_code_input(page):
            return True
        page.wait_for_timeout(1000)
    return False


def fill_phone_verification_code_input(page, code: str, *, fill_first: FillFirst) -> str:
    selector = fill_first(page, PHONE_CODE_INPUT_SELECTORS, code, 20000)
    if selector:
        return selector

    try:
        return str(
            page.evaluate(
                """(code) => {
                    const visibleInputs = Array.from(document.querySelectorAll('input'))
                        .filter((el) => {
                            const rect = el.getBoundingClientRect();
                            const type = String(el.type || '').toLowerCase();
                            return Boolean(rect.width && rect.height) &&
                                type !== 'hidden' &&
                                type !== 'password';
                        });

                    const isCodeInput = (el) => {
                        const autocomplete = String(el.autocomplete || '').toLowerCase();
                        const attrs = [
                            el.type,
                            el.name,
                            el.id,
                            autocomplete,
                            el.getAttribute('aria-label'),
                            el.getAttribute('placeholder')
                        ].join(' ').toLowerCase();
                        if (attrs.includes('totp') || el.id === 'totpPin') return false;
                        if (el.id === 'phoneNumberId') return false;
                        return (
                            attrs.includes('idv') ||
                            attrs.includes('one-time-code') ||
                            attrs.includes('verification') ||
                            attrs.includes('security code') ||
                            attrs.includes('enter code') ||
                            attrs.includes('code') ||
                            attrs.includes('pin') ||
                            attrs.includes('验证码')
                        );
                    };

                    const fill = (el, label) => {
                        el.scrollIntoView({ block: 'center', inline: 'center' });
                        el.focus();
                        const proto = Object.getPrototypeOf(el);
                        const descriptor = Object.getOwnPropertyDescriptor(proto, 'value');
                        if (descriptor && descriptor.set) {
                            descriptor.set.call(el, code);
                        } else {
                            el.value = code;
                        }
                        el.dispatchEvent(new Event('input', { bubbles: true }));
                        el.dispatchEvent(new Event('change', { bubbles: true }));
                        el.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: code.slice(-1) || '0' }));
                        return label;
                    };

                    for (const el of visibleInputs) {
                        if (!isCodeInput(el)) continue;
                        const label = [
                            el.type,
                            el.name,
                            el.id,
                            el.autocomplete,
                            el.getAttribute('aria-label'),
                            el.getAttribute('placeholder')
                        ].filter(Boolean).join('/');
                        return fill(el, label || 'code input');
                    }
                    return '';
                }""",
                code,
            )
        )
    except Exception:
        return ""


def refresh_phone_verification_code_input_events(page, code: str) -> bool:
    try:
        return bool(
            page.evaluate(
                """(code) => {
                    const selectors = [
                        "#idvPin",
                        "#idvAnyPhonePin",
                        "input[name='idvPin']",
                        "input[name='pin']",
                        "input[autocomplete='one-time-code']",
                        "input[id*='idv' i]",
                        "input[id*='pin' i]",
                        "input[name*='pin' i]",
                        "input[name*='code' i]",
                        "input[id*='code' i]",
                        "input[aria-label*='code' i]",
                        "input[placeholder*='code' i]"
                    ];
                    let input = null;
                    for (const selector of selectors) {
                        input = document.querySelector(selector);
                        if (input) break;
                    }
                    if (!input) return false;

                    input.focus();
                    const proto = Object.getPrototypeOf(input);
                    const descriptor = Object.getOwnPropertyDescriptor(proto, 'value');
                    if (descriptor && descriptor.set) {
                        descriptor.set.call(input, code);
                    } else {
                        input.value = code;
                    }
                    input.dispatchEvent(new Event('input', { bubbles: true }));
                    input.dispatchEvent(new Event('change', { bubbles: true }));
                    input.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: code.slice(-1) || '0' }));
                    input.blur();
                    input.focus();
                    return true;
                }""",
                code,
            )
        )
    except Exception:
        return False


def click_phone_verification_code_next(
    page,
    *,
    click_first_visible: ClickFirstVisible,
    click_validation_action: ClickValidationAction,
    emit_progress: EmitProgress,
    progress_logger: ProgressLogger | None = None,
) -> bool:
    clicked_selector = click_first_visible(page, PHONE_CODE_NEXT_SELECTORS, 200, 800)
    if clicked_selector:
        emit_progress(f"手机号验证码下一步已点击，按钮: {clicked_selector}", "info", progress_logger)
        return True

    if click_validation_action(page, PHONE_CODE_NEXT_TEXTS, progress_logger):
        return True

    try:
        page.locator(
            "#idvAnyPhonePin, #idvPin, input[name='pin'], input[name='idvPin'], input[autocomplete='one-time-code']"
        ).first.press("Enter", timeout=1500)
        emit_progress("已在验证码输入框按 Enter 触发下一步", "info", progress_logger)
        return True
    except Exception:
        return False


def wait_after_phone_verification_code_submit(
    page,
    *,
    page_success: PageStatusCheck,
    page_has_phone_rate_limit: PageStatusCheck,
    page_has_qr_code: PageStatusCheck,
    page_has_code_input: PageStatusCheck,
    timeout_seconds: int = 8,
) -> str:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if page_success(page):
            return "success"
        if page_has_phone_rate_limit(page):
            return "phone_rate_limited"
        if page_has_qr_code(page):
            return "qr_required"
        if not page_has_code_input(page):
            return "submitted"
        page.wait_for_timeout(400)
    return "code_next_not_triggered"


def submit_phone_verification_code_page(
    page,
    code: str,
    *,
    fill_first: FillFirst,
    click_first_visible: ClickFirstVisible,
    click_validation_action: ClickValidationAction,
    page_success: PageStatusCheck,
    page_has_phone_rate_limit: PageStatusCheck,
    page_has_qr_code: PageStatusCheck,
    diagnostic_snapshot: DiagnosticSnapshot,
    emit_progress: EmitProgress,
    progress_logger: ProgressLogger | None = None,
) -> str:
    code = str(code or "").strip()
    if not code:
        return "code_empty"

    emit_progress("正在填充手机号验证码", "info", progress_logger)
    selector = fill_phone_verification_code_input(page, code, fill_first=fill_first)
    if selector:
        emit_progress(f"手机号验证码已填充，输入框: {selector}", "info", progress_logger)
    else:
        emit_progress(
            f"未找到可填充的手机号验证码输入框；诊断: {diagnostic_snapshot(page)}",
            "warning",
            progress_logger,
        )
        return "code_input_not_found"

    refresh_phone_verification_code_input_events(page, code)

    submit_status = "code_next_not_triggered"
    for attempt in range(1, 3):
        if not click_phone_verification_code_next(
            page,
            click_first_visible=click_first_visible,
            click_validation_action=click_validation_action,
            emit_progress=emit_progress,
            progress_logger=progress_logger,
        ):
            break

        submit_status = wait_after_phone_verification_code_submit(
            page,
            page_success=page_success,
            page_has_phone_rate_limit=page_has_phone_rate_limit,
            page_has_qr_code=page_has_qr_code,
            page_has_code_input=has_phone_verification_code_input,
            timeout_seconds=8,
        )
        if submit_status in {"submitted", "success", "qr_required", "phone_rate_limited"}:
            break

        if attempt < 2 and submit_status == "code_next_not_triggered":
            emit_progress("验证码下一步点击后仍停留在验证码输入页，正在重试提交", "warning", progress_logger)
            refresh_phone_verification_code_input_events(page, code)
            continue
        break

    if submit_status == "code_next_not_triggered":
        emit_progress(
            f"手机号验证码已填充，但未能触发下一步；诊断: {diagnostic_snapshot(page)}",
            "warning",
            progress_logger,
        )
        return "code_next_not_triggered"
    if submit_status == "phone_rate_limited":
        emit_progress("当前手机号异常：该手机号已被用于验证过多次", "warning", progress_logger)
        return "phone_rate_limited"
    if submit_status == "success":
        emit_progress("手机号验证码提交后页面已完成验证", "info", progress_logger)
    elif submit_status == "qr_required":
        emit_progress("手机号验证码提交后出现二维码", "warning", progress_logger)

    return submit_status
