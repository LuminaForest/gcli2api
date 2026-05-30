"""Phone number entry page handling for Google verification."""

import re
from collections.abc import Callable


ProgressLogger = Callable[[str, str], None]
EmitProgress = Callable[[str, str, ProgressLogger | None], None]
FillFirst = Callable[[object, list[str], str, int], str | None]
ClickFirstVisible = Callable[[object, list[str], int, int], str | None]
ClickValidationAction = Callable[[object, list[str], ProgressLogger | None], bool]
WaitForCodeInput = Callable[[object, int], bool]
PageStatusCheck = Callable[[object], bool]
DiagnosticSnapshot = Callable[[object], str]
RedactQueryValue = Callable[[str, set[str]], str]

PHONE_NUMBER_ENTRY_PROMPT = "enter a phone number to get a text message with a verification code"
PHONE_NUMBER_UNUSABLE_STATUS = "phone_number_unusable"
PHONE_NUMBER_UNUSABLE_MESSAGE = "This phone number can't be used for verification"
PHONE_NUMBER_UNUSABLE_MARKERS = (
    "this phone number can't be used for verification",
    "this phone number cannot be used for verification",
)
PHONE_INPUT_SELECTORS = [
    "#phoneNumberId",
    "input[name='phoneNumber']",
    "input[autocomplete='tel']:not([id*='code' i]):not([name*='code' i]):not([id*='pin' i]):not([name*='pin' i]):not([id*='idv' i]):not([name*='idv' i]):not(#totpPin)",
    "input[type='tel']:not([autocomplete='one-time-code']):not([id*='code' i]):not([name*='code' i]):not([id*='pin' i]):not([name*='pin' i]):not([id*='idv' i]):not([name*='idv' i]):not(#totpPin)",
    "input[aria-label*='phone' i]:not([id*='code' i]):not([name*='code' i]):not([id*='pin' i]):not([name*='pin' i]):not([id*='idv' i]):not([name*='idv' i])",
    "input[placeholder*='phone' i]:not([id*='code' i]):not([name*='code' i]):not([id*='pin' i]):not([name*='pin' i]):not([id*='idv' i]):not([name*='idv' i])",
]
PHONE_NEXT_TEXTS = [
    "Next",
    "Continue",
    "Send",
    "Get code",
    "Send code",
    "下一步",
    "继续",
    "发送",
    "获取验证码",
    "发送验证码",
    "Tiếp tục",
    "Gửi",
]
PHONE_NEXT_SELECTORS = [
    "#idvPreregisteredPhoneNext button",
    "#idvPreregisteredPhoneNext",
    "#next button",
    "#next",
    "button:has-text('Next')",
    "div[role='button']:has-text('Next')",
    "button:has-text('Continue')",
    "div[role='button']:has-text('Continue')",
    "button:has-text('Send')",
    "div[role='button']:has-text('Send')",
    "button:has-text('Get code')",
    "div[role='button']:has-text('Get code')",
    "button:has-text('下一步')",
    "div[role='button']:has-text('下一步')",
    "button:has-text('继续')",
    "div[role='button']:has-text('继续')",
    "button:has-text('发送')",
    "div[role='button']:has-text('发送')",
    "button:has-text('Tiếp tục')",
    "div[role='button']:has-text('Tiếp tục')",
    "button:has-text('Gửi')",
    "div[role='button']:has-text('Gửi')",
]


def _page_body_text(page, timeout: int = 2000) -> str:
    try:
        return str(page.locator("body").inner_text(timeout=timeout) or "")
    except Exception:
        return ""


def has_phone_number_entry_prompt(page) -> bool:
    text = re.sub(r"\s+", " ", _page_body_text(page).lower()).strip()
    return (
        PHONE_NUMBER_ENTRY_PROMPT in text
        or (
            "enter a phone number" in text
            and "text message" in text
            and "verification code" in text
        )
    )


def has_phone_number_unusable_message(page) -> bool:
    text = _page_body_text(page).lower().replace("’", "'")
    text = re.sub(r"\s+", " ", text).strip()
    return any(marker in text for marker in PHONE_NUMBER_UNUSABLE_MARKERS)


def has_phone_number_entry_input(page) -> bool:
    if not has_phone_number_entry_prompt(page):
        return False

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


def fill_phone_number_entry_input(page, phone: str, *, fill_first: FillFirst) -> str:
    selector = fill_first(page, PHONE_INPUT_SELECTORS, phone, 8000)
    if selector:
        return selector

    try:
        return str(
            page.evaluate(
                """(phone) => {
                    const inputs = Array.from(document.querySelectorAll('input'));
                    const usable = inputs.filter((el) => {
                        const rect = el.getBoundingClientRect();
                        const type = String(el.type || '').toLowerCase();
                        return Boolean(rect.width && rect.height) &&
                            type !== 'hidden' &&
                            type !== 'password' &&
                            type !== 'button' &&
                            type !== 'submit' &&
                            type !== 'checkbox' &&
                            type !== 'radio' &&
                            !el.disabled &&
                            !el.readOnly;
                    });
                    if (!usable.length) return '';

                    const fill = (el, label) => {
                        el.scrollIntoView({ block: 'center', inline: 'center' });
                        el.focus();
                        const proto = Object.getPrototypeOf(el);
                        const descriptor = Object.getOwnPropertyDescriptor(proto, 'value');
                        if (descriptor && descriptor.set) {
                            descriptor.set.call(el, phone);
                        } else {
                            el.value = phone;
                        }
                        el.dispatchEvent(new Event('input', { bubbles: true }));
                        el.dispatchEvent(new Event('change', { bubbles: true }));
                        el.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: phone.slice(-1) || '0' }));
                        return label || 'input';
                    };

                    const sorted = [...usable].sort((a, b) => {
                        const ar = a.getBoundingClientRect();
                        const br = b.getBoundingClientRect();
                        const aScore = (a === document.activeElement ? 1000000 : 0) + ar.width * ar.height;
                        const bScore = (b === document.activeElement ? 1000000 : 0) + br.width * br.height;
                        return bScore - aScore;
                    });
                    const target = sorted[0];
                    const attrs = [
                        target.type,
                        target.name,
                        target.id,
                        target.autocomplete,
                        target.getAttribute('aria-label'),
                        target.getAttribute('placeholder')
                    ].filter(Boolean).join('/');
                    return fill(target, `phone entry prompt input ${attrs}`.trim());
                }""",
                phone,
            )
        )
    except Exception:
        return ""


def refresh_phone_number_entry_input_events(page, phone: str) -> bool:
    try:
        return bool(
            page.evaluate(
                """(phone) => {
                    const selectors = [
                        "#phoneNumberId",
                        "input[name='phoneNumber']",
                        "input[autocomplete='tel']",
                        "input[type='tel']:not(#totpPin)",
                        "input[aria-label*='phone' i]",
                        "input[placeholder*='phone' i]"
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
                        descriptor.set.call(input, phone);
                    } else {
                        input.value = phone;
                    }
                    input.dispatchEvent(new Event('input', { bubbles: true }));
                    input.dispatchEvent(new Event('change', { bubbles: true }));
                    input.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true, key: '0' }));
                    input.blur();
                    input.focus();
                    return true;
                }""",
                phone,
            )
        )
    except Exception:
        return False


def click_phone_number_entry_next(
    page,
    *,
    click_first_visible: ClickFirstVisible,
    click_validation_action: ClickValidationAction,
    emit_progress: EmitProgress,
    progress_logger: ProgressLogger | None = None,
) -> bool:
    clicked_selector = click_first_visible(page, PHONE_NEXT_SELECTORS, 200, 800)
    if clicked_selector:
        emit_progress(f"手机号下一步已点击，按钮: {clicked_selector}", "info", progress_logger)
        return True

    if click_validation_action(page, PHONE_NEXT_TEXTS, progress_logger):
        return True

    emit_progress(
        "手机号已填充，但未找到可点击的 Next/发送验证码按钮，尝试按 Enter 提交",
        "warning",
        progress_logger,
    )
    try:
        page.locator("#phoneNumberId, input[name='phoneNumber'], input[autocomplete='tel']").first.press(
            "Enter",
            timeout=3000,
        )
        emit_progress("已在手机号输入框按 Enter 触发下一步", "info", progress_logger)
        return True
    except Exception:
        return False


def wait_after_phone_number_entry_next(
    page,
    *,
    wait_for_code_input: WaitForCodeInput,
    page_success: PageStatusCheck,
    page_has_phone_rate_limit: PageStatusCheck,
    page_has_qr_code: PageStatusCheck,
    timeout_seconds: int = 12,
) -> str:
    import time

    deadline = time.monotonic() + timeout_seconds
    try:
        page.wait_for_timeout(3000)
    except Exception:
        time.sleep(3)

    if has_phone_number_unusable_message(page):
        return PHONE_NUMBER_UNUSABLE_STATUS
    if page_success(page):
        return "success"
    if page_has_phone_rate_limit(page):
        return "phone_rate_limited"
    if page_has_qr_code(page):
        return "qr_required"
    if wait_for_code_input(page, 1):
        return "code_input"

    while time.monotonic() < deadline:
        if has_phone_number_unusable_message(page):
            return PHONE_NUMBER_UNUSABLE_STATUS
        if page_success(page):
            return "success"
        if page_has_phone_rate_limit(page):
            return "phone_rate_limited"
        if page_has_qr_code(page):
            return "qr_required"
        if wait_for_code_input(page, 1):
            return "code_input"
        page.wait_for_timeout(500)

    if has_phone_number_entry_input(page):
        return "phone_next_not_triggered"
    return "code_input_timeout"


def submit_phone_number_entry_page(
    page,
    phone: str,
    *,
    fill_first: FillFirst,
    click_first_visible: ClickFirstVisible,
    click_validation_action: ClickValidationAction,
    wait_for_code_input: WaitForCodeInput,
    page_success: PageStatusCheck,
    page_has_phone_rate_limit: PageStatusCheck,
    page_has_qr_code: PageStatusCheck,
    diagnostic_snapshot: DiagnosticSnapshot,
    redact_query_value: RedactQueryValue,
    emit_progress: EmitProgress,
    progress_logger: ProgressLogger | None = None,
) -> str:
    phone = str(phone or "").strip()
    if not phone:
        emit_progress(
            "账号验证页面需要绑定手机号，但上传文件未提供手机号",
            "warning",
            progress_logger,
        )
        return "phone_required_but_not_submitted"

    if page_has_qr_code(page):
        return "qr_required"

    if not has_phone_number_entry_input(page):
        emit_progress(
            f"等待手机号输入页超时；诊断: {diagnostic_snapshot(page)}",
            "warning",
            progress_logger,
        )
        return "phone_input_timeout"

    emit_progress("已进入手机号输入页，正在填充手机号", "info", progress_logger)
    filled = fill_phone_number_entry_input(page, phone, fill_first=fill_first)
    if not filled:
        emit_progress(
            f"未找到可填充的手机号输入框；诊断: {diagnostic_snapshot(page)}",
            "warning",
            progress_logger,
        )
        return "phone_input_not_found"

    emit_progress(f"手机号已填充，输入框: {filled}", "info", progress_logger)
    refresh_phone_number_entry_input_events(page, phone)

    before_url = str(getattr(page, "url", "") or "")
    final_status = "phone_next_not_triggered"
    for attempt in range(1, 4):
        if not click_phone_number_entry_next(
            page,
            click_first_visible=click_first_visible,
            click_validation_action=click_validation_action,
            emit_progress=emit_progress,
            progress_logger=progress_logger,
        ):
            emit_progress("手机号已填充，但未能触发下一步", "warning", progress_logger)
            final_status = "phone_next_not_triggered"
            break

        emit_progress("手机号下一步已点击，正在确认是否进入验证码输入页", "info", progress_logger)
        final_status = wait_after_phone_number_entry_next(
            page,
            wait_for_code_input=wait_for_code_input,
            page_success=page_success,
            page_has_phone_rate_limit=page_has_phone_rate_limit,
            page_has_qr_code=page_has_qr_code,
            timeout_seconds=12,
        )
        if final_status in {"code_input", "success", "qr_required"}:
            break

        if attempt < 3 and final_status == "phone_next_not_triggered":
            emit_progress(
                "手机号下一步点击后仍停留在手机号输入页，正在重新填充并重试",
                "warning",
                progress_logger,
            )
            refresh_phone_number_entry_input_events(page, phone)
            continue

        break

    after_url = str(getattr(page, "url", "") or "")
    if after_url != before_url:
        emit_progress(
            f"手机号提交后页面地址已变化: {redact_query_value(after_url, {'code'})}",
            "info",
            progress_logger,
        )
    emit_progress(f"手机号提交后页面诊断: {diagnostic_snapshot(page)}", "info", progress_logger)

    if final_status == "phone_rate_limited":
        emit_progress("当前手机号异常：该手机号已被用于验证过多次", "warning", progress_logger)
        return "phone_rate_limited"
    if final_status == PHONE_NUMBER_UNUSABLE_STATUS:
        emit_progress(f"当前手机号异常：{PHONE_NUMBER_UNUSABLE_MESSAGE}", "error", progress_logger)
        return PHONE_NUMBER_UNUSABLE_STATUS
    if page_has_qr_code(page):
        return "qr_required"
    if final_status == "code_input":
        emit_progress("已确认进入手机号验证码输入页", "info", progress_logger)
    elif final_status == "phone_next_not_triggered":
        emit_progress("手机号下一步未生效，仍停留在手机号输入页，未获取短信验证码", "warning", progress_logger)
    return final_status
