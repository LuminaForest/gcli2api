"""Two-factor verification method selection for batch generation."""

from collections.abc import Callable

from src.batch_generate_pages.validation import _validation_page_has_phone_number_entry_prompt


ProgressLogger = Callable[[str, str], None]
EmitProgress = Callable[[str, str, ProgressLogger | None], None]

TWO_STEP_PROMPT_MARKERS = (
    "choose how you want to sign in",
)
GOOGLE_AUTHENTICATOR_APP_OPTION_TEXT = "get a verification code from the google authenticator app"


def _page_text(page, timeout: int = 3000) -> str:
    try:
        return str(page.locator("body").inner_text(timeout=timeout) or "")
    except Exception:
        return ""


def _page_has_two_step_verification_prompt(page) -> bool:
    if _validation_page_has_phone_number_entry_prompt(page):
        return False

    page_text = _page_text(page).lower()
    return any(marker in page_text for marker in TWO_STEP_PROMPT_MARKERS)


def select_google_authenticator_app_option_if_present(
    page,
    *,
    emit_progress: EmitProgress,
    progress_logger: ProgressLogger | None = None,
) -> bool:
    if not _page_has_two_step_verification_prompt(page):
        return False

    emit_progress(
        "检测到2FA方式选择页，正在选择 Get a verification code from the Google Authenticator app",
        "info",
        progress_logger,
    )

    selectors = [
        "button:has-text('Get a verification code from the Google Authenticator app')",
        "div[role='button']:has-text('Get a verification code from the Google Authenticator app')",
        "[role='link']:has-text('Get a verification code from the Google Authenticator app')",
        "a:has-text('Get a verification code from the Google Authenticator app')",
        "[tabindex='0']:has-text('Get a verification code from the Google Authenticator app')",
        "text=Get a verification code from the Google Authenticator app",
    ]
    for selector in selectors:
        locator = page.locator(selector).first
        try:
            if locator.count() < 1:
                continue
            locator.scroll_into_view_if_needed(timeout=500)
            locator.click(timeout=1500)
            emit_progress(f"2FA方式选择页已点击 Google Authenticator app 选项: {selector}", "info", progress_logger)
            return True
        except Exception:
            continue

    try:
        clicked_text = page.evaluate(
            """(targetText) => {
                const normalize = (value) => String(value || '').replace(/\\s+/g, ' ').trim();
                const target = normalize(targetText).toLowerCase();
                const visible = (el) => {
                    const rect = el.getBoundingClientRect();
                    const style = window.getComputedStyle(el);
                    return Boolean(rect.width && rect.height) &&
                        style.visibility !== 'hidden' &&
                        style.display !== 'none' &&
                        style.opacity !== '0';
                };
                const interactive = Array.from(document.querySelectorAll(
                    [
                        "button",
                        "[role='button']",
                        "[role='link']",
                        "a",
                        "input[type='button']",
                        "input[type='submit']",
                        "[jscontroller][jsaction]",
                        "[tabindex='0']"
                    ].join(",")
                ));
                const textOf = (el) => normalize(
                    el.innerText ||
                    el.textContent ||
                    el.value ||
                    el.getAttribute('aria-label') ||
                    el.getAttribute('title')
                );
                for (const el of interactive) {
                    if (!visible(el)) continue;
                    const text = textOf(el);
                    if (!text) continue;
                    if (text.toLowerCase().includes(target)) {
                        el.scrollIntoView({ block: 'center', inline: 'center' });
                        el.click();
                        return text;
                    }
                }
                return '';
            }""",
            GOOGLE_AUTHENTICATOR_APP_OPTION_TEXT,
        )
    except Exception:
        clicked_text = ""

    if clicked_text:
        emit_progress(f"2FA方式选择页已点击 Google Authenticator app 选项: {clicked_text}", "info", progress_logger)
        return True

    emit_progress(
        "2FA方式选择页未找到 Get a verification code from the Google Authenticator app 选项",
        "warning",
        progress_logger,
    )
    return False
