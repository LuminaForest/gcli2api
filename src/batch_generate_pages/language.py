"""Language helpers for Google verification pages."""

import re
from collections.abc import Callable
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from log import log


ProgressLogger = Callable[[str, str], None]

_GOOGLE_ENGLISH_PARAMS = {"hl": "en", "gl": "US"}
_ENGLISH_TEXT_MARKERS = (
    "sign in with google",
    "verify it’s you",
    "verify it's you",
    "two-step verification",
    "2-step verification",
    "get a verification code from the",
    "google authenticator",
    "verify your phone number",
    "enter a phone number",
    "try another way",
    "confirm you're not a robot",
    "confirm you’re not a robot",
    "i'm not a robot",
    "i’m not a robot",
)


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


def _with_query_params(url: str, values: dict[str, str]) -> str:
    parsed = urlparse(str(url or ""))
    if not parsed.scheme or not parsed.netloc:
        return url

    query = parse_qs(parsed.query, keep_blank_values=True)
    for key, value in values.items():
        query[key] = [str(value)]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def _with_english_locale(url: str) -> str:
    return _with_query_params(url, _GOOGLE_ENGLISH_PARAMS)


def _is_google_page_url(url: str) -> bool:
    hostname = (urlparse(str(url or "")).hostname or "").lower()
    return hostname == "google.com" or hostname.endswith(".google.com")


def _page_language_state(page) -> tuple[str, str]:
    try:
        state = page.evaluate(
            """() => {
                const normalize = (value) => String(value || '').replace(/\\s+/g, ' ').trim();
                return {
                    lang: normalize(document.documentElement ? document.documentElement.lang : ''),
                    text: normalize(document.body ? document.body.innerText : '').slice(0, 2000)
                };
            }"""
        )
        if isinstance(state, dict):
            return str(state.get("lang") or ""), str(state.get("text") or "")
    except Exception:
        pass
    return "", ""


def _page_looks_english(page) -> bool:
    lang, text = _page_language_state(page)
    normalized_lang = str(lang or "").strip().lower()
    if normalized_lang.startswith("en"):
        return True

    normalized_text = re.sub(r"\s+", " ", str(text or "").lower()).strip()
    return any(marker in normalized_text for marker in _ENGLISH_TEXT_MARKERS)


def _set_google_english_cookie(page) -> None:
    try:
        page.context.add_cookies(
            [
                {
                    "name": "PREF",
                    "value": "hl=en&gl=US",
                    "domain": ".google.com",
                    "path": "/",
                    "secure": True,
                    "sameSite": "Lax",
                }
            ]
        )
    except Exception:
        pass


def _select_native_english_option(page) -> str:
    try:
        selected = page.evaluate(
            """() => {
                const visible = (el) => {
                    const rect = el.getBoundingClientRect();
                    const style = window.getComputedStyle(el);
                    return Boolean(rect.width && rect.height) &&
                        style.visibility !== 'hidden' &&
                        style.display !== 'none';
                };
                const options = Array.from(document.querySelectorAll('select option'));
                for (const option of options) {
                    const text = String(option.textContent || '').trim();
                    const value = String(option.value || '').trim();
                    if (!/english|\\ben\\b|hl=en/i.test(`${text} ${value}`)) continue;
                    const select = option.closest('select');
                    if (!select || !visible(select)) continue;
                    select.value = option.value;
                    select.dispatchEvent(new Event('input', { bubbles: true }));
                    select.dispatchEvent(new Event('change', { bubbles: true }));
                    return text || value;
                }
                return '';
            }"""
        )
    except Exception:
        selected = ""
    return str(selected or "").strip()


def _click_language_menu(page) -> str:
    try:
        clicked = page.evaluate(
            """() => {
                const normalize = (value) => String(value || '').replace(/\\s+/g, ' ').trim();
                const visible = (el) => {
                    const rect = el.getBoundingClientRect();
                    const style = window.getComputedStyle(el);
                    return Boolean(rect.width && rect.height) &&
                        style.visibility !== 'hidden' &&
                        style.display !== 'none';
                };
                const labelPattern = /language|lang|locale|语言|語言|言語|언어|ngôn ngữ|idioma|sprache|langue|язык/i;
                const elements = Array.from(document.querySelectorAll(
                    "button, [role='button'], [aria-haspopup], [jscontroller][jsaction], [tabindex='0']"
                ));
                const viewportHeight = window.innerHeight || document.documentElement.clientHeight || 0;
                const candidates = [];
                for (const el of elements) {
                    if (!visible(el)) continue;
                    const rect = el.getBoundingClientRect();
                    const text = normalize(
                        el.innerText ||
                        el.textContent ||
                        el.getAttribute('aria-label') ||
                        el.getAttribute('title')
                    );
                    const attrs = normalize([
                        el.id,
                        el.className,
                        el.getAttribute('aria-label'),
                        el.getAttribute('title'),
                        el.getAttribute('aria-haspopup')
                    ].filter(Boolean).join(' '));
                    const lowerText = text.toLowerCase();
                    const score =
                        (labelPattern.test(`${text} ${attrs}`) ? 5 : 0) +
                        (String(el.getAttribute('aria-haspopup') || '').toLowerCase().includes('listbox') ? 3 : 0) +
                        (rect.top > viewportHeight * 0.65 ? 2 : 0) +
                        (/\\(.+\\)/.test(text) && text.length <= 80 ? 1 : 0) +
                        (lowerText.includes('english') ? 1 : 0);
                    if (score <= 2) continue;
                    candidates.push({ el, text, score, top: rect.top });
                }
                candidates.sort((a, b) => b.score - a.score || b.top - a.top);
                const target = candidates[0];
                if (!target) return '';
                target.el.scrollIntoView({ block: 'center', inline: 'center' });
                target.el.click();
                return target.text || target.el.getAttribute('aria-label') || target.el.tagName.toLowerCase();
            }"""
        )
    except Exception:
        clicked = ""
    return str(clicked or "").strip()


def _click_english_option(page) -> str:
    selectors = [
        "text=English (United States)",
        "text=English",
        "[role='option']:has-text('English')",
        "[role='menuitem']:has-text('English')",
        "li:has-text('English')",
        "div:has-text('English (United States)')",
    ]
    for selector in selectors:
        locator = page.locator(selector).first
        try:
            if locator.count() < 1:
                continue
            locator.click(timeout=1500)
            return selector
        except Exception:
            continue
    return ""


def _reload_with_english_locale(page) -> bool:
    current_url = str(getattr(page, "url", "") or "")
    if not _is_google_page_url(current_url):
        return False

    english_url = _with_english_locale(current_url)
    try:
        if english_url == current_url:
            page.reload(wait_until="domcontentloaded", timeout=30000)
        else:
            page.goto(english_url, wait_until="domcontentloaded", timeout=30000)
        return True
    except Exception:
        return False


def ensure_english_verification_page(
    page,
    *,
    label: str = "验证页面",
    progress_logger: ProgressLogger | None = None,
) -> bool:
    """Switch a Google verification page to English before page-specific automation."""
    current_url = str(getattr(page, "url", "") or "")
    if not _is_google_page_url(current_url):
        return False
    if _page_looks_english(page):
        return False

    parsed = urlparse(current_url)
    page_key = f"{label}:{parsed.netloc}{parsed.path}"
    checked_keys = getattr(page, "_batch_english_verification_checked_keys", None)
    if not isinstance(checked_keys, set):
        checked_keys = set()
        setattr(page, "_batch_english_verification_checked_keys", checked_keys)
    if page_key in checked_keys:
        return False
    checked_keys.add(page_key)

    _emit_progress(f"{label}不是英文页面，正在尝试切换到 English", progress_logger=progress_logger)
    _set_google_english_cookie(page)

    selected = _select_native_english_option(page)
    if selected:
        _emit_progress(f"{label}已通过语言下拉框选择 English: {selected}", progress_logger=progress_logger)
        page.wait_for_timeout(1500)
        if _page_looks_english(page):
            return True

    opened = _click_language_menu(page)
    if opened:
        page.wait_for_timeout(500)
        clicked = _click_english_option(page)
        if clicked:
            _emit_progress(f"{label}已点击 English 语言选项: {clicked}", progress_logger=progress_logger)
            page.wait_for_timeout(2000)
            if _page_looks_english(page):
                return True

    if _reload_with_english_locale(page):
        _emit_progress(f"{label}已使用 hl=en 重新加载英文页面", progress_logger=progress_logger)
        page.wait_for_timeout(1000)
        return True

    _emit_progress(f"{label}切换 English 失败，将继续当前页面", level="warning", progress_logger=progress_logger)
    return False
