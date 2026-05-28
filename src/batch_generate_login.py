"""
Browser automation helpers for batch credential generation.
"""

import asyncio
import base64
import hashlib
import hmac
import html
import json
import os
import re
import struct
import threading
import time
from collections.abc import Callable
from urllib.parse import parse_qs, quote, unquote, urlencode, urljoin, urlparse, urlunparse

import httpx

from log import log
from src.utils import ANTIGRAVITY_USER_AGENT, GEMINICLI_USER_AGENT


ProgressLogger = Callable[[str, str], None]

_2FA_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"
    )
}
_2FA_BYPASS_URL = (
    "https://2fa.run/a20be899_96a6_40b2_88ba_32f1f75f1552_yanzheng_huadong.php"
    "?type=ad82060c2e67cc7e2cc47552a4fc1242"
    "&key=aaf92b1b25ded7c7de771b1d276f724e"
    "&value=f6ca1876c31e17a320fc3785ec6f05e6"
)
_GOOGLE_ENGLISH_PARAMS = {"hl": "en", "gl": "US", "lr": "lang_en"}
_PHONE_CODE_PATTERN = re.compile(r"\bG\s*[-:：]\s*([0-9A-Za-z]{4,12})\b", re.IGNORECASE)
_PHONE_RATE_LIMIT_SENTINEL = "__PHONE_RATE_LIMITED__"


def _normalize_credential_mode(mode: str) -> str:
    return "antigravity" if str(mode or "").strip() == "antigravity" else "geminicli"


def _credential_mode_label(mode: str) -> str:
    return "Antigravity" if _normalize_credential_mode(mode) == "antigravity" else "GCLI"


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


def _summarize_http_response_body(response_text: str, response_data: dict) -> str:
    if response_text:
        return response_text[:2000]
    if response_data:
        try:
            return json.dumps(response_data, ensure_ascii=False)[:2000]
        except Exception:
            return str(response_data)[:2000]
    return ""


def ensure_browser_automation_available() -> None:
    try:
        import patchright.sync_api  # noqa: F401
    except ImportError as exc:
        raise RuntimeError("缺少 patchright 依赖，请先安装 patchright；容器内浏览器模式还需要执行 patchright install chrome") from exc


def _batch_generate_chrome_cdp_url() -> str:
    return str(
        os.getenv("BATCH_GENERATE_CHROME_CDP_URL")
        or os.getenv("CHROME_CDP_URL")
        or ""
    ).strip()


def _build_2fa_url(two_fa_key: str) -> str:
    value = str(two_fa_key or "").strip()
    if not value:
        return ""
    if value.startswith("http://") or value.startswith("https://"):
        return value
    return f"https://2fa.run/2fa/#{quote(value, safe='')}"


def _extract_2fa_secret(two_fa_key: str) -> str:
    value = str(two_fa_key or "").strip()
    if not value:
        return ""

    parsed = urlparse(value)
    if parsed.scheme == "otpauth":
        secret = parse_qs(parsed.query).get("secret", [""])[0]
        return unquote(secret).strip()

    if parsed.scheme in {"http", "https"}:
        query = parse_qs(parsed.query)
        for key in ("secret", "key", "otp"):
            secret = query.get(key, [""])[0]
            if secret:
                return unquote(secret).strip()

        if parsed.fragment:
            fragment = unquote(parsed.fragment).strip()
            fragment_query = parse_qs(fragment.lstrip("?"))
            for key in ("secret", "key", "otp"):
                secret = fragment_query.get(key, [""])[0]
                if secret:
                    return unquote(secret).strip()
            return fragment.split("&", 1)[0].strip()

        path_marker = "/2fa/"
        if path_marker in parsed.path:
            return unquote(parsed.path.split(path_marker, 1)[1]).strip("/")

        return ""

    return value


def _normalize_totp_secret(secret: str) -> str:
    return re.sub(r"[\s-]+", "", str(secret or "")).upper()


def _generate_totp_code(secret: str, digits: int = 6, period: int = 30) -> str:
    normalized = _normalize_totp_secret(secret)
    if not normalized:
        return ""

    padding = "=" * ((8 - len(normalized) % 8) % 8)
    key = base64.b32decode(normalized + padding, casefold=True)
    counter = int(time.time()) // period
    digest = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % (10**digits)).zfill(digits)


def _build_2fa_request_urls(two_fa_key: str) -> list[str]:
    urls = []
    display_url = _build_2fa_url(two_fa_key)
    if display_url:
        urls.append(display_url)

    secret = _extract_2fa_secret(two_fa_key)
    if secret:
        urls.append(f"https://2fa.run/2fa/{quote(secret, safe='')}")

    deduped = []
    for url in urls:
        if url and url not in deduped:
            deduped.append(url)
    return deduped


def _totp_submission_cache_key(page) -> str:
    current_url = str(getattr(page, "url", "") or "")
    parsed = urlparse(current_url)
    return f"{parsed.hostname or ''}{parsed.path or ''}"


def _was_totp_submitted_recently(page, cooldown_seconds: int = 8) -> bool:
    last_submission = getattr(_submit_totp_if_needed, "_last_submission", None)
    if not isinstance(last_submission, dict):
        return False

    current_key = _totp_submission_cache_key(page)
    last_key = str(last_submission.get("key") or "")
    last_at = float(last_submission.get("at") or 0.0)
    if not current_key or current_key != last_key:
        return False
    return (time.monotonic() - last_at) < cooldown_seconds


def _mark_totp_submitted(page) -> None:
    setattr(
        _submit_totp_if_needed,
        "_last_submission",
        {"key": _totp_submission_cache_key(page), "at": time.monotonic()},
    )


def _redact_2fa_url(url: str) -> str:
    parsed = urlparse(str(url or ""))
    if not parsed.scheme:
        return _mask_value(url)

    if parsed.fragment:
        return url.replace(parsed.fragment, _mask_value(parsed.fragment))

    path_marker = "/2fa/"
    if path_marker in parsed.path:
        secret = parsed.path.split(path_marker, 1)[1].strip("/")
        if secret:
            return url.replace(secret, _mask_value(secret))

    return url


def _run_async(coro):
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)

    result = {}

    def run_in_thread():
        try:
            result["value"] = asyncio.run(coro)
        except Exception as exc:
            result["error"] = exc

    thread = threading.Thread(target=run_in_thread, daemon=True)
    thread.start()
    thread.join()

    if "error" in result:
        raise result["error"]
    return result.get("value")


def _redact_query_value(url: str, keys: set[str]) -> str:
    parsed = urlparse(str(url or ""))
    if not parsed.query:
        return url

    query = parse_qs(parsed.query, keep_blank_values=True)
    for key in keys:
        if key in query:
            query[key] = [_mask_value(query[key][0])]

    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def _with_query_params(url: str, values: dict[str, str]) -> str:
    parsed = urlparse(str(url or ""))
    if not parsed.scheme or not parsed.netloc:
        return url

    query = parse_qs(parsed.query, keep_blank_values=True)
    for key, value in values.items():
        query[key] = [str(value)]
    return urlunparse(parsed._replace(query=urlencode(query, doseq=True)))


def _with_english_locale(url: str, extra_params: dict[str, str] | None = None) -> str:
    params = dict(_GOOGLE_ENGLISH_PARAMS)
    if extra_params:
        params.update(extra_params)
    return _with_query_params(url, params)


def _is_google_page_url(url: str) -> bool:
    hostname = (urlparse(str(url or "")).hostname or "").lower()
    return hostname == "google.com" or hostname.endswith(".google.com")


def _install_english_navigation_guard(context, progress_logger: ProgressLogger | None = None) -> None:
    try:
        context.add_cookies(
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
        _emit_progress("已设置Google英文语言Cookie", progress_logger=progress_logger)
    except Exception as exc:
        _emit_progress(
            f"设置Google英文语言Cookie失败: {exc}",
            level="warning",
            progress_logger=progress_logger,
        )

    def english_route(route):
        request = route.request
        url = request.url
        try:
            if (
                request.method.upper() == "GET"
                and request.resource_type == "document"
                and _is_google_page_url(url)
            ):
                english_url = _with_english_locale(url)
                if english_url != url:
                    route.continue_(url=english_url)
                    return
        except Exception:
            pass
        route.continue_()

    try:
        context.route("**/*", english_route)
        _emit_progress("已启用Google页面英文导航拦截", progress_logger=progress_logger)
    except Exception as exc:
        _emit_progress(
            f"启用英文导航拦截失败: {exc}",
            level="warning",
            progress_logger=progress_logger,
        )

    try:
        context.add_init_script(
            """() => {
                const defineGetter = (target, key, value) => {
                    try {
                        Object.defineProperty(target, key, {
                            get: () => value,
                            configurable: true
                        });
                    } catch (_) {}
                };

                defineGetter(navigator, 'language', 'en-US');
                defineGetter(navigator, 'languages', ['en-US', 'en']);
            }"""
        )
        _emit_progress("已固定浏览器navigator语言为 en-US", progress_logger=progress_logger)
    except Exception as exc:
        _emit_progress(
            f"固定navigator语言失败: {exc}",
            level="warning",
            progress_logger=progress_logger,
        )


def _goto_english(page, url: str, **kwargs) -> None:
    page.goto(_with_english_locale(url), **kwargs)


def _open_oauth_auth_url(page, auth_url: str, state: str, progress_logger: ProgressLogger | None = None) -> None:
    try:
        _goto_english(page, auth_url, wait_until="commit", timeout=30000)
        return
    except Exception as exc:
        current_url = str(getattr(page, "url", "") or "")
        if _parse_callback_code_from_url(current_url):
            _emit_progress(
                f"OAuth授权页已跳转到回调地址，将直接读取地址栏URL: {exc}",
                level="warning",
                progress_logger=progress_logger,
            )
            return

        _emit_progress(
            f"OAuth授权页 commit 等待失败，将用短超时继续打开并轮询地址栏: {exc}",
            level="warning",
            progress_logger=progress_logger,
        )

    try:
        _goto_english(page, auth_url, wait_until="domcontentloaded", timeout=3000)
    except Exception as exc:
        _emit_progress(
            f"OAuth授权页打开等待超时或被回调页中断，将继续检查地址栏: {exc}",
            level="warning",
            progress_logger=progress_logger,
        )


def _build_batch_proxy_kwargs(proxy_url: str, request_label: str) -> dict:
    proxy_url = str(proxy_url or "").strip()
    return {
        "proxy": proxy_url or None,
        "_proxy_log": {
            "mode": "geminicli",
            "credential": "batch_generate_cache",
            "request_label": request_label,
            "bound_proxy_name": "",
        },
    }


def _origin_base_url() -> str:
    return str(os.getenv("GCLI2API_BASE_URL") or "").strip().rstrip("/")


def _origin_panel_token() -> str:
    return str(os.getenv("GCLI2API_PANEL_TOKEN") or "").strip()


def _use_origin_callback_api() -> bool:
    return bool(_origin_base_url() and _origin_panel_token())


def _origin_auth_headers() -> dict[str, str]:
    panel_token = _origin_panel_token()
    if not panel_token:
        raise RuntimeError("未配置远程服务连接密码，无法将回调URL发送到远程服务")
    return {"Authorization": f"Bearer {panel_token}"}


def _parse_callback_code_from_url(callback_url: str, expected_state: str = "") -> tuple[str, str] | None:
    parsed = urlparse(str(callback_url or ""))
    query = parse_qs(parsed.query)
    state = query.get("state", [""])[0]
    code = query.get("code", [""])[0]
    if code and state and (not expected_state or state == expected_state):
        return state, code
    return None


def _get_object_url(value) -> str:
    try:
        url_value = getattr(value, "url", "")
        if callable(url_value):
            return str(url_value() or "")
        return str(url_value or "")
    except Exception:
        return ""


def _remember_oauth_callback_url(
    page,
    candidate_url: str,
    progress_logger: ProgressLogger | None = None,
) -> bool:
    candidate_url = str(candidate_url or "")
    if not _parse_callback_code_from_url(candidate_url):
        return False

    if getattr(page, "_batch_oauth_callback_url", "") == candidate_url:
        return True

    setattr(page, "_batch_oauth_callback_url", candidate_url)
    _emit_progress(
        f"已捕获OAuth回调URL: {_redact_query_value(candidate_url, {'code'})}",
        progress_logger=progress_logger,
    )
    return True


def _install_oauth_callback_capture(
    page,
    progress_logger: ProgressLogger | None = None,
) -> None:
    if getattr(page, "_batch_oauth_callback_capture_installed", False):
        return
    setattr(page, "_batch_oauth_callback_capture_installed", True)

    def capture_from_value(value) -> None:
        _remember_oauth_callback_url(
            page,
            _get_object_url(value),
            progress_logger=progress_logger,
        )

    try:
        page.on("request", capture_from_value)
        page.on("requestfailed", capture_from_value)
        page.on("framenavigated", capture_from_value)
    except Exception as exc:
        _emit_progress(
            f"安装OAuth回调URL监听器失败，将仅轮询当前地址栏: {exc}",
            level="warning",
            progress_logger=progress_logger,
        )


def _build_callback_url(callback_base_url: str, state: str, code: str) -> str:
    separator = "&" if "?" in callback_base_url else "?"
    return f"{callback_base_url}{separator}{urlencode({'state': state, 'code': code})}"


def _click_oauth_action_if_present(
    page,
    email: str,
    progress_logger: ProgressLogger | None = None,
) -> bool:
    current_url = str(getattr(page, "url", "") or "")
    is_nativeapp_signin = "signin/oauth/firstparty/nativeapp" in current_url
    action_texts = [
        "Continue",
        "Allow",
        "Next",
        "I agree",
        "Got it",
        "Confirm",
        "Approve",
        "Accept",
        "Done",
        "Finish",
        "Open",
        "Sign in",
        "Use this account",
        "继续",
        "下一步",
        "允许",
        "同意",
        "确认",
        "批准",
        "接受",
        "完成",
        "打开",
        "登录",
        "登入",
        "使用此账号",
        "Tiếp tục",
        "Cho phép",
        "Đồng ý",
        "Xác nhận",
        "Mở",
        "Đăng nhập",
        "Sử dụng tài khoản này",
    ]
    if is_nativeapp_signin:
        action_texts = [
            "Sign in",
            "登录",
            "登入",
            "Đăng nhập",
            *[text for text in action_texts if text not in {"Sign in", "登录", "登入", "Đăng nhập"}],
        ]

    last_click_url = str(getattr(page, "_batch_oauth_last_action_click_url", "") or "")
    last_click_at = float(getattr(page, "_batch_oauth_last_action_click_at", 0.0) or 0.0)
    if current_url and current_url == last_click_url and time.monotonic() - last_click_at < 2.0:
        return False

    def mark_action_clicked() -> None:
        try:
            setattr(page, "_batch_oauth_last_action_click_url", current_url)
            setattr(page, "_batch_oauth_last_action_click_at", time.monotonic())
        except Exception:
            pass

    selectors = []
    if is_nativeapp_signin:
        selectors.extend(
            [
                "button:has-text('Sign in')",
                "div[role='button']:has-text('Sign in')",
                "[role='link']:has-text('Sign in')",
                "a:has-text('Sign in')",
                "button[aria-label='Sign in']",
                "[role='button'][aria-label='Sign in']",
                "[role='link'][aria-label='Sign in']",
                "input[type='submit'][value='Sign in']",
                "button:has-text('登录')",
                "button:has-text('登入')",
                "button:has-text('Đăng nhập')",
                "div[role='button']:has-text('Đăng nhập')",
            ]
        )

    selectors.extend([
        "button:has-text('Continue')",
        "button:has-text('继续')",
        "button:has-text('下一步')",
        "button:has-text('Next')",
        "button:has-text('Allow')",
        "button:has-text('允许')",
        "button:has-text('同意')",
        "button:has-text('Approve')",
        "button:has-text('Accept')",
        "button:has-text('Open')",
        "button:has-text('Sign in')",
        "button:has-text('Use this account')",
        "button:has-text('Tiếp tục')",
        "button:has-text('Cho phép')",
        "button:has-text('Đồng ý')",
        "button:has-text('Đăng nhập')",
        "div[role='button']:has-text('Continue')",
        "div[role='button']:has-text('Allow')",
        "div[role='button']:has-text('Approve')",
        "div[role='button']:has-text('Accept')",
        "div[role='button']:has-text('Open')",
        "div[role='button']:has-text('Sign in')",
        "div[role='button']:has-text('Use this account')",
        "div[role='button']:has-text('Tiếp tục')",
        "div[role='button']:has-text('Cho phép')",
        "div[role='button']:has-text('Đồng ý')",
        "div[role='button']:has-text('Đăng nhập')",
        "[role='link']:has-text('Continue')",
        "[role='link']:has-text('Sign in')",
        "a:has-text('Continue')",
        "a:has-text('Sign in')",
        "input[type='submit']",
    ])

    if email and "accountchooser" in current_url:
        selectors.extend(
            [
                f"[data-email='{email}']",
                f"[data-identifier='{email}']",
                f"text={email}",
            ]
        )

    deduped_selectors = []
    for selector in selectors:
        if selector not in deduped_selectors:
            deduped_selectors.append(selector)

    clicked_accessible = _click_by_accessible_name(
        page,
        action_texts,
        timeout=500 if is_nativeapp_signin else 800,
    )
    if clicked_accessible:
        mark_action_clicked()
        _emit_progress(
            f"OAuth授权页已点击操作项: {clicked_accessible}",
            progress_logger=progress_logger,
        )
        return True

    clicked_selector = _click_first_visible(
        page,
        deduped_selectors,
        visible_timeout=300 if is_nativeapp_signin else 500,
        click_timeout=700 if is_nativeapp_signin else 1000,
    )
    if clicked_selector:
        mark_action_clicked()
        _emit_progress(
            f"OAuth授权页已点击操作项: {clicked_selector}",
            progress_logger=progress_logger,
        )
        return True

    try:
        clicked_text = page.evaluate(
            """(texts) => {
                const normalize = (value) => String(value || '').replace(/\\s+/g, ' ').trim();
                const targets = texts.map((text) => normalize(text).toLowerCase()).filter(Boolean);
                const labelledText = (el) => {
                    const ids = String(el.getAttribute('aria-labelledby') || '')
                        .split(/\\s+/)
                        .filter(Boolean);
                    return ids.map((id) => {
                        const item = document.getElementById(id);
                        return item ? normalize(item.innerText || item.textContent) : '';
                    }).filter(Boolean).join(' ');
                };
                const labelText = (el) => normalize(
                    el.innerText ||
                    el.textContent ||
                    el.value ||
                    el.getAttribute('aria-label') ||
                    el.getAttribute('title') ||
                    labelledText(el) ||
                    Array.from(el.querySelectorAll('[aria-label], img[alt]'))
                        .map((item) => item.getAttribute('aria-label') || item.getAttribute('alt') || '')
                        .join(' ')
                );
                const fireClick = (el) => {
                    const rect = el.getBoundingClientRect();
                    const x = rect.left + rect.width / 2;
                    const y = rect.top + rect.height / 2;
                    for (const type of ['pointerdown', 'mousedown', 'pointerup', 'mouseup', 'click']) {
                        el.dispatchEvent(new MouseEvent(type, {
                            bubbles: true,
                            cancelable: true,
                            view: window,
                            clientX: x,
                            clientY: y
                        }));
                    }
                    el.click();
                };
                const elements = Array.from(document.querySelectorAll(
                    [
                        "button",
                        "[role='button']",
                        "[role='link']",
                        "a",
                        "input[type='button']",
                        "input[type='submit']",
                        "[jscontroller][jsaction]",
                        "[data-mdc-dialog-action]",
                        "[tabindex='0']"
                    ].join(",")
                ));
                const candidates = [];

                for (const el of elements) {
                    const rect = el.getBoundingClientRect();
                    if (!rect.width || !rect.height) continue;
                    if (el.disabled || el.getAttribute('aria-disabled') === 'true') continue;

                    const text = labelText(el);
                    if (!text) continue;
                    candidates.push({ el, text, lowerText: text.toLowerCase() });
                }

                for (const candidate of candidates) {
                    const matched = targets.find((target) => candidate.lowerText === target);
                    if (matched) {
                        fireClick(candidate.el);
                        return candidate.text;
                    }
                }

                for (const candidate of candidates) {
                    if (candidate.text.length > 80) continue;
                    const matched = targets.find((target) =>
                        candidate.lowerText.includes(target)
                    );
                    if (matched) {
                        fireClick(candidate.el);
                        return candidate.text;
                    }
                }

                return "";
            }""",
            action_texts,
        )
    except Exception:
        clicked_text = ""

    if clicked_text:
        mark_action_clicked()
        _emit_progress(
            f"OAuth授权页已点击操作项: {clicked_text}",
            progress_logger=progress_logger,
        )
        return True
    try:
        url_key = current_url.split("?", 1)[0]
        last_diagnostic_url = getattr(_click_oauth_action_if_present, "_last_diagnostic_url", "")
        if url_key != last_diagnostic_url:
            setattr(_click_oauth_action_if_present, "_last_diagnostic_url", url_key)
            candidates = page.evaluate(
                """() => {
                    const normalize = (value) => String(value || '').replace(/\\s+/g, ' ').trim();
                    const elements = Array.from(document.querySelectorAll(
                        [
                            "button",
                            "[role='button']",
                            "[role='link']",
                            "a",
                            "input[type='button']",
                            "input[type='submit']",
                            "[jscontroller][jsaction]",
                            "[data-mdc-dialog-action]",
                            "[tabindex='0']"
                        ].join(",")
                    ));
                    const items = [];
                    for (const el of elements) {
                        const rect = el.getBoundingClientRect();
                        if (!rect.width || !rect.height) continue;
                        const text = normalize(
                            el.innerText ||
                            el.textContent ||
                            el.value ||
                            el.getAttribute('aria-label') ||
                            el.getAttribute('title')
                        );
                        const displayText = text.length > 140 ? `${text.slice(0, 140)}...` : text;
                        if (displayText && !items.includes(displayText)) items.push(displayText);
                        if (items.length >= 8) break;
                    }
                    return items;
                }"""
            )
            if candidates:
                _emit_progress(
                    f"OAuth页面未匹配到授权按钮，可见操作项: {' | '.join(candidates)}",
                    level="warning",
                    progress_logger=progress_logger,
                )
            else:
                _emit_progress(
                    "OAuth页面未匹配到授权按钮，当前没有可见操作项",
                    level="warning",
                    progress_logger=progress_logger,
                )
    except Exception as exc:
        _emit_progress(
            f"OAuth页面操作项诊断失败: {exc}",
            level="warning",
            progress_logger=progress_logger,
        )
    return False


def _submit_password_if_present(
    page,
    password: str,
    progress_logger: ProgressLogger | None = None,
) -> bool:
    if not str(password or ""):
        return False

    try:
        if page.locator("input[type='password'], #password input").count() <= 0:
            return False

        _emit_progress("OAuth阶段检测到密码验证，正在填充密码", progress_logger=progress_logger)
        selector = _fill_first(
            page,
            ["input[type='password']", "#password input"],
            password,
            timeout=3000,
        )
        if not selector:
            _emit_progress(
                "OAuth阶段未找到可填充的密码输入框",
                level="warning",
                progress_logger=progress_logger,
            )
            return False

        _emit_progress(f"OAuth阶段密码已填充，输入框: {selector}", progress_logger=progress_logger)
        clicked_selector = _click_first(
            page,
            ["#passwordNext button", "button:has-text('Next')", "button:has-text('下一步')"],
            timeout=3000,
        )
        if clicked_selector:
            _emit_progress(
                f"OAuth阶段密码下一步已点击，按钮: {clicked_selector}",
                progress_logger=progress_logger,
            )
        else:
            _emit_progress(
                "OAuth阶段密码已填充，但未找到下一步按钮",
                level="warning",
                progress_logger=progress_logger,
            )
        return True
    except Exception as exc:
        _emit_progress(
            f"OAuth阶段处理密码验证失败: {exc}",
            level="warning",
            progress_logger=progress_logger,
        )
        return False


def _click_later_if_present(
    page,
    progress_logger: ProgressLogger | None = None,
) -> bool:
    simplify_sign_in_markers = [
        "simplify your sign-in",
        "simplify sign in",
        "让登录更简单",
        "簡化登入方式",
    ]
    continue_texts = [
        "Continue",
        "继续",
        "繼續",
        "Tiếp tục",
    ]
    later_texts = [
        "以后再说",
        "稍后再说",
        "稍后",
        "暂不",
        "暂时不要",
        "跳过",
        "Not now",
        "Maybe later",
        "Later",
        "Skip",
        "Do this later",
        "Remind me later",
    ]

    try:
        clicked_continue = page.evaluate(
            """(markers, continueTexts) => {
                const normalize = (value) => String(value || '').replace(/\\s+/g, ' ').trim();
                const bodyText = normalize(document.body ? document.body.innerText : '').toLowerCase();
                if (!markers.some((marker) => bodyText.includes(String(marker || '').toLowerCase()))) {
                    return "";
                }

                const targets = continueTexts.map((text) => normalize(text).toLowerCase()).filter(Boolean);
                const elements = Array.from(document.querySelectorAll(
                    "button, [role='button'], a, input[type='button'], input[type='submit']"
                ));

                for (const el of elements) {
                    const rect = el.getBoundingClientRect();
                    if (!rect.width || !rect.height) continue;

                    const text = normalize(
                        el.innerText ||
                        el.textContent ||
                        el.value ||
                        el.getAttribute('aria-label') ||
                        el.getAttribute('title')
                    );
                    const lowerText = text.toLowerCase();
                    if (!lowerText) continue;

                    const matched = targets.find((target) =>
                        lowerText === target ||
                        (
                            target.length > 4 &&
                            lowerText.includes(target)
                        )
                    );
                    if (matched) {
                        el.click();
                        return text;
                    }
                }

                return "__SIMPLIFY_SIGNIN_DETECTED__";
            }""",
            simplify_sign_in_markers,
            continue_texts,
        )
    except Exception:
        clicked_continue = ""

    if clicked_continue and clicked_continue != "__SIMPLIFY_SIGNIN_DETECTED__":
        _emit_progress(
            f"检测到 Simplify your sign-in 页面，已点击 Continue: {clicked_continue}",
            progress_logger=progress_logger,
        )
        return True
    if clicked_continue == "__SIMPLIFY_SIGNIN_DETECTED__":
        _emit_progress(
            "检测到 Simplify your sign-in 页面，但未找到可点击的 Continue 按钮",
            level="warning",
            progress_logger=progress_logger,
        )
        return False

    try:
        clicked_text = page.evaluate(
            """(texts) => {
                const normalize = (value) => String(value || '').replace(/\\s+/g, ' ').trim();
                const targets = texts.map((text) => normalize(text).toLowerCase()).filter(Boolean);
                const elements = Array.from(document.querySelectorAll(
                    "button, [role='button'], a, input[type='button'], input[type='submit']"
                ));

                for (const el of elements) {
                    const rect = el.getBoundingClientRect();
                    if (!rect.width || !rect.height) continue;

                    const text = normalize(
                        el.innerText ||
                        el.textContent ||
                        el.value ||
                        el.getAttribute('aria-label') ||
                        el.getAttribute('title')
                    );
                    const lowerText = text.toLowerCase();
                    if (!lowerText) continue;
                    if (lowerText.includes('skip to main content')) continue;

                    const matched = targets.find((target) =>
                        lowerText === target ||
                        (
                            target.length > 4 &&
                            lowerText.includes(target)
                        )
                    );
                    if (matched) {
                        el.click();
                        return text;
                    }
                }

                return "";
            }""",
            later_texts,
        )
    except Exception:
        clicked_text = ""

    if clicked_text:
        _emit_progress(
            f"检测到以后再说/Not now提示，已点击: {clicked_text}",
            progress_logger=progress_logger,
        )
        return True
    return False


def _page_has_two_step_verification_prompt(page) -> bool:
    try:
        page_text = page.locator("body").inner_text(timeout=3000).lower()
    except Exception:
        return False

    return any(
        marker in page_text
        for marker in (
            "two-step verification",
            "2-step verification",
            "two-factor authentication",
            "2fa",
            "choose how you want to sign in",
            "tap yes on your phone or tablet",
            "google authenticator",
            "authenticator app",
            "两步验证",
            "两步驟驗證",
            "选择您要登录的方式",
            "選擇你要登入的方式",
            "xác minh 2 bước",
            "chọn cách bạn muốn đăng nhập",
        )
    )


def _click_totp_challenge_option_if_present(
    page,
    progress_logger: ProgressLogger | None = None,
) -> bool:
    primary_selectors = [
        "button:has-text('Google Authenticator')",
        "div[role='button']:has-text('Google Authenticator')",
        "[role='link']:has-text('Google Authenticator')",
        "a:has-text('Google Authenticator')",
        "[tabindex='0']:has-text('Google Authenticator')",
        "text=Google Authenticator",
    ]
    clicked_selector = _click_first_visible(page, primary_selectors, visible_timeout=300, click_timeout=1200)
    if clicked_selector:
        _emit_progress(
            f"2FA方式选择页已点击 Google Authenticator 入口: {clicked_selector}",
            progress_logger=progress_logger,
        )
        return True

    try:
        clicked_text = page.evaluate(
            """() => {
                const normalize = (value) => String(value || '').replace(/\\s+/g, ' ').trim();
                const visible = (el) => {
                    const rect = el.getBoundingClientRect();
                    const style = window.getComputedStyle(el);
                    return Boolean(rect.width && rect.height) &&
                        style.visibility !== 'hidden' &&
                        style.display !== 'none';
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
                const click = (el) => {
                    el.scrollIntoView({ block: 'center', inline: 'center' });
                    el.click();
                    return textOf(el);
                };

                for (const el of interactive) {
                    if (!visible(el)) continue;
                    const text = textOf(el).toLowerCase();
                    if (!text) continue;
                    if (text.includes('google authenticator')) {
                        return click(el);
                    }
                }
                return '';
            }"""
        )
    except Exception:
        clicked_text = ""

    if clicked_text:
        _emit_progress(
            f"2FA方式选择页已点击操作项: {clicked_text}",
            progress_logger=progress_logger,
        )
        return True

    _emit_progress(
        "2FA方式选择页未找到包含 Google Authenticator 的组件",
        level="warning",
        progress_logger=progress_logger,
    )
    return False


def _wait_for_oauth_callback(
    page,
    state: str,
    email: str,
    password: str,
    two_fa_key: str,
    timeout_seconds: int = 180,
    progress_logger: ProgressLogger | None = None,
) -> str:
    from src.auth import auth_flows

    start_time = time.monotonic()
    last_logged_url = ""

    while time.monotonic() - start_time < timeout_seconds:
        captured_url = str(getattr(page, "_batch_oauth_callback_url", "") or "")
        if _parse_callback_code_from_url(captured_url):
            _emit_progress(
                "已从浏览器请求记录捕获OAuth回调URL，准备继续处理",
                progress_logger=progress_logger,
            )
            return captured_url

        flow_data = auth_flows.get(state) or {}
        code = flow_data.get("code")
        if code:
            current_url = str(getattr(page, "url", "") or "")
            if _parse_callback_code_from_url(current_url, state):
                return current_url
            return _build_callback_url(flow_data.get("callback_url") or "", state, code)

        current_url = str(getattr(page, "url", "") or "")
        if current_url and current_url != last_logged_url:
            last_logged_url = current_url
            if "accounts.google.com" in current_url or _parse_callback_code_from_url(current_url):
                _emit_progress(
                    f"OAuth当前地址: {_redact_query_value(current_url, {'code'})}",
                    progress_logger=progress_logger,
                )

        if _remember_oauth_callback_url(page, current_url, progress_logger=progress_logger):
            _emit_progress(
                "已检测到地址栏OAuth回调URL，准备继续处理",
                progress_logger=progress_logger,
            )
            return str(getattr(page, "_batch_oauth_callback_url", "") or current_url)

        _raise_if_service_unavailable_page(page, progress_logger=progress_logger)

        if _submit_password_if_present(page, password, progress_logger=progress_logger):
            page.wait_for_timeout(1000)
            continue

        if (
            str(two_fa_key or "").strip()
            and (
                page.locator("#totpPin, input[name='totpPin']").count() > 0
                or _page_has_two_step_verification_prompt(page)
            )
        ):
            _submit_totp_if_needed(page, two_fa_key, progress_logger=progress_logger)
            page.wait_for_timeout(1000)
            continue

        if not _click_later_if_present(page, progress_logger=progress_logger):
            _click_oauth_action_if_present(page, email, progress_logger=progress_logger)
        page.wait_for_timeout(1000)

    raise TimeoutError("等待OAuth授权回调超时")


def _extract_validation_url(response_data: dict) -> str:
    def normalize_url(value: str) -> str:
        return re.sub(r"\s+", "", str(value or ""))

    if not isinstance(response_data, dict):
        return ""

    error = response_data.get("error")
    if not isinstance(error, dict):
        return ""

    message = str(error.get("message") or "")
    if int(error.get("code") or 0) != 403 or "verify your account to continue" not in message.lower():
        return ""

    for detail in error.get("details") or []:
        if not isinstance(detail, dict):
            continue

        metadata = detail.get("metadata")
        if isinstance(metadata, dict) and metadata.get("validation_url"):
            return normalize_url(metadata["validation_url"])

        links = detail.get("links")
        if isinstance(links, list):
            for link in links:
                if not isinstance(link, dict):
                    continue
                description = str(link.get("description") or "")
                url = normalize_url(link.get("url") or "")
                if "Verify your account" in description and url:
                    return url

    return ""


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


def _raise_if_service_unavailable_page(
    page,
    progress_logger: ProgressLogger | None = None,
) -> None:
    if not _page_has_service_unavailable(page):
        return

    message = "页面提示 Entire service unavailable，该账号不可用"
    _emit_progress(message, level="error", progress_logger=progress_logger)
    raise AccountUnusableError("service_unavailable", message)


def _click_validation_action(
    page,
    texts: list[str],
    progress_logger: ProgressLogger | None = None,
) -> bool:
    try:
        clicked_text = page.evaluate(
            """(texts) => {
                const normalize = (value) => String(value || '').replace(/\\s+/g, ' ').trim();
                const targets = texts.map((text) => normalize(text).toLowerCase()).filter(Boolean);
                const elements = Array.from(document.querySelectorAll(
                    [
                        "button",
                        "[role='button']",
                        "[role='link']",
                        "a",
                        "input[type='button']",
                        "input[type='submit']",
                        "[jscontroller][jsaction]",
                        "[data-mdc-dialog-action]",
                        "[tabindex='0']"
                    ].join(",")
                ));
                const candidates = [];

                for (const el of elements) {
                    const rect = el.getBoundingClientRect();
                    if (!rect.width || !rect.height) continue;

                    const text = normalize(
                        el.innerText ||
                        el.textContent ||
                        el.value ||
                        el.getAttribute('aria-label') ||
                        el.getAttribute('title')
                    );
                    if (!text) continue;
                    candidates.push({ el, text, lowerText: text.toLowerCase() });
                }

                for (const candidate of candidates) {
                    if (targets.includes(candidate.lowerText)) {
                        candidate.el.click();
                        return candidate.text;
                    }
                }

                for (const candidate of candidates) {
                    if (candidate.text.length > 80) continue;
                    const matched = targets.find((target) => candidate.lowerText.includes(target));
                    if (matched) {
                        candidate.el.click();
                        return candidate.text;
                    }
                }

                return "";
            }""",
            texts,
        )
    except Exception:
        clicked_text = ""

    if clicked_text:
        _emit_progress(
            f"账号验证页面已点击操作项: {clicked_text}",
            progress_logger=progress_logger,
        )
        return True
    return False


def _click_validation_phone_option_if_present(
    page,
    progress_logger: ProgressLogger | None = None,
) -> bool:
    preferred_selectors = [
        "button[id*='phone' i]",
        "button[id*='sms' i]",
        "button[class*='phone' i]",
        "button[class*='sms' i]",
        "[role='button'][id*='phone' i]",
        "[role='button'][id*='sms' i]",
        "[role='button'][class*='phone' i]",
        "[role='button'][class*='sms' i]",
        "a[id*='phone' i]",
        "a[id*='sms' i]",
        "[role='link'][id*='phone' i]",
        "[role='link'][id*='sms' i]",
        "[aria-controls*='phone' i]",
        "[aria-controls*='sms' i]",
        "[data-view-id*='phone' i]",
        "[data-view-id*='sms' i]",
    ]
    clicked_selector = _click_first_visible(page, preferred_selectors, visible_timeout=200, click_timeout=1200)
    if clicked_selector:
        _emit_progress(
            f"账号验证页面已点击手机号验证入口: {clicked_selector}",
            progress_logger=progress_logger,
        )
        return True

    try:
        clicked_text = page.evaluate(
            """() => {
                const visible = (el) => {
                    const rect = el.getBoundingClientRect();
                    const style = window.getComputedStyle(el);
                    return Boolean(rect.width && rect.height) &&
                        style.visibility !== 'hidden' &&
                        style.display !== 'none';
                };
                const interactive = Array.from(document.querySelectorAll(
                    "button, [role='button'], a, [role='link'], [jscontroller][jsaction], [tabindex='0']"
                ));
                const attrPattern = /(phone|mobile|sms|tel|preregisteredphone|anyphone|idvphone|idvpin)/i;
                const textOf = (el) => String(
                    el.innerText ||
                    el.textContent ||
                    el.getAttribute('aria-label') ||
                    el.getAttribute('title') ||
                    ''
                ).replace(/\\s+/g, ' ').trim();
                for (const el of interactive) {
                    if (!visible(el)) continue;
                    const attrs = [
                        el.id,
                        el.className,
                        el.getAttribute('name'),
                        el.getAttribute('jsname'),
                        el.getAttribute('aria-controls'),
                        el.getAttribute('data-secondary-action-label'),
                        el.getAttribute('data-view-id')
                    ].filter(Boolean).join(' ');
                    if (!attrPattern.test(attrs)) continue;
                    el.scrollIntoView({ block: 'center', inline: 'center' });
                    el.click();
                    return textOf(el) || attrs || el.tagName.toLowerCase();
                }
                return '';
            }"""
        )
    except Exception:
        clicked_text = ""

    if clicked_text:
        _emit_progress(
            f"账号验证页面已点击手机号验证入口: {clicked_text}",
            progress_logger=progress_logger,
        )
        return True

    return False


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


def _click_verify_your_phone_number_component(
    page,
    progress_logger: ProgressLogger | None = None,
) -> bool:
    selectors = [
        "button:has-text('Verify your phone number')",
        "div[role='button']:has-text('Verify your phone number')",
        "[role='link']:has-text('Verify your phone number')",
        "a:has-text('Verify your phone number')",
        "text=Verify your phone number",
    ]
    clicked_selector = _click_first_visible(page, selectors, visible_timeout=200, click_timeout=1200)
    if clicked_selector:
        _emit_progress(
            f"验证方式选择页已点击 Verify your phone number 组件: {clicked_selector}",
            progress_logger=progress_logger,
        )
        return True

    try:
        clicked_text = page.evaluate(
            """() => {
                const normalize = (value) => String(value || '').replace(/\\s+/g, ' ').trim();
                const visible = (el) => {
                    const rect = el.getBoundingClientRect();
                    const style = window.getComputedStyle(el);
                    return Boolean(rect.width && rect.height) &&
                        style.visibility !== 'hidden' &&
                        style.display !== 'none';
                };
                const interactive = Array.from(document.querySelectorAll(
                    "button, [role='button'], a, [role='link'], [jscontroller][jsaction], [tabindex='0']"
                ));
                for (const el of interactive) {
                    if (!visible(el)) continue;
                    const text = normalize(
                        el.innerText ||
                        el.textContent ||
                        el.getAttribute('aria-label') ||
                        el.getAttribute('title')
                    );
                    if (!text) continue;
                    if (text.toLowerCase().includes('verify your phone number')) {
                        el.scrollIntoView({ block: 'center', inline: 'center' });
                        el.click();
                        return text;
                    }
                }
                return '';
            }"""
        )
    except Exception:
        clicked_text = ""

    if clicked_text:
        _emit_progress(
            f"验证方式选择页已点击 Verify your phone number 组件: {clicked_text}",
            progress_logger=progress_logger,
        )
        return True

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


def _try_fill_validation_phone_input(page, phone: str) -> str:
    selector = _fill_first(
        page,
        [
            "#phoneNumberId",
            "input[name='phoneNumber']",
            "input[autocomplete='tel']",
            "input[type='tel']:not(#totpPin)",
            "input[type='number']",
            "input[aria-label*='phone' i]",
            "input[placeholder*='phone' i]",
            "input:not([type='hidden']):not([type='password']):not(#totpPin)",
        ],
        phone,
        timeout=8000,
    )
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
                        return Boolean(rect.width && rect.height) && type !== 'hidden' && type !== 'password';
                    });

                    const fill = (el, label) => {
                        el.focus();
                        el.value = phone;
                        el.dispatchEvent(new Event('input', { bubbles: true }));
                        el.dispatchEvent(new Event('change', { bubbles: true }));
                        return label || 'input';
                    };

                    for (const el of usable) {
                        const attrs = [
                            el.type,
                            el.name,
                            el.id,
                            el.autocomplete,
                            el.getAttribute('aria-label'),
                            el.getAttribute('placeholder')
                        ].join(' ').toLowerCase();
                        const phoneLike =
                            attrs.includes('phone') ||
                            attrs.includes('tel') ||
                            attrs.includes('mobile') ||
                            attrs.includes('电话') ||
                            attrs.includes('手機') ||
                            attrs.includes('số điện thoại');
                        if (!phoneLike || attrs.includes('totp')) continue;
                        return fill(el, attrs || 'phone-like input');
                    }

                    if (usable.length === 1) {
                        return fill(usable[0], 'single visible input');
                    }
                    return '';
                }""",
                phone,
            )
        )
    except Exception:
        return ""


def _refresh_validation_phone_input_events(page, phone: str) -> bool:
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


def _select_phone_verification_method(page, progress_logger: ProgressLogger | None = None) -> bool:
    if _validation_page_has_qr_code(page):
        _emit_progress(
            "账号验证页面检测到二维码，不再继续手机号验证方式选择",
            level="warning",
            progress_logger=progress_logger,
        )
        return False

    if _validation_page_has_phone_input(page):
        return True

    _emit_progress(
        "检测到手机号验证入口，正在等待并点击 Verify your phone number",
        progress_logger=progress_logger,
    )
    before_url = str(getattr(page, "url", "") or "")
    action_texts = [
        "Verify your phone number",
        "Use a verification code",
        "Add phone number",
        "Phone number",
        "手机号",
        "电话号码",
        "驗證手機號碼",
        "Số điện thoại",
        "Xác minh số điện thoại",
    ]

    deadline = time.monotonic() + 15
    clicked = False
    while time.monotonic() < deadline:
        if _validation_page_has_qr_code(page):
            _emit_progress(
                "等待手机号验证方式时检测到二维码页面",
                level="warning",
                progress_logger=progress_logger,
            )
            return False
        if _validation_page_has_phone_input(page):
            return True
        if _click_validation_phone_option_if_present(page, progress_logger=progress_logger):
            clicked = True
            page.wait_for_timeout(1200)
            if _validation_page_has_phone_input(page):
                return True
            if _validation_page_has_qr_code(page):
                return False
            continue
        if _click_validation_action(page, action_texts, progress_logger=progress_logger):
            clicked = True
            break
        if _validation_page_success(page):
            return False
        page.wait_for_timeout(500)

    if not clicked:
        if _validation_page_has_qr_code(page):
            _emit_progress(
                "手机号验证方式未出现，但页面已进入二维码验证",
                level="warning",
                progress_logger=progress_logger,
            )
            return False
        _emit_progress(
            f"等待 Verify your phone number 操作项超时；诊断: {_validation_page_diagnostic_snapshot(page)}",
            level="warning",
            progress_logger=progress_logger,
        )
        return False

    page.wait_for_timeout(1200)
    if _validation_page_has_qr_code(page):
        _emit_progress(
            "点击手机号验证方式后进入二维码验证页面",
            level="warning",
            progress_logger=progress_logger,
        )
        return False
    if not _validation_page_has_phone_input(page):
        _emit_progress(
            f"已点击手机号验证入口，但尚未进入手机号输入页；诊断: {_validation_page_diagnostic_snapshot(page)}",
            level="warning",
            progress_logger=progress_logger,
        )
        return False
    after_url = str(getattr(page, "url", "") or "")
    if after_url != before_url:
        _emit_progress(
            f"手机号验证方式选择后页面地址已变化: {_redact_query_value(after_url, {'code'})}",
            progress_logger=progress_logger,
        )
    _emit_progress(
        f"手机号验证方式选择后页面诊断: {_validation_page_diagnostic_snapshot(page)}",
        progress_logger=progress_logger,
    )
    return True


def _click_validation_phone_next(page, progress_logger: ProgressLogger | None = None) -> bool:
    next_texts = [
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

    playwright_selectors = [
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
    clicked_selector = _click_first_visible(page, playwright_selectors, visible_timeout=200, click_timeout=800)
    if clicked_selector:
        _emit_progress(
            f"手机号下一步已点击，按钮: {clicked_selector}",
            progress_logger=progress_logger,
        )
        return True

    try:
        clicked_text = page.evaluate(
            """(texts) => {
                const normalize = (value) => String(value || '').replace(/\\s+/g, ' ').trim();
                const targets = texts.map((text) => normalize(text).toLowerCase()).filter(Boolean);
                const visible = (el) => {
                    const rect = el.getBoundingClientRect();
                    const style = window.getComputedStyle(el);
                    return Boolean(rect.width && rect.height) &&
                        style.visibility !== 'hidden' &&
                        style.display !== 'none';
                };
                const disabled = (el) =>
                    el.disabled ||
                    el.getAttribute('aria-disabled') === 'true' ||
                    el.closest('[aria-disabled="true"]');
                const textOf = (el) => normalize(
                    el.innerText ||
                    el.textContent ||
                    el.value ||
                    el.getAttribute('aria-label') ||
                    el.getAttribute('title')
                );
                const matches = (el) => {
                    const text = textOf(el).toLowerCase();
                    if (targets.includes(text)) return true;
                    if (text && text.length <= 80 && targets.some((target) => text.includes(target))) {
                        return true;
                    }
                    const attrs = [
                        el.id,
                        el.name,
                        el.getAttribute('jsname'),
                        el.getAttribute('data-mdc-dialog-action')
                    ].join(' ').toLowerCase();
                    return /(^|[\\s_-])next($|[\\s_-])/.test(attrs);
                };
                const click = (el) => {
                    el.scrollIntoView({ block: 'center', inline: 'center' });
                    el.click();
                    return textOf(el) || el.id || el.name || el.tagName.toLowerCase();
                };

                const preferredSelectors = [
                    "#idvPreregisteredPhoneNext button",
                    "#idvPreregisteredPhoneNext",
                    "#next button",
                    "#next",
                    "button[type='submit']",
                    "input[type='submit']"
                ];
                for (const selector of preferredSelectors) {
                    const elements = Array.from(document.querySelectorAll(selector));
                    for (const el of elements) {
                        if (visible(el) && !disabled(el) && matches(el)) {
                            return click(el);
                        }
                    }
                }

                const elements = Array.from(document.querySelectorAll(
                    "button, [role='button'], input[type='button'], input[type='submit'], [jscontroller][jsaction], [tabindex='0']"
                ));
                for (const el of elements) {
                    if (visible(el) && !disabled(el) && matches(el)) {
                        return click(el);
                    }
                }
                return "";
            }""",
            next_texts,
        )
    except Exception:
        clicked_text = ""

    if clicked_text:
        _emit_progress(
            f"手机号下一步已点击: {clicked_text}",
            progress_logger=progress_logger,
        )
        return True

    _emit_progress(
        "手机号已填充，但未找到可点击的 Next/发送验证码按钮，尝试按 Enter 提交",
        level="warning",
        progress_logger=progress_logger,
    )
    try:
        page.locator("#phoneNumberId, input[name='phoneNumber'], input[autocomplete='tel']").first.press(
            "Enter",
            timeout=3000,
        )
        _emit_progress("已在手机号输入框按 Enter 触发下一步", progress_logger=progress_logger)
        return True
    except Exception:
        return False


def _wait_for_validation_phone_input(page, timeout_seconds: int = 20) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if _validation_page_has_phone_input(page):
            return True
        if _validation_page_success(page):
            return False
        page.wait_for_timeout(500)
    return False


def _wait_for_validation_after_phone_next(page, timeout_seconds: int = 12) -> str:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if _validation_page_success(page):
            return "success"
        if _validation_page_has_phone_rate_limit(page):
            return "phone_rate_limited"
        if _validation_page_has_qr_code(page):
            return "qr_required"
        if _wait_for_validation_code_input(page, timeout_seconds=1):
            return "code_input"
        page.wait_for_timeout(500)

    if _validation_page_has_phone_input(page):
        return "phone_next_not_triggered"
    return "code_input_timeout"


def _fill_validation_phone(page, phone: str, progress_logger: ProgressLogger | None = None) -> str:
    phone = str(phone or "").strip()
    if not phone:
        _emit_progress(
            "账号验证页面需要绑定手机号，但上传文件未提供手机号",
            level="warning",
            progress_logger=progress_logger,
        )
        return "phone_required_but_not_submitted"

    if _validation_page_has_qr_code(page):
        return "qr_required"

    if not _select_phone_verification_method(page, progress_logger=progress_logger):
        if _validation_page_has_qr_code(page):
            return "qr_required"
        return "phone_method_not_selected"

    if not _wait_for_validation_phone_input(page, timeout_seconds=20):
        if _validation_page_has_qr_code(page):
            return "qr_required"
        _emit_progress(
            f"等待手机号输入页超时；诊断: {_validation_page_diagnostic_snapshot(page)}",
            level="warning",
            progress_logger=progress_logger,
        )
        return "phone_input_timeout"

    _emit_progress("已进入手机号输入页，正在填充手机号", progress_logger=progress_logger)
    filled = _try_fill_validation_phone_input(page, phone)
    if not filled:
        _emit_progress(
            f"未找到可填充的手机号输入框；诊断: {_validation_page_diagnostic_snapshot(page)}",
            level="warning",
            progress_logger=progress_logger,
        )
        return "phone_input_not_found"

    _emit_progress(f"手机号已填充，输入框: {filled}", progress_logger=progress_logger)
    _refresh_validation_phone_input_events(page, phone)

    before_url = str(getattr(page, "url", "") or "")
    final_status = "phone_next_not_triggered"
    for attempt in range(1, 4):
        if not _click_validation_phone_next(page, progress_logger=progress_logger):
            _emit_progress(
                "手机号已填充，但未能触发下一步",
                level="warning",
                progress_logger=progress_logger,
            )
            final_status = "phone_next_not_triggered"
            break

        _emit_progress(
            "手机号下一步已点击，正在确认是否进入验证码输入页",
            progress_logger=progress_logger,
        )
        final_status = _wait_for_validation_after_phone_next(page, timeout_seconds=12)
        if final_status in {"code_input", "success", "qr_required"}:
            break

        if attempt < 3 and final_status == "phone_next_not_triggered":
            _emit_progress(
                "手机号下一步点击后仍停留在手机号输入页，正在重新填充并重试",
                level="warning",
                progress_logger=progress_logger,
            )
            _refresh_validation_phone_input_events(page, phone)
            continue

        break

    after_url = str(getattr(page, "url", "") or "")
    if after_url != before_url:
        _emit_progress(
            f"手机号提交后页面地址已变化: {_redact_query_value(after_url, {'code'})}",
            progress_logger=progress_logger,
        )
    _emit_progress(
        f"手机号提交后页面诊断: {_validation_page_diagnostic_snapshot(page)}",
        progress_logger=progress_logger,
    )
    if final_status == "phone_rate_limited":
        _emit_progress(
            "当前手机号异常：该手机号已被用于验证过多次",
            level="warning",
            progress_logger=progress_logger,
        )
        return "phone_rate_limited"
    if _validation_page_has_qr_code(page):
        return "qr_required"
    if final_status == "code_input":
        _emit_progress("已确认进入手机号验证码输入页", progress_logger=progress_logger)
    elif final_status == "phone_next_not_triggered":
        _emit_progress(
            "手机号下一步未生效，仍停留在手机号输入页，未获取短信验证码",
            level="warning",
            progress_logger=progress_logger,
        )
    return final_status


def _extract_phone_code_from_text(text: str) -> str:
    decoded = html.unescape(unquote(str(text or "")))
    match = _PHONE_CODE_PATTERN.search(decoded)
    return match.group(1) if match else ""


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


def _extract_links_from_text(text: str, base_url: str) -> list[str]:
    decoded = html.unescape(str(text or ""))
    links: list[str] = []

    for match in re.finditer(r"""href=["']([^"']+)["']""", decoded, re.IGNORECASE):
        links.append(match.group(1))
    for match in re.finditer(r"""https?://[^\s"'<>]+""", decoded, re.IGNORECASE):
        links.append(match.group(0))

    deduped: list[str] = []
    for link in links:
        normalized = html.unescape(unquote(str(link or "").strip()))
        if not normalized:
            continue
        normalized = urljoin(base_url, normalized)
        if normalized not in deduped:
            deduped.append(normalized)
    return deduped


def get_phone_verification_code(
    phone_code_url: str,
    progress_logger: ProgressLogger | None = None,
    timeout_seconds: int = 150,
) -> str:
    phone_code_url = str(phone_code_url or "").strip()
    if not phone_code_url:
        _emit_progress(
            "未提供手机号验证码获取链接，无法自动获取短信验证码",
            level="warning",
            progress_logger=progress_logger,
        )
        return ""

    deadline = time.monotonic() + timeout_seconds
    attempt = 0
    retry_interval_seconds = 12
    with httpx.Client(timeout=20.0, headers=_2FA_HEADERS, follow_redirects=True) as client:
        while time.monotonic() < deadline:
            attempt += 1
            try:
                if attempt == 1:
                    initial_wait = min(6, max(0, deadline - time.monotonic()))
                    if initial_wait > 0:
                        _emit_progress(
                            f"发送验证码后先等待 {int(max(1, round(initial_wait)))} 秒，再开始获取手机号验证码",
                            progress_logger=progress_logger,
                        )
                        time.sleep(initial_wait)
                _emit_progress(
                    f"正在获取手机号验证码: attempt={attempt}",
                    progress_logger=progress_logger,
                )
                response = client.get(phone_code_url)
                response_text = response.text if hasattr(response, "text") else ""
                if _contains_phone_rate_limit_message(response_text):
                    _emit_progress(
                        "当前手机号异常：该手机号已被用于验证过多次",
                        level="warning",
                        progress_logger=progress_logger,
                    )
                    return _PHONE_RATE_LIMIT_SENTINEL

                code = _extract_phone_code_from_text(response_text)
                if code:
                    _emit_progress("手机号验证码获取成功", progress_logger=progress_logger)
                    return code

                links = _extract_links_from_text(response_text, str(response.url))
                if links:
                    last_link = links[-1]
                    code = _extract_phone_code_from_text(last_link)
                    if code:
                        _emit_progress(
                            "已从验证码页面最后一个链接中解析到手机号验证码",
                            progress_logger=progress_logger,
                        )
                        return code

                    _emit_progress(
                        "验证码页面未直接包含G-验证码，正在请求最后一个链接",
                        progress_logger=progress_logger,
                    )
                    detail_response = client.get(last_link)
                    detail_text = detail_response.text if hasattr(detail_response, "text") else ""
                    if _contains_phone_rate_limit_message(detail_text):
                        _emit_progress(
                            "当前手机号异常：该手机号已被用于验证过多次",
                            level="warning",
                            progress_logger=progress_logger,
                        )
                        return _PHONE_RATE_LIMIT_SENTINEL
                    code = _extract_phone_code_from_text(detail_text)
                    if code:
                        _emit_progress(
                            "已从最后一个链接页面解析到手机号验证码",
                            progress_logger=progress_logger,
                        )
                        return code

                _emit_progress(
                    "本次未获取到手机号验证码，稍后重试",
                    level="warning",
                    progress_logger=progress_logger,
                )
            except Exception as exc:
                _emit_progress(
                    f"获取手机号验证码失败，稍后重试: {exc}",
                    level="warning",
                    progress_logger=progress_logger,
                )

            remaining = deadline - time.monotonic()
            if remaining > 0:
                sleep_seconds = min(retry_interval_seconds, remaining)
                _emit_progress(
                    f"等待 {int(max(1, round(sleep_seconds)))} 秒后重试获取手机号验证码",
                    progress_logger=progress_logger,
                )
                time.sleep(sleep_seconds)

    _emit_progress(
        "等待手机号验证码超时",
        level="warning",
        progress_logger=progress_logger,
    )
    return ""


def _try_fill_validation_code_input(page, code: str) -> str:
    selector = _fill_first(
        page,
        [
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
        ],
        code,
        timeout=20000,
    )
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


def _fill_validation_code(page, code: str, progress_logger: ProgressLogger | None = None) -> str:
    code = str(code or "").strip()
    if not code:
        return "code_empty"

    _emit_progress("正在填充手机号验证码", progress_logger=progress_logger)
    selector = _try_fill_validation_code_input(page, code)
    if selector:
        _emit_progress(f"手机号验证码已填充，输入框: {selector}", progress_logger=progress_logger)
    else:
        _emit_progress(
            f"未找到可填充的手机号验证码输入框；诊断: {_validation_page_diagnostic_snapshot(page)}",
            level="warning",
            progress_logger=progress_logger,
        )
        return "code_input_not_found"

    _refresh_validation_code_input_events(page, code)

    submit_status = "code_next_not_triggered"
    for attempt in range(1, 3):
        if not _click_validation_code_next(page, progress_logger=progress_logger):
            break

        submit_status = _wait_for_validation_after_code_submit(page, timeout_seconds=8)
        if submit_status in {"submitted", "success", "qr_required", "phone_rate_limited"}:
            break

        if attempt < 2 and submit_status == "code_next_not_triggered":
            _emit_progress(
                "验证码下一步点击后仍停留在验证码输入页，正在重试提交",
                level="warning",
                progress_logger=progress_logger,
            )
            _refresh_validation_code_input_events(page, code)
            continue
        break

    if submit_status == "code_next_not_triggered":
        _emit_progress(
            f"手机号验证码已填充，但未能触发下一步；诊断: {_validation_page_diagnostic_snapshot(page)}",
            level="warning",
            progress_logger=progress_logger,
        )
        return "code_next_not_triggered"
    if submit_status == "phone_rate_limited":
        _emit_progress(
            "当前手机号异常：该手机号已被用于验证过多次",
            level="warning",
            progress_logger=progress_logger,
        )
        return "phone_rate_limited"
    if submit_status == "success":
        _emit_progress("手机号验证码提交后页面已完成验证", progress_logger=progress_logger)
    elif submit_status == "qr_required":
        _emit_progress("手机号验证码提交后出现二维码", level="warning", progress_logger=progress_logger)

    return submit_status


def _validation_page_has_code_input(page) -> bool:
    try:
        return bool(
            page.evaluate(
                """() => {
                    const visibleInputs = Array.from(document.querySelectorAll('input'))
                        .filter((el) => {
                            const rect = el.getBoundingClientRect();
                            const type = String(el.type || '').toLowerCase();
                            return Boolean(rect.width && rect.height) &&
                                type !== 'hidden' &&
                                type !== 'password';
                        });

                    return visibleInputs.some((el) => {
                        const autocomplete = String(el.autocomplete || '').toLowerCase();
                        const attrs = [
                            el.type,
                            el.name,
                            el.id,
                            autocomplete,
                            el.getAttribute('aria-label'),
                            el.getAttribute('placeholder')
                        ].join(' ').toLowerCase();
                        if (attrs.includes('totp') || el.id === 'totpPin' || el.id === 'phoneNumberId') {
                            return false;
                        }
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
                    });
                }"""
            )
        )
    except Exception:
        return False


def _wait_for_validation_code_input(page, timeout_seconds: int = 90) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        text = _page_body_text(page, timeout=2000).lower()
        has_code_text = any(
            marker in text
            for marker in (
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
        )
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

        if has_code_text and has_code_input:
            return True
        page.wait_for_timeout(1000)
    return False


def _refresh_validation_code_input_events(page, code: str) -> bool:
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


def _click_validation_code_next(page, progress_logger: ProgressLogger | None = None) -> bool:
    playwright_selectors = [
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
    clicked_selector = _click_first_visible(page, playwright_selectors, visible_timeout=200, click_timeout=800)
    if clicked_selector:
        _emit_progress(f"手机号验证码下一步已点击，按钮: {clicked_selector}", progress_logger=progress_logger)
        return True

    if _click_validation_action(
        page,
        [
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
        ],
        progress_logger=progress_logger,
    ):
        return True

    try:
        page.locator(
            "#idvAnyPhonePin, #idvPin, input[name='pin'], input[name='idvPin'], input[autocomplete='one-time-code']"
        ).first.press("Enter", timeout=1500)
        _emit_progress("已在验证码输入框按 Enter 触发下一步", progress_logger=progress_logger)
        return True
    except Exception:
        return False


def _wait_for_validation_after_code_submit(page, timeout_seconds: int = 8) -> str:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if _validation_page_success(page):
            return "success"
        if _validation_page_has_phone_rate_limit(page):
            return "phone_rate_limited"
        if _validation_page_has_qr_code(page):
            return "qr_required"
        if not _validation_page_has_code_input(page):
            return "submitted"
        page.wait_for_timeout(400)
    return "code_next_not_triggered"


def _handle_validation_url(
    page,
    validation_url: str,
    phone: str,
    phone_code_url: str,
    progress_logger: ProgressLogger | None = None,
) -> dict:
    result = {
        "status": "unknown",
        "account_unusable": False,
        "phone_submitted": False,
        "code_submitted": False,
    }

    _emit_progress(
        "正在打开账号验证 validation_url",
        level="warning",
        progress_logger=progress_logger,
    )
    try:
        _goto_english(page, validation_url, wait_until="domcontentloaded", timeout=180000)
    except Exception as exc:
        _emit_progress(
            f"打开 validation_url 失败: {exc}",
            level="warning",
            progress_logger=progress_logger,
        )
        result["status"] = "open_failed"
        result["error"] = str(exc)
        return result

    _emit_progress(
        "validation_url 已打开，正在等待账号验证页面加载",
        level="warning",
        progress_logger=progress_logger,
    )

    deadline = time.monotonic() + 180
    last_logged_url = ""
    last_diagnostic_at = 0.0
    last_diagnostic = ""
    verify_info_selection_since = 0.0
    while time.monotonic() < deadline:
        current_url = str(getattr(page, "url", "") or "")
        if current_url and current_url != last_logged_url:
            last_logged_url = current_url
            _emit_progress(
                f"账号验证当前地址: {_redact_query_value(current_url, {'code'})}",
                progress_logger=progress_logger,
            )

        _click_later_if_present(page, progress_logger=progress_logger)

        if _page_has_service_unavailable(page):
            result["status"] = "service_unavailable"
            result["account_unusable"] = True
            _emit_progress(
                "页面提示 Entire service unavailable，该账号不可用",
                level="error",
                progress_logger=progress_logger,
            )
            return result

        if _validation_page_success(page):
            result["status"] = "success"
            _emit_progress("账号验证页面显示已完成", progress_logger=progress_logger)
            return result

        if _validation_page_has_phone_rate_limit(page):
            result["status"] = "phone_rate_limited"
            result["account_unusable"] = True
            _emit_progress(
                "当前手机号异常：This phone number has already been used too many times for verification",
                level="error",
                progress_logger=progress_logger,
            )
            return result

        now = time.monotonic()
        if now - last_diagnostic_at >= 15:
            last_diagnostic_at = now
            diagnostic = _validation_page_diagnostic_snapshot(page)
            if diagnostic and diagnostic != last_diagnostic:
                last_diagnostic = diagnostic
                _emit_progress(
                    f"账号验证页面诊断: {diagnostic}",
                    level="warning",
                    progress_logger=progress_logger,
                )

        if _is_verify_info_selection_page(page):
            if not verify_info_selection_since:
                verify_info_selection_since = time.monotonic()
            if _click_verify_your_phone_number_component(page, progress_logger=progress_logger):
                page.wait_for_timeout(1200)
                continue
            if time.monotonic() - verify_info_selection_since >= 8:
                result["status"] = "phone_option_missing"
                result["account_unusable"] = True
                _emit_progress(
                    "验证方式选择页未提供 Verify your phone number 组件，该账号不可用",
                    level="error",
                    progress_logger=progress_logger,
                )
                return result
            page.wait_for_timeout(500)
            continue
        verify_info_selection_since = 0.0

        if _validation_page_has_qr_code(page):
            result["status"] = "qr_required"
            result["account_unusable"] = True
            _emit_progress(
                "账号验证页面显示二维码，该账号不可用",
                level="error",
                progress_logger=progress_logger,
            )
            return result

        if _validation_page_has_phone_prompt(page):
            phone_status = _fill_validation_phone(page, phone, progress_logger=progress_logger)
            if phone_status == "success":
                result["status"] = "success"
                _emit_progress("账号手机号验证已完成", progress_logger=progress_logger)
                return result
            if phone_status == "phone_rate_limited":
                result["status"] = "phone_rate_limited"
                result["account_unusable"] = True
                _emit_progress(
                    "当前手机号异常：This phone number has already been used too many times for verification",
                    level="error",
                    progress_logger=progress_logger,
                )
                return result
            if phone_status == "qr_required":
                result["status"] = "qr_required"
                result["account_unusable"] = True
                _emit_progress(
                    "手机号提交后出现二维码，该账号不可用",
                    level="error",
                    progress_logger=progress_logger,
                )
                return result
            if phone_status != "code_input":
                result["status"] = phone_status or "phone_required_but_not_submitted"
                _emit_progress(
                    f"手机号下一步未完成，暂不获取短信验证码: status={result['status']}",
                    level="warning",
                    progress_logger=progress_logger,
                )
                return result
            result["phone_submitted"] = True

            _emit_progress("已进入手机号验证码输入页，开始获取短信验证码", progress_logger=progress_logger)
            code = get_phone_verification_code(
                phone_code_url,
                progress_logger=progress_logger,
                timeout_seconds=150,
            )
            if code == _PHONE_RATE_LIMIT_SENTINEL:
                result["status"] = "phone_rate_limited"
                result["account_unusable"] = True
                _emit_progress(
                    "当前手机号异常：This phone number has already been used too many times for verification",
                    level="error",
                    progress_logger=progress_logger,
                )
                return result
            if not code:
                result["status"] = "code_fetch_failed"
                return result

            code_submit_status = _fill_validation_code(page, code, progress_logger=progress_logger)
            if code_submit_status == "phone_rate_limited":
                result["status"] = "phone_rate_limited"
                result["account_unusable"] = True
                _emit_progress(
                    "当前手机号异常：This phone number has already been used too many times for verification",
                    level="error",
                    progress_logger=progress_logger,
                )
                return result
            if code_submit_status not in {"submitted", "success", "qr_required"}:
                result["status"] = "code_submit_failed"
                return result

            result["code_submitted"] = True
            _emit_progress("手机号验证码已提交，正在等待验证结果", progress_logger=progress_logger)
            for _ in range(90):
                page.wait_for_timeout(1000)
                if _validation_page_success(page):
                    result["status"] = "success"
                    _emit_progress("账号手机号验证已完成", progress_logger=progress_logger)
                    return result
                if _validation_page_has_phone_rate_limit(page):
                    result["status"] = "phone_rate_limited"
                    result["account_unusable"] = True
                    _emit_progress(
                        "当前手机号异常：This phone number has already been used too many times for verification",
                        level="error",
                        progress_logger=progress_logger,
                    )
                    return result
                if _validation_page_has_qr_code(page):
                    result["status"] = "qr_required"
                    result["account_unusable"] = True
                    _emit_progress(
                        "手机号验证码提交后出现二维码，该账号不可用",
                        level="error",
                        progress_logger=progress_logger,
                    )
                    return result

            result["status"] = "submitted_wait_timeout"
            _emit_progress(
                "手机号验证码已提交，但等待验证完成超时",
                level="warning",
                progress_logger=progress_logger,
            )
            return result

        page.wait_for_timeout(1000)

    result["status"] = "page_load_timeout"
    _emit_progress(
        "等待账号验证页面加载或可操作状态超时",
        level="warning",
        progress_logger=progress_logger,
    )
    diagnostic = _validation_page_diagnostic_snapshot(page)
    if diagnostic:
        _emit_progress(
            f"账号验证页面超时诊断: {diagnostic}",
            level="warning",
            progress_logger=progress_logger,
        )
    return result


async def _test_cached_gemini_credential(
    credential_data: dict,
    proxy_url: str,
    mode: str = "geminicli",
    progress_logger: ProgressLogger | None = None,
) -> dict:
    from config import get_antigravity_api_url, get_code_assist_endpoint
    from src.httpx_client import _extract_httpx_error_message, post_async

    mode = _normalize_credential_mode(mode)
    mode_label = _credential_mode_label(mode)
    access_token = credential_data.get("access_token") or credential_data.get("token")
    project_id = credential_data.get("project_id")
    test_model = "gemini-2.5-flash"

    if mode == "antigravity":
        from src.api.antigravity import build_antigravity_headers

        api_base_url = await get_antigravity_api_url()
        headers = build_antigravity_headers(access_token, test_model)
    else:
        api_base_url = await get_code_assist_endpoint()
        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": "application/json",
            "User-Agent": GEMINICLI_USER_AGENT,
        }

    _emit_progress(
        f"正在使用临时{mode_label}凭证测试 {test_model}: project_id={project_id}",
        progress_logger=progress_logger,
    )

    try:
        response = await post_async(
            url=f"{api_base_url}/v1internal:generateContent",
            json={
                "model": test_model,
                "project": project_id,
                "request": {
                    "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
                    "generationConfig": {"maxOutputTokens": 1},
                },
            },
            headers=headers,
            timeout=30.0,
            **_build_batch_proxy_kwargs(proxy_url, f"batch_generate_{mode}_credential_test"),
        )
    except Exception as exc:
        error_detail = _extract_httpx_error_message(exc)
        log.warning(
            f"[BATCH_GENERATE] {mode_label} {test_model} 测试请求异常: "
            f"project_id={project_id}, error_type={type(exc).__name__}, error={error_detail}"
        )
        raise RuntimeError(f"{type(exc).__name__}: {error_detail}") from exc

    response_text = response.text if hasattr(response, "text") else ""
    try:
        response_data = response.json()
    except Exception:
        response_data = {}

    response_summary = _summarize_http_response_body(response_text, response_data)
    log.info(
        f"[BATCH_GENERATE] {mode_label} {test_model} 测试返回: "
        f"project_id={project_id}, status_code={response.status_code}, body={response_summary}"
    )

    validation_url = _extract_validation_url(response_data)
    success = response.status_code in (200, 429)
    if success:
        _emit_progress(
            f"{test_model} 测试通过: HTTP {response.status_code}",
            progress_logger=progress_logger,
        )
    elif validation_url:
        _emit_progress(
            f"{test_model} 返回账号验证要求，已解析 validation_url",
            level="warning",
            progress_logger=progress_logger,
        )
    else:
        _emit_progress(
            f"{test_model} 测试失败: HTTP {response.status_code}, body={response_text[:500]}",
            level="warning",
            progress_logger=progress_logger,
        )

    return {
        "success": success,
        "status_code": response.status_code,
        "validation_url": validation_url,
        "error": response_text if not success else "",
    }


async def _build_cached_credential_from_callback_url(
    callback_url: str,
    proxy_url: str,
    mode: str = "geminicli",
    progress_logger: ProgressLogger | None = None,
) -> dict:
    from src.auth import (
        DEFAULT_PROJECT_ID,
        _cleanup_auth_flow_server,
        _prepare_credentials_data,
        auth_flows,
    )
    from config import get_antigravity_api_url, get_code_assist_endpoint
    from src.google_oauth_api import fetch_project_id_and_tier

    mode = _normalize_credential_mode(mode)
    callback_query = parse_qs(urlparse(callback_url).query)
    state = callback_query.get("state", [""])[0]
    parsed = _parse_callback_code_from_url(callback_url, state)
    if not state or not parsed:
        raise RuntimeError("OAuth回调URL缺少有效的 state 或 code")

    _, code = parsed
    flow_data = auth_flows.get(state)
    if not flow_data:
        raise RuntimeError(f"未找到OAuth授权流程: state={state}")

    mode = _normalize_credential_mode(flow_data.get("mode") or mode)
    mode_label = _credential_mode_label(mode)
    flow = flow_data["flow"]
    subscription_tier = None
    project_id = None

    try:
        _emit_progress("正在用OAuth回调code换取访问令牌", progress_logger=progress_logger)
        credentials = await flow.exchange_code(
            code,
            proxy_kwargs=_build_batch_proxy_kwargs(proxy_url, "batch_generate_oauth_exchange"),
        )
        _emit_progress("OAuth访问令牌获取成功", progress_logger=progress_logger)

        try:
            if mode == "antigravity":
                _emit_progress("正在从Antigravity接口检测 project_id", progress_logger=progress_logger)
                api_base_url = await get_antigravity_api_url()
                user_agent = ANTIGRAVITY_USER_AGENT
            else:
                _emit_progress("正在从Code Assist接口检测 project_id", progress_logger=progress_logger)
                api_base_url = await get_code_assist_endpoint()
                user_agent = GEMINICLI_USER_AGENT

            project_id, subscription_tier = await fetch_project_id_and_tier(
                credentials.access_token,
                user_agent,
                api_base_url,
                proxy_kwargs=_build_batch_proxy_kwargs(proxy_url, f"batch_generate_{mode}_project_detect"),
            )
        except Exception as exc:
            _emit_progress(
                f"自动检测 project_id 失败，将使用默认项目ID: {exc}",
                level="warning",
                progress_logger=progress_logger,
            )

        if not project_id:
            project_id = DEFAULT_PROJECT_ID
            _emit_progress(
                f"未检测到 project_id，使用默认项目ID: {project_id}",
                level="warning",
                progress_logger=progress_logger,
            )
        else:
            _emit_progress(
                f"已检测到 project_id: {project_id}",
                progress_logger=progress_logger,
            )

        credential_data = _prepare_credentials_data(
            credentials,
            project_id,
            mode=mode,
            subscription_tier=subscription_tier,
        )
        _emit_progress(f"临时{mode_label}凭证已生成并保存在内存缓存中", progress_logger=progress_logger)

        test_result = await _test_cached_gemini_credential(
            credential_data,
            proxy_url,
            mode=mode,
            progress_logger=progress_logger,
        )

        return {
            "credentials": credential_data,
            "project_id": project_id,
            "subscription_tier": subscription_tier,
            "test": test_result,
        }
    finally:
        _cleanup_auth_flow_server(state)


async def _build_cached_credential_from_origin_callback_url(
    callback_url: str,
    proxy_url: str,
    mode: str = "geminicli",
    progress_logger: ProgressLogger | None = None,
) -> dict:
    mode = _normalize_credential_mode(mode)
    mode_label = _credential_mode_label(mode)
    base_url = _origin_base_url()
    if not base_url:
        raise RuntimeError("未配置远程服务地址，无法通过远程服务认证回调URL")

    _emit_progress(
        "已从地址栏获取OAuth回调URL，正在发送到远程服务认证",
        progress_logger=progress_logger,
    )
    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(
                f"{base_url}/auth/callback-url",
                json={
                    "callback_url": callback_url,
                    "mode": mode,
                    "persist_credentials": False,
                    "proxy_url": proxy_url or "",
                },
                headers=_origin_auth_headers(),
            )
    except Exception as exc:
        raise RuntimeError(f"将回调URL发送到远程服务失败: {exc}") from exc

    try:
        data = response.json()
    except Exception:
        data = {}

    if response.status_code >= 400:
        detail = data.get("detail") or data.get("error") or response.text
        raise RuntimeError(f"远程服务处理回调URL失败: HTTP {response.status_code}, {detail}")

    credential_data = dict(data.get("credentials") or {})
    if not credential_data:
        raise RuntimeError("远程服务未返回临时凭证")

    project_id = str(data.get("project_id") or credential_data.get("project_id") or "").strip()
    if not project_id:
        raise RuntimeError("远程服务返回的临时凭证缺少 project_id")

    _emit_progress(
        f"远程服务已完成{mode_label}认证，临时凭证已返回",
        progress_logger=progress_logger,
    )
    return {
        "credentials": credential_data,
        "project_id": project_id,
        "subscription_tier": data.get("subscription_tier"),
        "mode": data.get("mode") or mode,
    }


def _authorize_logged_in_account_and_test(
    page,
    email: str,
    password: str,
    two_fa_key: str,
    phone: str,
    phone_code_url: str,
    proxy_url: str,
    mode: str = "geminicli",
    progress_logger: ProgressLogger | None = None,
) -> dict:
    from src.auth import _cleanup_auth_flow_server, create_auth_url

    mode = _normalize_credential_mode(mode)
    mode_label = _credential_mode_label(mode)
    use_origin_callback = _use_origin_callback_api()
    if use_origin_callback:
        _emit_progress(
            f"检测到远程服务配置，将在本地生成{mode_label} OAuth授权链接并把回调URL发送到远程认证",
            progress_logger=progress_logger,
        )
    _emit_progress(f"正在生成{mode_label} OAuth授权链接", progress_logger=progress_logger)
    auth_result = _run_async(create_auth_url(user_session="batch_generate", mode=mode))
    if not auth_result.get("success"):
        raise RuntimeError(auth_result.get("error") or "生成OAuth授权链接失败")

    auth_url = _with_english_locale(
        auth_result["auth_url"],
        {"login_hint": email, "authuser": "0"},
    )
    state = auth_result["state"]
    try:
        _emit_progress("OAuth授权链接已生成，正在使用当前已登录账号打开", progress_logger=progress_logger)
        _install_oauth_callback_capture(page, progress_logger=progress_logger)
        _open_oauth_auth_url(page, auth_url, state, progress_logger=progress_logger)

        callback_url = _wait_for_oauth_callback(
            page,
            state,
            email,
            password,
            two_fa_key,
            timeout_seconds=180,
            progress_logger=progress_logger,
        )
        _emit_progress(
            f"已从地址栏获取OAuth回调URL: {_redact_query_value(callback_url, {'code'})}",
            progress_logger=progress_logger,
        )

        if use_origin_callback:
            result = _run_async(
                _build_cached_credential_from_origin_callback_url(
                    callback_url,
                    proxy_url,
                    mode=mode,
                    progress_logger=progress_logger,
                )
            )
        else:
            result = _run_async(
                _build_cached_credential_from_callback_url(
                    callback_url,
                    proxy_url,
                    mode=mode,
                    progress_logger=progress_logger,
                )
            )

        if result.get("credentials") and not result.get("test"):
            result["test"] = _run_async(
                _test_cached_gemini_credential(
                    result["credentials"],
                    proxy_url,
                    mode=mode,
                    progress_logger=progress_logger,
                )
            )
    except AccountUnusableError as exc:
        _cleanup_auth_flow_server(state)
        return {
            "status": exc.status,
            "error": exc.message,
            "account_unusable": True,
            "validation": {
                "status": exc.status,
                "error": exc.message,
                "account_unusable": True,
            },
        }
    except Exception:
        _cleanup_auth_flow_server(state)
        raise
    finally:
        if use_origin_callback:
            _cleanup_auth_flow_server(state)

    validation_url = (result.get("test") or {}).get("validation_url")
    if validation_url:
        validation_result = _handle_validation_url(
            page,
            validation_url,
            phone,
            phone_code_url,
            progress_logger=progress_logger,
        )
        result["validation"] = validation_result

        if validation_result.get("account_unusable"):
            result["account_unusable"] = True
        elif validation_result.get("status") == "success" and result.get("credentials"):
            _emit_progress(
                "账号验证已完成，正在复测 gemini-2.5-flash",
                progress_logger=progress_logger,
            )
            retest_result = _run_async(
                _test_cached_gemini_credential(
                    result["credentials"],
                    proxy_url,
                    mode=mode,
                    progress_logger=progress_logger,
                )
            )
            result["test_before_validation"] = result.get("test")
            result["test_after_validation"] = retest_result
            result["test"] = retest_result
        else:
            result["validation_failed"] = True
            result["status"] = validation_result.get("status") or "validation_failed"
            _emit_progress(
                f"账号验证未完成: status={result['status']}",
                level="warning",
                progress_logger=progress_logger,
            )

    return result


def get_2fa_code(
    two_fa_key: str,
    progress_logger: ProgressLogger | None = None,
) -> str:
    if not str(two_fa_key or "").strip():
        return ""

    secret = _extract_2fa_secret(two_fa_key)
    if secret:
        try:
            _emit_progress(
                f"正在本地解析2FA验证码: secret={_mask_value(_normalize_totp_secret(secret))}",
                progress_logger=progress_logger,
            )
            code = _generate_totp_code(secret)
            if code:
                _emit_progress("2FA验证码本地解析成功", progress_logger=progress_logger)
                return code
        except Exception as exc:
            _emit_progress(
                f"本地解析2FA验证码失败，准备尝试2fa.run: {exc}",
                level="warning",
                progress_logger=progress_logger,
            )
    else:
        _emit_progress(
            "未能从2FA输入中解析出密钥，准备尝试2fa.run链接",
            level="warning",
            progress_logger=progress_logger,
        )

    urls = _build_2fa_request_urls(two_fa_key)
    if not urls:
        return ""

    try:
        with httpx.Client(timeout=20.0, headers=_2FA_HEADERS, follow_redirects=True) as client:
            for url in urls:
                _emit_progress(
                    f"正在请求2fa.run解析页面: {_redact_2fa_url(url)}",
                    progress_logger=progress_logger,
                )
                response = client.get(url)
                if response.status_code == 403:
                    _emit_progress(
                        "2fa.run返回403，正在执行验证接口后重试",
                        level="warning",
                        progress_logger=progress_logger,
                    )
                    client.get(_2FA_BYPASS_URL)
                    response = client.get(url)

                if response.status_code != 200:
                    _emit_progress(
                        f"2fa.run解析页面返回状态码: {response.status_code}",
                        level="warning",
                        progress_logger=progress_logger,
                    )
                    continue

                match = re.search(r'<span class="codetxt">(\d+)</span>', response.text)
                if match:
                    _emit_progress("2fa.run验证码解析成功", progress_logger=progress_logger)
                    return match.group(1)

                _emit_progress(
                    "2fa.run响应中未找到验证码",
                    level="warning",
                    progress_logger=progress_logger,
                )
    except Exception as exc:
        _emit_progress(
            f"获取2FA验证码失败: {exc}",
            level="warning",
            progress_logger=progress_logger,
        )

    return ""


def _parse_playwright_proxy(proxy_url: str) -> dict | None:
    proxy_url = str(proxy_url or "").strip()
    if not proxy_url:
        return None

    parsed = urlparse(proxy_url)
    if parsed.scheme not in {"http", "https", "socks5"}:
        return None

    rest = proxy_url.split("://", 1)[1] if "://" in proxy_url else ""
    parts = rest.split(":", 3)
    if len(parts) == 4 and "@" not in rest and all(parts):
        host, port, username, password = parts
        return {
            "server": f"{parsed.scheme}://{host}:{port}",
            "username": username,
            "password": password,
            "bypass": "localhost,127.0.0.1,::1",
        }

    if not parsed.hostname:
        return None

    server = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port:
        server += f":{parsed.port}"

    proxy = {"server": server, "bypass": "localhost,127.0.0.1,::1"}
    if parsed.username:
        proxy["username"] = unquote(parsed.username)
    if parsed.password:
        proxy["password"] = unquote(parsed.password)
    return proxy


def _click_first(page, selectors: list[str], timeout: int = 5000) -> str | None:
    for selector in selectors:
        try:
            page.locator(selector).first.click(timeout=timeout)
            return selector
        except Exception:
            continue
    return None


def _click_by_accessible_name(
    page,
    texts: list[str],
    roles: tuple[str, ...] = ("button", "link"),
    timeout: int = 800,
) -> str | None:
    for text in texts:
        text = str(text or "").strip()
        if not text:
            continue

        exact_pattern = re.compile(rf"^\s*{re.escape(text)}\s*$", re.IGNORECASE)
        partial_pattern = re.compile(re.escape(text), re.IGNORECASE)
        for role in roles:
            for pattern in (exact_pattern, partial_pattern):
                try:
                    locator = page.get_by_role(role, name=pattern).first
                    if locator.count() < 1:
                        continue
                    locator.scroll_into_view_if_needed(timeout=timeout)
                    locator.click(timeout=timeout)
                    return f"role={role}, name~={text}"
                except Exception:
                    continue

    return None


def _click_first_visible(
    page,
    selectors: list[str],
    visible_timeout: int = 200,
    click_timeout: int = 800,
) -> str | None:
    for selector in selectors:
        locator = page.locator(selector).first
        try:
            if locator.count() < 1:
                continue
        except Exception:
            continue

        try:
            if not locator.is_visible(timeout=visible_timeout):
                continue
        except Exception:
            continue

        try:
            locator.scroll_into_view_if_needed(timeout=visible_timeout)
        except Exception:
            pass

        try:
            locator.click(timeout=click_timeout)
            return selector
        except Exception:
            continue
    return None


def _fill_first(page, selectors: list[str], value: str, timeout: int = 5000) -> str | None:
    for selector in selectors:
        try:
            page.locator(selector).first.fill(value, timeout=timeout)
            return selector
        except Exception:
            continue
    return None


def _submit_totp_if_needed(
    page,
    two_fa_key: str,
    progress_logger: ProgressLogger | None = None,
) -> None:
    if not str(two_fa_key or "").strip():
        _emit_progress("未提供2FA密钥，跳过2FA自动填充", progress_logger=progress_logger)
        return

    try:
        _emit_progress("正在检查是否出现2FA验证页面", progress_logger=progress_logger)
        page.wait_for_timeout(300)
        if _was_totp_submitted_recently(page):
            return
        two_step_prompt = _page_has_two_step_verification_prompt(page)
        if two_step_prompt:
            _emit_progress(
                "检测到两步验证方式选择页，正在尝试切换到 Google Authenticator 验证码输入",
                progress_logger=progress_logger,
            )
            _click_totp_challenge_option_if_present(page, progress_logger=progress_logger)

        has_totp = False
        wait_deadline = time.monotonic() + 8
        while time.monotonic() < wait_deadline:
            has_totp = page.locator("#totpPin, input[name='totpPin'], input[type='tel']").count() > 0
            if has_totp:
                break
            if not two_step_prompt:
                break
            page.wait_for_timeout(400)

        if not has_totp and not two_step_prompt:
            page_text = page.locator("body").inner_text(timeout=3000).lower()
            has_totp = any(
                marker in page_text
                for marker in (
                    "两步验证",
                    "two-step verification",
                    "two-factor authentication",
                    "2fa",
                    "verification code",
                )
            )
        if not has_totp:
            if two_step_prompt:
                _emit_progress(
                    "已识别两步验证方式选择页，但暂未出现验证码输入框",
                    level="warning",
                    progress_logger=progress_logger,
                )
            else:
                _emit_progress("未检测到2FA验证页面", progress_logger=progress_logger)
            return

        _emit_progress("检测到2FA，正在获取验证码", progress_logger=progress_logger)
        code = get_2fa_code(two_fa_key, progress_logger=progress_logger)
        if not code:
            _emit_progress(
                "检测到2FA，但未获取到验证码",
                level="warning",
                progress_logger=progress_logger,
            )
            return

        _emit_progress("正在填充2FA验证码", progress_logger=progress_logger)
        selector = _fill_first(
            page,
            ["#totpPin", "input[name='totpPin']", "input[type='tel']"],
            code,
            timeout=8000,
        )
        if selector:
            _emit_progress(f"2FA验证码已填充，输入框: {selector}", progress_logger=progress_logger)
            clicked_selector = _click_first(
                page,
                [
                    "#totpNext button",
                    "button:has-text('Next')",
                    "button:has-text('下一步')",
                ],
                timeout=8000,
            )
            if clicked_selector:
                _mark_totp_submitted(page)
                _emit_progress(
                    f"2FA验证码已提交，按钮: {clicked_selector}",
                    progress_logger=progress_logger,
                )
                page.wait_for_timeout(1500)
                _click_later_if_present(page, progress_logger=progress_logger)
            else:
                _emit_progress(
                    "2FA验证码已填充，但未找到下一步按钮",
                    level="warning",
                    progress_logger=progress_logger,
                )
        else:
            _emit_progress(
                "未找到可填充的2FA验证码输入框",
                level="warning",
                progress_logger=progress_logger,
            )
    except Exception as exc:
        _emit_progress(
            f"处理2FA失败: {exc}",
            level="warning",
            progress_logger=progress_logger,
        )


def run_google_login(
    email: str,
    password: str,
    two_fa_key: str = "",
    phone: str = "",
    phone_code_url: str = "",
    proxy_url: str = "",
    mode: str = "geminicli",
    keep_open_seconds: int = 600,
    progress_logger: ProgressLogger | None = None,
) -> dict:
    mode = _normalize_credential_mode(mode)
    mode_label = _credential_mode_label(mode)
    _emit_progress("正在检查浏览器自动化依赖", progress_logger=progress_logger)
    ensure_browser_automation_available()

    from patchright.sync_api import sync_playwright

    email = str(email or "").strip()
    password = str(password or "")
    proxy = _parse_playwright_proxy(proxy_url)
    chrome_cdp_url = _batch_generate_chrome_cdp_url()
    login_url = (
        "https://accounts.google.com/signin/v2/identifier"
        "?service=accountsettings&continue=https%3A%2F%2Fmyaccount.google.com%2F"
    )

    _emit_progress(
        f"启动{'本机Chrome CDP' if chrome_cdp_url else 'Chrome无痕'}登录并生成{mode_label}凭证: email={email}, "
        f"proxy={'enabled' if proxy else 'disabled'}, phone={'set' if phone else '-'}, "
        f"phone_code_url={'set' if phone_code_url else '-'}, "
        f"2fa={'set' if two_fa_key else '-'}",
        progress_logger=progress_logger,
    )

    with sync_playwright() as playwright:
        result = {}
        context = None
        page = None
        close_browser = True
        close_context = False
        if chrome_cdp_url:
            _emit_progress(f"正在连接本机Chrome CDP: {chrome_cdp_url}", progress_logger=progress_logger)
            browser = playwright.chromium.connect_over_cdp(chrome_cdp_url)
            close_browser = False
            if proxy:
                _emit_progress(
                    "本机Chrome CDP模式下代理需在启动Chrome时配置，任务内代理参数可能无法生效",
                    level="warning",
                    progress_logger=progress_logger,
                )
        else:
            _emit_progress("正在启动Chrome浏览器", progress_logger=progress_logger)
            browser = playwright.chromium.launch(
                channel="chrome",
                headless=False,
                args=[
                    "--incognito",
                    "--window-size=1280,900",
                    "--window-position=120,80",
                    "--lang=en-US",
                    "--accept-lang=en-US,en",
                ],
            )

        _emit_progress("正在创建无痕浏览器上下文", progress_logger=progress_logger)
        context_options = {
            "no_viewport": True,
            "locale": "en-US",
            "extra_http_headers": {"Accept-Language": "en-US,en;q=0.9"},
        }
        if proxy:
            context_options["proxy"] = proxy
        try:
            context = browser.new_context(**context_options)
            close_context = True
        except Exception as exc:
            if not chrome_cdp_url or not browser.contexts:
                raise
            _emit_progress(
                f"CDP模式创建无痕上下文失败，改用本机Chrome默认上下文: {exc}",
                level="warning",
                progress_logger=progress_logger,
            )
            context = browser.contexts[0]
            try:
                context.set_extra_http_headers({"Accept-Language": "en-US,en;q=0.9"})
            except Exception:
                pass
        _install_english_navigation_guard(context, progress_logger=progress_logger)
        page = context.new_page()

        try:
            _emit_progress("正在打开Google登录页面", progress_logger=progress_logger)
            _goto_english(page, login_url, wait_until="domcontentloaded", timeout=60000)

            _emit_progress(f"正在填充邮箱: {email}", progress_logger=progress_logger)
            email_selector = _fill_first(
                page,
                ["#identifierId", "input[type='email']"],
                email,
                timeout=30000,
            )
            if email_selector:
                _emit_progress(f"邮箱已填充，输入框: {email_selector}", progress_logger=progress_logger)
            else:
                _emit_progress(
                    "未找到邮箱输入框",
                    level="warning",
                    progress_logger=progress_logger,
                )
            email_next_selector = _click_first(
                page,
                ["#identifierNext button", "button:has-text('Next')", "button:has-text('下一步')"],
                timeout=10000,
            )
            if email_next_selector:
                _emit_progress(
                    f"邮箱下一步已点击，按钮: {email_next_selector}",
                    progress_logger=progress_logger,
                )
            else:
                _emit_progress(
                    "未找到邮箱下一步按钮",
                    level="warning",
                    progress_logger=progress_logger,
                )

            _emit_progress("正在填充密码", progress_logger=progress_logger)
            password_selector = _fill_first(
                page,
                ["input[type='password']", "#password input"],
                password,
                timeout=30000,
            )
            if password_selector:
                _emit_progress(f"密码已填充，输入框: {password_selector}", progress_logger=progress_logger)
            else:
                _emit_progress(
                    "未找到密码输入框",
                    level="warning",
                    progress_logger=progress_logger,
                )
            password_next_selector = _click_first(
                page,
                ["#passwordNext button", "button:has-text('Next')", "button:has-text('下一步')"],
                timeout=10000,
            )
            if password_next_selector:
                _emit_progress(
                    f"密码下一步已点击，按钮: {password_next_selector}",
                    progress_logger=progress_logger,
                )
            else:
                _emit_progress(
                    "未找到密码下一步按钮",
                    level="warning",
                    progress_logger=progress_logger,
                )

            page.wait_for_timeout(1500)
            _click_later_if_present(page, progress_logger=progress_logger)
            _submit_totp_if_needed(page, two_fa_key, progress_logger=progress_logger)
            _emit_progress(f"已提交Google登录信息: email={email}", progress_logger=progress_logger)
            page.wait_for_timeout(3000)
            _click_later_if_present(page, progress_logger=progress_logger)

            result = _authorize_logged_in_account_and_test(
                page,
                email=email,
                password=password,
                two_fa_key=two_fa_key,
                phone=phone,
                phone_code_url=phone_code_url,
                proxy_url=proxy_url,
                mode=mode,
                progress_logger=progress_logger,
            )
            if (result or {}).get("account_unusable"):
                validation_status = str(
                    ((result or {}).get("validation") or {}).get("status")
                    or (result or {}).get("status")
                    or ""
                ).strip()
                if validation_status in {"phone_rate_limited", "service_unavailable"}:
                    _emit_progress(
                        "当前账号不可用，Chrome窗口将立即关闭并继续下一个账号",
                        level="warning",
                        progress_logger=progress_logger,
                    )
                else:
                    _emit_progress(
                        "当前账号不可用，Chrome窗口将保持打开 3 秒后关闭",
                        level="warning",
                        progress_logger=progress_logger,
                    )
                    page.wait_for_timeout(3000)
            else:
                _emit_progress(
                    f"Chrome窗口将保持打开 {max(1, keep_open_seconds)} 秒",
                    progress_logger=progress_logger,
                )
                page.wait_for_timeout(max(1, keep_open_seconds) * 1000)
        except Exception as exc:
            error_text = str(exc).strip() or type(exc).__name__
            result["status"] = "automation_failed"
            result["error"] = error_text
            _emit_progress(
                f"Google登录自动化异常: email={email}, error={error_text}",
                level="warning",
                progress_logger=progress_logger,
            )
            try:
                page.wait_for_timeout(30000)
            except Exception:
                pass
        finally:
            _emit_progress("正在关闭浏览器上下文", progress_logger=progress_logger)
            if page is not None:
                try:
                    page.close(run_before_unload=False)
                except Exception:
                    pass
            if close_context and context is not None:
                try:
                    context.close()
                except Exception:
                    pass
            if close_browser:
                try:
                    browser.close(reason="batch_generate_done")
                except Exception:
                    pass
            _emit_progress("Chrome登录任务已结束", progress_logger=progress_logger)

        return result
