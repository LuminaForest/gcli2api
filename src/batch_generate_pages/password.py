"""Google password page handling for batch generation."""

from collections.abc import Callable


ProgressLogger = Callable[[str, str], None]
EmitProgress = Callable[[str, str, ProgressLogger | None], None]
FillFirst = Callable[[object, list[str], str, int], str | None]
ClickNextButton = Callable[[object, list[str] | None, str, int], str | None]

PASSWORD_INPUT_SELECTORS = [
    "input[type='password']",
    "#password input",
]
PASSWORD_NEXT_SELECTORS = [
    "#passwordNext button",
    "#passwordNext [role='button']",
    "#passwordNext",
]


def is_password_page(page) -> bool:
    for selector in PASSWORD_INPUT_SELECTORS:
        try:
            if page.locator(selector).first.is_visible(timeout=200):
                return True
        except Exception:
            continue
    return False


def submit_password_page(
    page,
    password: str,
    *,
    fill_first: FillFirst,
    click_next_button: ClickNextButton,
    emit_progress: EmitProgress,
    progress_logger: ProgressLogger | None = None,
    log_prefix: str = "",
    fill_timeout: int = 30000,
    next_timeout: int = 10000,
) -> bool:
    prefix = str(log_prefix or "").strip()
    label = f"{prefix}密码" if prefix else "密码"

    emit_progress(f"正在填充{label}", "info", progress_logger)
    password_selector = fill_first(
        page,
        PASSWORD_INPUT_SELECTORS,
        password,
        fill_timeout,
    )
    if password_selector:
        emit_progress(f"{label}已填充，输入框: {password_selector}", "info", progress_logger)
    else:
        emit_progress(f"未找到{label}输入框", "warning", progress_logger)

    password_next_selector = click_next_button(
        page,
        PASSWORD_NEXT_SELECTORS,
        ", ".join(PASSWORD_INPUT_SELECTORS),
        next_timeout,
    )
    if password_next_selector:
        emit_progress(f"{label}下一步已点击，按钮: {password_next_selector}", "info", progress_logger)
    else:
        emit_progress(f"未找到{label}下一步按钮", "warning", progress_logger)

    return bool(password_selector)


def submit_password_page_if_present(
    page,
    password: str,
    *,
    fill_first: FillFirst,
    click_next_button: ClickNextButton,
    emit_progress: EmitProgress,
    progress_logger: ProgressLogger | None = None,
    log_prefix: str = "",
    fill_timeout: int = 3000,
    next_timeout: int = 5000,
) -> bool:
    if not str(password or ""):
        return False
    if not is_password_page(page):
        return False

    try:
        prefix = str(log_prefix or "").strip()
        message = f"{prefix}检测到密码验证，正在填充密码" if prefix else "检测到密码验证，正在填充密码"
        emit_progress(message, "info", progress_logger)
        return submit_password_page(
            page,
            password,
            fill_first=fill_first,
            click_next_button=click_next_button,
            emit_progress=emit_progress,
            progress_logger=progress_logger,
            log_prefix=log_prefix,
            fill_timeout=fill_timeout,
            next_timeout=next_timeout,
        )
    except Exception as exc:
        prefix = str(log_prefix or "").strip()
        message = f"{prefix}处理密码验证失败: {exc}" if prefix else f"处理密码验证失败: {exc}"
        emit_progress(message, "warning", progress_logger)
        return False
