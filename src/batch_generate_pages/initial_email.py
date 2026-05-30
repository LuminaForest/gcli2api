"""Initial Google email page handling for batch generation."""

from collections.abc import Callable


ProgressLogger = Callable[[str, str], None]
EmitProgress = Callable[[str, str, ProgressLogger | None], None]
FillFirst = Callable[[object, list[str], str, int], str | None]
ClickNextButton = Callable[[object, list[str] | None, str, int], str | None]
WaitBeforePageJudgement = Callable[[object, str, ProgressLogger | None], int]

INITIAL_EMAIL_PAGE_LABEL = "初始登录邮箱页"
INITIAL_EMAIL_INPUT_SELECTORS = [
    "#identifierId",
    "input[type='email']",
]
INITIAL_EMAIL_NEXT_SELECTORS = [
    "#identifierNext button",
    "#identifierNext [role='button']",
    "#identifierNext",
    "button[jsname='LgbsSe']",
]


def submit_initial_email_page(
    page,
    email: str,
    *,
    fill_first: FillFirst,
    click_next_button: ClickNextButton,
    wait_before_page_judgement: WaitBeforePageJudgement,
    emit_progress: EmitProgress,
    progress_logger: ProgressLogger | None = None,
) -> None:
    wait_before_page_judgement(
        page,
        INITIAL_EMAIL_PAGE_LABEL,
        progress_logger=progress_logger,
    )

    emit_progress(f"正在填充邮箱: {email}", "info", progress_logger)
    email_selector = fill_first(
        page,
        INITIAL_EMAIL_INPUT_SELECTORS,
        email,
        30000,
    )
    if email_selector:
        emit_progress(f"邮箱已填充，输入框: {email_selector}", "info", progress_logger)
    else:
        emit_progress("未找到邮箱输入框", "warning", progress_logger)

    email_next_selector = click_next_button(
        page,
        INITIAL_EMAIL_NEXT_SELECTORS,
        ", ".join(INITIAL_EMAIL_INPUT_SELECTORS),
        10000,
    )
    if email_next_selector:
        emit_progress(f"邮箱下一步已点击，按钮: {email_next_selector}", "info", progress_logger)
    else:
        emit_progress("未找到邮箱下一步按钮", "warning", progress_logger)
