"""
Batch generation panel routes.
"""

import config as app_config
import asyncio
import re
import time
import uuid
from threading import Lock

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import JSONResponse

from log import log
from src.auth import save_credentials
from src.batch_generate_login import ensure_browser_automation_available, run_google_login
from src.google_oauth_api import Credentials
from src.models import BatchGenerateLoginRequest
from src.proxy_config import generate_proxy_url_from_generator
from src.storage_adapter import get_storage_adapter
from src.utils import verify_panel_token
from .creds import configure_preview_channel_common
from .utils import validate_mode


router = APIRouter(prefix="/batch-generate", tags=["batch-generate"])

_LOGIN_TASKS: dict[str, dict] = {}
_LOGIN_TASK_LOCK = Lock()
_LOGIN_TASK_LIMIT = 50
_LOGIN_TASK_LOG_LIMIT = 500
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


def _validate_email(email: str) -> bool:
    return re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", email) is not None


def _credential_management_label(mode: str) -> str:
    return "AG凭证管理" if mode == "antigravity" else "GCLI凭证管理"


def _cleanup_login_tasks_locked() -> None:
    if len(_LOGIN_TASKS) <= _LOGIN_TASK_LIMIT:
        return

    task_ids = sorted(_LOGIN_TASKS, key=lambda task_id: _LOGIN_TASKS[task_id].get("updated_at", 0))
    for task_id in task_ids[: len(_LOGIN_TASKS) - _LOGIN_TASK_LIMIT]:
        _LOGIN_TASKS.pop(task_id, None)


def _create_login_task(email: str, mode: str) -> str:
    task_id = uuid.uuid4().hex
    now = time.time()
    with _LOGIN_TASK_LOCK:
        _LOGIN_TASKS[task_id] = {
            "task_id": task_id,
            "email": email,
            "mode": mode,
            "status": "queued",
            "account_unusable": False,
            "failure_reason": "",
            "failure_error": "",
            "final_test_status_code": 0,
            "credential_persisted": False,
            "save_skipped_reason": "",
            "saved_credential_filename": "",
            "saved_proxy_name": "",
            "saved_user_email": "",
            "saved_preview_enabled": False,
            "seq": 0,
            "logs": [],
            "created_at": now,
            "updated_at": now,
        }
        _cleanup_login_tasks_locked()
    return task_id


def _append_login_task_log(task_id: str, message: str, level: str = "info") -> None:
    with _LOGIN_TASK_LOCK:
        task = _LOGIN_TASKS.get(task_id)
        if not task:
            return

        task["seq"] += 1
        task["updated_at"] = time.time()
        task["logs"].append(
            {
                "seq": task["seq"],
                "level": level,
                "message": message,
                "created_at": task["updated_at"],
            }
        )
        if len(task["logs"]) > _LOGIN_TASK_LOG_LIMIT:
            task["logs"] = task["logs"][-_LOGIN_TASK_LOG_LIMIT:]


def _set_login_task_status(task_id: str, status: str) -> None:
    with _LOGIN_TASK_LOCK:
        task = _LOGIN_TASKS.get(task_id)
        if not task:
            return
        task["status"] = status
        task["updated_at"] = time.time()


def _classify_login_failure_reason(status: str, error: str = "") -> str:
    status = str(status or "").strip()
    error_text = str(error or "").lower()
    if status == "automation_failed" and any(marker in error_text for marker in _PAGE_LOAD_FAILURE_MARKERS):
        return "page_load_failed"
    return status or "credential_missing"


def _set_login_task_failure(task_id: str, failure_reason: str, failure_error: str = "") -> None:
    with _LOGIN_TASK_LOCK:
        task = _LOGIN_TASKS.get(task_id)
        if not task:
            return
        task["failure_reason"] = failure_reason
        task["failure_error"] = failure_error
        task["status"] = "failed"
        task["updated_at"] = time.time()


def _set_login_task_test_result(task_id: str, test_result: dict) -> None:
    with _LOGIN_TASK_LOCK:
        task = _LOGIN_TASKS.get(task_id)
        if not task:
            return
        test_result = dict(test_result or {})
        task["final_test_status_code"] = int(test_result.get("status_code") or 0)
        task["save_skipped_reason"] = ""
        task["updated_at"] = time.time()


def _set_login_task_save_skipped(task_id: str, reason: str) -> None:
    with _LOGIN_TASK_LOCK:
        task = _LOGIN_TASKS.get(task_id)
        if not task:
            return
        task["credential_persisted"] = False
        task["save_skipped_reason"] = str(reason or "").strip()
        task["updated_at"] = time.time()


def _set_login_task_cached_credential(task_id: str, result: dict) -> None:
    if (result or {}).get("account_unusable") or (result or {}).get("validation_failed"):
        return

    credential_data = (result or {}).get("credentials")
    if not credential_data:
        return

    with _LOGIN_TASK_LOCK:
        task = _LOGIN_TASKS.get(task_id)
        if not task:
            return
        task["cached_credential"] = credential_data
        task["cached_credential_meta"] = {
            "project_id": result.get("project_id"),
            "subscription_tier": result.get("subscription_tier"),
            "test": result.get("test"),
            "cached_at": time.time(),
        }
        task["updated_at"] = time.time()


def _set_login_task_saved_credential(task_id: str, saved_result: dict) -> None:
    with _LOGIN_TASK_LOCK:
        task = _LOGIN_TASKS.get(task_id)
        if not task:
            return
        task["credential_persisted"] = True
        task["save_skipped_reason"] = ""
        task["saved_credential_filename"] = saved_result.get("filename") or ""
        task["saved_proxy_name"] = saved_result.get("proxy_name") or ""
        task["saved_user_email"] = saved_result.get("user_email") or ""
        task["saved_preview_enabled"] = bool(saved_result.get("preview_enabled"))
        task["updated_at"] = time.time()


def _sort_proxy_pool(proxy_pool: list[dict[str, str]]) -> list[dict[str, str]]:
    def sort_key(item: dict[str, str]):
        name = str(item.get("name", ""))
        if name.startswith("proxy_"):
            suffix = name.removeprefix("proxy_")
            if suffix.isdigit():
                return (0, int(suffix), name)
        return (1, 0, name)

    return sorted(proxy_pool, key=sort_key)


def _next_proxy_pool_name(proxy_pool: list[dict[str, str]]) -> str:
    max_seq = 0
    for item in proxy_pool:
        name = str((item or {}).get("name") or "").strip()
        if not name.startswith("proxy_"):
            continue
        suffix = name.removeprefix("proxy_")
        if suffix.isdigit():
            max_seq = max(max_seq, int(suffix))
    return f"proxy_{max_seq + 1}"


async def _create_proxy_pool_entry() -> dict:
    generator_url = str(await app_config.get_credential_proxy_generator_url() or "").strip()
    if not generator_url:
        raise RuntimeError("未配置凭证代理生成链接，无法为新凭证创建专属代理")

    storage_adapter = await get_storage_adapter()
    proxy_pool = list(await app_config.get_proxy_pool_config())
    proxy_name = _next_proxy_pool_name(proxy_pool)
    proxy_url = await generate_proxy_url_from_generator(generator_url, scheme="http")
    if not proxy_url:
        raise RuntimeError("生成新的专属代理失败，请检查凭证代理生成链接")

    updated_pool = _sort_proxy_pool([*proxy_pool, {"name": proxy_name, "url": proxy_url}])
    if not await storage_adapter.set_config("proxy_pool", updated_pool):
        raise RuntimeError("保存新的代理池配置失败")

    await app_config.reload_config()
    return {"proxy_name": proxy_name, "proxy_url": proxy_url}


async def _persist_batch_generated_credential(
    result: dict,
    email: str,
    progress_logger,
    mode: str,
) -> dict:
    mode = validate_mode(mode)
    management_label = _credential_management_label(mode)
    credential_data = dict((result or {}).get("credentials") or {})
    project_id = str((result or {}).get("project_id") or credential_data.get("project_id") or "").strip()
    subscription_tier = str((result or {}).get("subscription_tier") or "").strip() or None
    if not credential_data:
        raise RuntimeError(f"临时凭证不存在，无法保存到 {management_label}")
    if not project_id:
        raise RuntimeError(f"临时凭证缺少 project_id，无法保存到 {management_label}")

    progress_logger(f"gemini-2.5-flash 返回 200，正在保存凭证到 {management_label}")
    saved_filename = await save_credentials(
        Credentials.from_dict(credential_data),
        project_id,
        mode=mode,
        subscription_tier=subscription_tier,
    )

    storage_adapter = await get_storage_adapter()
    updated = await storage_adapter.update_credential_state(
        saved_filename,
        {
            "user_email": email,
            "disabled": False,
            "error_codes": [],
            "error_messages": {},
            **({"tier": subscription_tier} if subscription_tier else {}),
        },
        mode=mode,
    )
    if not updated:
        raise RuntimeError(f"保存凭证状态失败: {saved_filename}")
    progress_logger(f"凭证已保存到 {management_label}: {saved_filename}")

    proxy_info = await _create_proxy_pool_entry()
    progress_logger(f"已在代理池创建新代理: {proxy_info['proxy_name']}")

    updated = await storage_adapter.update_credential_state(
        saved_filename,
        {"proxy_name": proxy_info["proxy_name"], "user_email": email},
        mode=mode,
    )
    if not updated:
        raise RuntimeError(f"绑定专属代理失败: {saved_filename}")
    progress_logger(f"已将代理 {proxy_info['proxy_name']} 绑定到凭证 {saved_filename}")

    preview_enabled = False
    if mode == "geminicli":
        preview_result = await configure_preview_channel_common(saved_filename, mode="geminicli")
        if not preview_result.get("success"):
            error_message = str(preview_result.get("error") or preview_result.get("message") or "开启 Preview 失败")
            raise RuntimeError(f"开启 Preview 失败: {error_message}")
        preview_enabled = True
        progress_logger(f"Preview 已开启: {saved_filename}")
    else:
        progress_logger(f"{management_label} 不需要开启 Preview，已跳过")

    updated = await storage_adapter.update_credential_state(
        saved_filename,
        {"user_email": email},
        mode=mode,
    )
    if not updated:
        raise RuntimeError(f"写入账号邮箱失败: {saved_filename}")
    progress_logger(f"{management_label} 已显示邮箱: {email}")

    return {
        "filename": saved_filename,
        "proxy_name": proxy_info["proxy_name"],
        "proxy_url": proxy_info["proxy_url"],
        "user_email": email,
        "preview_enabled": preview_enabled,
    }


async def _run_login_task(
    task_id: str,
    email: str,
    password: str,
    two_fa_key: str,
    phone: str,
    phone_code_url: str,
    proxy_url: str,
    mode: str,
) -> None:
    mode = validate_mode(mode)
    management_label = _credential_management_label(mode)

    def progress_logger(message: str, level: str = "info") -> None:
        _append_login_task_log(task_id, message, level)

    _set_login_task_status(task_id, "running")
    _append_login_task_log(task_id, "后台登录任务开始执行")

    try:
        result = await asyncio.to_thread(
            run_google_login,
            email=email,
            password=password,
            two_fa_key=two_fa_key,
            phone=phone,
            phone_code_url=phone_code_url,
            proxy_url=proxy_url,
            mode=mode,
            keep_open_seconds=3,
            progress_logger=progress_logger,
        )
        if (result or {}).get("account_unusable"):
            validation_status = str(
                ((result or {}).get("validation") or {}).get("status")
                or (result or {}).get("status")
                or "account_unusable"
            )
            unusable_message = "账号验证页面显示二维码，该账号不可用"
            if validation_status == "phone_option_missing":
                unusable_message = "验证方式选择页未提供 Verify your phone number，该账号不可用"
            elif validation_status == "phone_rate_limited":
                unusable_message = "当前手机号异常：This phone number has already been used too many times for verification"
            elif validation_status == "service_unavailable":
                unusable_message = "页面提示 Entire service unavailable，该账号不可用"
            _append_login_task_log(task_id, f"{unusable_message}，准备处理下一行账号", "error")
            with _LOGIN_TASK_LOCK:
                task = _LOGIN_TASKS.get(task_id)
                if task:
                    task["account_unusable"] = True
                    task["failure_reason"] = validation_status
                    task["status"] = "unusable"
                    task["updated_at"] = time.time()
            return

        _set_login_task_cached_credential(task_id, result)
        if (result or {}).get("validation_failed"):
            failure_reason = str((result or {}).get("status") or "validation_failed")
            _set_login_task_failure(task_id, failure_reason)
            _append_login_task_log(task_id, f"后台登录任务失败: 账号验证未完成 ({failure_reason})", "error")
            return

        if not (result or {}).get("credentials"):
            error = str((result or {}).get("error") or "未生成临时凭证")
            failure_reason = _classify_login_failure_reason(
                str((result or {}).get("status") or "credential_missing"),
                error,
            )
            _set_login_task_failure(task_id, failure_reason, error)
            _append_login_task_log(task_id, f"后台登录任务失败: {error}", "error")
            return

        test_info = (result or {}).get("test") or {}
        test_status_code = int(test_info.get("status_code") or 0)
        _set_login_task_test_result(task_id, test_info)
        if test_status_code == 200:
            try:
                saved_result = await _persist_batch_generated_credential(result, email, progress_logger, mode=mode)
            except Exception as exc:
                error = str(exc).strip() or f"保存凭证到 {management_label} 失败"
                _set_login_task_failure(task_id, "credential_persist_failed", error)
                _append_login_task_log(task_id, f"后台登录任务失败: {error}", "error")
                return
            _set_login_task_saved_credential(task_id, saved_result)
            update_parts = [
                f"filename={saved_result['filename']}",
                f"proxy={saved_result['proxy_name']}",
            ]
            if saved_result.get("preview_enabled"):
                update_parts.append("preview=ON")
            update_parts.append(f"email={saved_result['user_email']}")
            _append_login_task_log(
                task_id,
                f"{management_label}已更新: " + ", ".join(update_parts),
            )
        else:
            _set_login_task_save_skipped(task_id, "model_test_not_200")
            _append_login_task_log(
                task_id,
                f"模型测试状态码为 {test_status_code or '-'}，跳过保存到 {management_label}",
                "warning",
            )

        _append_login_task_log(task_id, "临时凭证已写入后台内存缓存")
        _set_login_task_status(task_id, "completed")
        _append_login_task_log(task_id, "后台登录任务已完成")
    except Exception as exc:
        error = str(exc)
        failure_reason = _classify_login_failure_reason("automation_failed", error)
        _set_login_task_failure(task_id, failure_reason, error)
        _append_login_task_log(task_id, f"后台登录任务失败: {error}", "error")
        log.exception(f"[BATCH_GENERATE] 后台登录任务失败: email={email}")


@router.post("/login-first")
async def login_first_account(
    request: BatchGenerateLoginRequest,
    background_tasks: BackgroundTasks,
    token: str = Depends(verify_panel_token),
):
    email = request.email.strip()
    password = request.password
    line_number = max(1, int(request.line_number or 1))
    line_label = f"第{line_number}行"
    mode = validate_mode(request.mode or "geminicli")

    if not _validate_email(email):
        raise HTTPException(status_code=400, detail=f"{line_label}邮箱格式不正确")
    if not password:
        raise HTTPException(status_code=400, detail=f"{line_label}密码不能为空")

    try:
        ensure_browser_automation_available()
    except RuntimeError as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc

    task_id = _create_login_task(email, mode)
    _append_login_task_log(task_id, f"已接收{line_label}账号登录任务: email={email}")
    _append_login_task_log(
        task_id,
        "任务参数: "
        f"mode={mode}, "
        f"proxy={'enabled' if request.proxy_url else 'disabled'}, "
        f"2fa={'set' if request.two_fa_key else '-'}, "
        f"phone={'set' if request.phone else '-'}, "
        f"phone_code_url={'set' if request.phone_code_url else '-'}",
    )

    background_tasks.add_task(
        _run_login_task,
        task_id=task_id,
        email=email,
        password=password,
        two_fa_key=request.two_fa_key or "",
        phone=request.phone or "",
        phone_code_url=request.phone_code_url or "",
        proxy_url=request.proxy_url or "",
        mode=mode,
    )
    log.info(f"[BATCH_GENERATE] 已提交{line_label}账号登录任务: email={email}, mode={mode}, task_id={task_id}")
    return JSONResponse(
        content={
            "message": f"已启动{line_label}账号登录流程: {email}",
            "task_id": task_id,
            "mode": mode,
        }
    )


@router.get("/logs/{task_id}")
async def get_login_task_logs(
    task_id: str,
    since: int = 0,
    token: str = Depends(verify_panel_token),
):
    with _LOGIN_TASK_LOCK:
        task = _LOGIN_TASKS.get(task_id)
        if not task:
            raise HTTPException(status_code=404, detail="登录任务不存在或日志已过期")

        logs = [entry.copy() for entry in task["logs"] if entry["seq"] > since]
        response = {
            "task_id": task_id,
            "status": task["status"],
            "email": task["email"],
            "mode": task.get("mode") or "geminicli",
            "account_unusable": bool(task.get("account_unusable")),
            "failure_reason": task.get("failure_reason") or "",
            "error": task.get("failure_error") or "",
            "final_test_status_code": int(task.get("final_test_status_code") or 0),
            "credential_persisted": bool(task.get("credential_persisted")),
            "save_skipped_reason": task.get("save_skipped_reason") or "",
            "saved_credential_filename": task.get("saved_credential_filename") or "",
            "saved_proxy_name": task.get("saved_proxy_name") or "",
            "saved_user_email": task.get("saved_user_email") or "",
            "saved_preview_enabled": bool(task.get("saved_preview_enabled")),
            "logs": logs,
            "last_seq": task["seq"],
        }

    return JSONResponse(content=response)
