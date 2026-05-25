"""
Credential proxy binding helpers.
"""

import os
import asyncio
from typing import Any, Dict, Optional

import httpx

import config as app_config
from config import (
    get_credential_proxy_generator_url,
    get_proxy_pool_config,
    mask_proxy_url,
    validate_proxy_url,
)
from log import log
from src.storage_adapter import get_storage_adapter


_proxy_pool_update_lock = asyncio.Lock()


def _extract_generated_proxy_suffix(response_text: str) -> Optional[str]:
    """Extract generated proxy suffix from a plain text API response."""
    for line in str(response_text or "").splitlines():
        candidate = line.strip().strip('"\'')
        if not candidate:
            continue
        if "://" in candidate:
            candidate = candidate.split("://", 1)[1]
        return candidate
    return None


def _replace_proxy_url_suffix(current_proxy_url: str, generated_suffix: str) -> Optional[str]:
    """Keep the current proxy scheme and replace everything after ://."""
    current_proxy_url = str(current_proxy_url or "").strip()
    generated_suffix = str(generated_suffix or "").strip().strip('"\'')
    if not current_proxy_url or "://" not in current_proxy_url or not generated_suffix:
        return None

    if "://" in generated_suffix:
        generated_suffix = generated_suffix.split("://", 1)[1]

    scheme = current_proxy_url.split("://", 1)[0]
    try:
        return validate_proxy_url(f"{scheme}://{generated_suffix}")
    except ValueError as e:
        log.warning(f"[PROXY] 代理生成接口返回无效代理地址: {e}")
        return None


async def _fetch_generated_proxy_suffix(generator_url: str) -> Optional[str]:
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.get(generator_url)
            response.raise_for_status()

        proxy_suffix = _extract_generated_proxy_suffix(response.text)
        if not proxy_suffix:
            log.warning("[PROXY] 代理生成接口未返回有效代理地址字符串")
            return None

        return proxy_suffix
    except Exception as e:
        log.warning(f"[PROXY] 获取新代理地址失败: {e}")
        return None


async def generate_proxy_url_from_generator(generator_url: str) -> Optional[str]:
    """Generate a socks5 proxy URL using the configured generator."""
    generator_url = str(generator_url or "").strip()
    if not generator_url:
        return None

    generated_suffix = await _fetch_generated_proxy_suffix(generator_url)
    if not generated_suffix:
        return None

    try:
        return validate_proxy_url(f"socks5://{generated_suffix}")
    except ValueError as e:
        log.warning(f"[PROXY] 代理生成接口返回无效代理地址: {e}")
        return None


async def refresh_bound_proxy_url_once(request_kwargs: Dict[str, Any], exc: Exception) -> Optional[str]:
    """Replace a bound credential proxy URL once after a proxy failure."""
    if request_kwargs.get("_proxy_refresh_attempted"):
        return None

    proxy_log = request_kwargs.get("_proxy_log") or {}
    proxy_name = (proxy_log.get("bound_proxy_name") or "").strip()
    credential = proxy_log.get("credential") or "-"
    mode = proxy_log.get("mode") or "-"
    failed_proxy_url = str(request_kwargs.get("proxy") or "").strip()

    if not proxy_name:
        return None

    generator_url = await get_credential_proxy_generator_url()
    if not generator_url:
        return None

    async with _proxy_pool_update_lock:
        await app_config.reload_config()
        proxy_pool = await get_proxy_pool_config()
        proxy_entry = next((item for item in proxy_pool if item["name"] == proxy_name), None)
        if not proxy_entry:
            log.warning(
                f"[PROXY] 绑定代理不存在，无法替换代理URL: "
                f"mode={mode}, credential={credential}, proxy_name={proxy_name}"
            )
            return None

        current_proxy_url = proxy_entry["url"]
        if failed_proxy_url and current_proxy_url != failed_proxy_url:
            log.info(
                f"[PROXY] 代理URL已被其他请求更新，复用最新URL: "
                f"mode={mode}, credential={credential}, proxy_name={proxy_name}, "
                f"current={mask_proxy_url(current_proxy_url)}"
            )
            return current_proxy_url

        log.warning(
            f"[PROXY] 代理异常，尝试生成新代理地址: "
            f"mode={mode}, credential={credential}, proxy_name={proxy_name}, "
            f"proxy_url={mask_proxy_url(current_proxy_url)}, error={exc}"
        )

        generated_suffix = await _fetch_generated_proxy_suffix(generator_url)
        if not generated_suffix:
            return None

        new_proxy_url = _replace_proxy_url_suffix(current_proxy_url, generated_suffix)
        if not new_proxy_url:
            return None

        updated_pool = [
            {"name": item["name"], "url": new_proxy_url} if item["name"] == proxy_name else item
            for item in proxy_pool
        ]

        try:
            storage_adapter = await get_storage_adapter()
            if not await storage_adapter.set_config("proxy_pool", updated_pool):
                log.warning(f"[PROXY] 保存更新后的代理池失败: proxy_name={proxy_name}")
                return None

            await app_config.reload_config()
            log.info(
                f"[PROXY] 已替换凭证代理URL: mode={mode}, credential={credential}, "
                f"proxy_name={proxy_name}, old={mask_proxy_url(current_proxy_url)}, "
                f"new={mask_proxy_url(new_proxy_url)}"
            )
            return new_proxy_url
        except Exception as e:
            log.warning(f"[PROXY] 更新代理池失败: proxy_name={proxy_name}, error={e}")
            return None


async def get_credential_proxy_request_kwargs(
    filename: str,
    mode: str,
    request_label: str,
) -> Dict[str, Any]:
    """Build httpx_client kwargs for a credential-scoped outbound request."""
    filename_only = os.path.basename(filename)
    proxy_name = None
    proxy_url = None

    try:
        storage_adapter = await get_storage_adapter()
        state = await storage_adapter.get_credential_state(filename_only, mode=mode)
        proxy_name = (state.get("proxy_name") or "").strip() if state else ""

        if proxy_name:
            proxy_pool = await get_proxy_pool_config()
            proxy_entry = next((item for item in proxy_pool if item["name"] == proxy_name), None)
            if proxy_entry:
                proxy_url = proxy_entry["url"]
            else:
                log.warning(
                    f"[PROXY] 绑定代理不存在，回退到全局代理: "
                    f"mode={mode}, credential={filename_only}, proxy_name={proxy_name}"
                )
    except Exception as e:
        log.warning(
            f"[PROXY] 读取凭证代理绑定失败，回退到全局代理: "
            f"mode={mode}, credential={filename_only}, error={e}"
        )

    return {
        "proxy": proxy_url,
        "_proxy_log": {
            "mode": mode,
            "credential": filename_only,
            "request_label": request_label,
            "bound_proxy_name": proxy_name or "",
        },
    }
