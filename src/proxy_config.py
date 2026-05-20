"""
Credential proxy binding helpers.
"""

import os
from typing import Any, Dict

from config import get_proxy_pool_config
from log import log
from src.storage_adapter import get_storage_adapter


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
