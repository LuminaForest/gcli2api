"""
通用的HTTP客户端模块
为所有需要使用httpx的模块提供统一的客户端配置和方法
保持通用性，不与特定业务逻辑耦合
"""

import asyncio
import base64
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Dict, Optional
from urllib.parse import unquote, urlsplit

import httpx

from config import format_proxy_for_httpx, get_proxy_config, mask_proxy_url
from log import log


class HttpxClientManager:
    """通用HTTP客户端管理器"""

    async def get_client_kwargs(self, timeout: float = 30.0, **kwargs) -> Dict[str, Any]:
        """获取httpx客户端的通用配置参数"""
        explicit_proxy = kwargs.pop("proxy", None)
        proxy_log = kwargs.pop("_proxy_log", None)
        kwargs.pop("_proxy_refresh_attempted", None)
        client_kwargs = {"timeout": timeout, **kwargs}

        proxy_source = "none"
        proxy_url = None

        if explicit_proxy:
            proxy_url = explicit_proxy
            proxy_source = "credential"
        else:
            # 动态读取代理配置，支持热更新
            current_proxy_config = await get_proxy_config()
            if current_proxy_config:
                proxy_url = current_proxy_config
                proxy_source = "global"

        if proxy_url:
            client_kwargs["proxy"] = format_proxy_for_httpx(proxy_url)

        if proxy_log:
            mode = proxy_log.get("mode", "-")
            credential = proxy_log.get("credential", "-")
            request_label = proxy_log.get("request_label", "-")
            bound_proxy_name = proxy_log.get("bound_proxy_name", "")
            masked_proxy = mask_proxy_url(proxy_url) if proxy_url else ""
            log.info(
                f"[PROXY] outbound request: mode={mode}, credential={credential}, "
                f"request={request_label}, proxy_source={proxy_source}, "
                f"proxy_name={bound_proxy_name or '-'}, proxy_url={masked_proxy or '-'}"
            )

        return client_kwargs

    @asynccontextmanager
    async def get_client(
        self, timeout: float = 30.0, **kwargs
    ) -> AsyncGenerator[httpx.AsyncClient, None]:
        """获取配置好的异步HTTP客户端"""
        client_kwargs = await self.get_client_kwargs(timeout=timeout, **kwargs)

        async with httpx.AsyncClient(**client_kwargs) as client:
            yield client

    @asynccontextmanager
    async def get_streaming_client(
        self, timeout: float = None, **kwargs
    ) -> AsyncGenerator[httpx.AsyncClient, None]:
        """获取用于流式请求的HTTP客户端（无超时限制）"""
        client_kwargs = await self.get_client_kwargs(timeout=timeout, **kwargs)

        # 创建独立的客户端实例用于流式处理
        client = httpx.AsyncClient(**client_kwargs)
        try:
            yield client
        finally:
            # 确保无论发生什么都关闭客户端
            try:
                await client.aclose()
            except Exception as e:
                log.warning(f"Error closing streaming client: {e}")


def _extract_httpx_error_message(exc: Exception) -> str:
    """Extract the most useful message from httpx exceptions."""
    response = getattr(exc, "response", None)
    if response is not None:
        try:
            body = response.text
        except Exception:
            body = ""
        if body:
            return f"{type(exc).__name__}: HTTP {response.status_code} - {body[:1000]}"
        return f"{type(exc).__name__}: HTTP {response.status_code}"

    cause = getattr(exc, "__cause__", None)
    if cause:
        return f"{type(exc).__name__}: {exc}; cause={type(cause).__name__}: {cause}"

    context = getattr(exc, "__context__", None)
    if context:
        return f"{type(exc).__name__}: {exc}; context={type(context).__name__}: {context}"

    return f"{type(exc).__name__}: {exc}"


async def _probe_http_proxy_error(proxy_url: str, target_url: str) -> Optional[str]:
    """Best-effort probe to capture HTTP proxy CONNECT error bodies."""
    try:
        formatted_proxy = format_proxy_for_httpx(proxy_url)
        proxy = urlsplit(formatted_proxy)
        target = urlsplit(target_url)

        if proxy.scheme != "http" or not proxy.hostname or not target.hostname:
            return None

        proxy_port = proxy.port or 80
        target_port = target.port or (443 if target.scheme == "https" else 80)
        target_authority = f"{target.hostname}:{target_port}"

        auth_header = ""
        if proxy.username is not None:
            username = unquote(proxy.username)
            password = unquote(proxy.password or "")
            token = base64.b64encode(f"{username}:{password}".encode()).decode()
            auth_header = f"Proxy-Authorization: Basic {token}\r\n"

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(proxy.hostname, proxy_port),
            timeout=5.0,
        )
        try:
            request = (
                f"CONNECT {target_authority} HTTP/1.1\r\n"
                f"Host: {target_authority}\r\n"
                f"{auth_header}"
                "Proxy-Connection: close\r\n"
                "\r\n"
            )
            writer.write(request.encode())
            await asyncio.wait_for(writer.drain(), timeout=5.0)
            data = await asyncio.wait_for(reader.read(4096), timeout=5.0)
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        if not data:
            return None

        text = data.decode("utf-8", errors="replace")
        headers, _, body = text.partition("\r\n\r\n")
        status_line = headers.splitlines()[0] if headers else ""
        body = body.strip()
        if body:
            return f"{status_line} - {body[:1000]}"
        return status_line or None

    except Exception as probe_error:
        return f"proxy probe failed: {type(probe_error).__name__}: {probe_error}"


async def _log_httpx_error(
    action: str, url: str, exc: Exception, request_kwargs: Optional[Dict[str, Any]] = None
) -> None:
    error_msg = _extract_httpx_error_message(exc)
    proxy_url = (request_kwargs or {}).get("proxy")
    if not proxy_url:
        proxy_url = await get_proxy_config()

    if proxy_url and isinstance(exc, httpx.ProxyError):
        proxy_detail = await _probe_http_proxy_error(proxy_url, url)
        if proxy_detail:
            error_msg = f"{error_msg}; proxy_detail={proxy_detail}"

    log.error(f"[HTTPX] {action} failed: url={url}, error={error_msg}")


async def _refresh_proxy_for_retry(
    action: str,
    url: str,
    exc: Exception,
    request_kwargs: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    if not _is_proxy_transport_error(exc, request_kwargs):
        return None

    try:
        from src.proxy_config import refresh_bound_proxy_url_once

        new_proxy_url = await refresh_bound_proxy_url_once(request_kwargs, exc)
        if not new_proxy_url:
            return None

        retry_kwargs = {**request_kwargs, "proxy": new_proxy_url, "_proxy_refresh_attempted": True}
        log.info(f"[HTTPX] {action} retrying once with refreshed credential proxy: url={url}")
        return retry_kwargs
    except Exception as refresh_error:
        log.warning(f"[HTTPX] {action} proxy refresh failed: url={url}, error={refresh_error}")
        return None


def _is_proxy_transport_error(exc: Exception, request_kwargs: Dict[str, Any]) -> bool:
    """Treat transport failures on proxied requests as proxy failures."""
    if not request_kwargs.get("proxy"):
        return isinstance(exc, httpx.ProxyError)

    exc_module = exc.__class__.__module__
    exc_text = str(exc)
    return isinstance(exc, httpx.ProxyError) or (
        isinstance(exc, httpx.TransportError)
        or exc_module.startswith("socksio")
        or "Malformed reply" in exc_text
    )


def _raise_proxy_transport_error(exc: Exception, request_kwargs: Dict[str, Any]) -> None:
    if isinstance(exc, httpx.ProxyError):
        raise exc
    if _is_proxy_transport_error(exc, request_kwargs):
        raise httpx.ProxyError(str(exc), request=getattr(exc, "request", None)) from exc
    raise exc


# 全局HTTP客户端管理器实例
http_client = HttpxClientManager()


# 通用的异步方法
async def get_async(
    url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 30.0, **kwargs
) -> httpx.Response:
    """通用异步GET请求"""
    async def request_once(request_kwargs: Dict[str, Any]) -> httpx.Response:
        async with http_client.get_client(timeout=timeout, **request_kwargs) as client:
            return await client.get(url, headers=headers)

    try:
        return await request_once(kwargs)
    except Exception as e:
        retry_kwargs = await _refresh_proxy_for_retry("GET", url, e, kwargs)
        if retry_kwargs:
            try:
                return await request_once(retry_kwargs)
            except Exception as retry_error:
                await _log_httpx_error("GET", url, retry_error, retry_kwargs)
                _raise_proxy_transport_error(retry_error, retry_kwargs)

        await _log_httpx_error("GET", url, e, kwargs)
        _raise_proxy_transport_error(e, kwargs)


async def post_async(
    url: str,
    data: Any = None,
    json: Any = None,
    headers: Optional[Dict[str, str]] = None,
    timeout: float = 900.0,
    **kwargs,
) -> httpx.Response:
    """通用异步POST请求"""
    async def request_once(request_kwargs: Dict[str, Any]) -> httpx.Response:
        async with http_client.get_client(timeout=timeout, **request_kwargs) as client:
            return await client.post(url, data=data, json=json, headers=headers)

    try:
        return await request_once(kwargs)
    except Exception as e:
        retry_kwargs = await _refresh_proxy_for_retry("POST", url, e, kwargs)
        if retry_kwargs:
            try:
                return await request_once(retry_kwargs)
            except Exception as retry_error:
                await _log_httpx_error("POST", url, retry_error, retry_kwargs)
                _raise_proxy_transport_error(retry_error, retry_kwargs)

        await _log_httpx_error("POST", url, e, kwargs)
        _raise_proxy_transport_error(e, kwargs)


# 调试用：设为 True 时所有流式请求都返回 429
_MOCK_STREAM_429 = False

async def stream_post_async(
    url: str,
    body: Dict[str, Any],
    native: bool = False,
    headers: Optional[Dict[str, str]] = None,
    **kwargs,
):
    """流式异步POST请求"""
    if _MOCK_STREAM_429:
        from fastapi import Response
        import json
        log.warning(f"[MOCK] stream_post_async: 返回模拟429错误")
        yield Response(
            content=json.dumps({"error": {"code": 429, "message": "mock rate limit", "status": "RESOURCE_EXHAUSTED"}}),
            status_code=429,
        )
        return

    async def stream_once(request_kwargs: Dict[str, Any]):
        async with http_client.get_streaming_client(**request_kwargs) as client:
            async with client.stream("POST", url, json=body, headers=headers) as r:
                # 错误直接返回
                if r.status_code != 200:
                    from fastapi import Response
                    yield Response(await r.aread(), r.status_code, dict(r.headers))
                    return

                # 如果native=True，直接返回bytes流
                if native:
                    async for chunk in r.aiter_bytes():
                        yield chunk
                else:
                    # 通过aiter_lines转化成str流返回
                    async for line in r.aiter_lines():
                        yield line

    try:
        async for chunk in stream_once(kwargs):
            yield chunk
    except Exception as e:
        retry_kwargs = await _refresh_proxy_for_retry("STREAM_POST", url, e, kwargs)
        if retry_kwargs:
            try:
                async for chunk in stream_once(retry_kwargs):
                    yield chunk
                return
            except Exception as retry_error:
                await _log_httpx_error("STREAM_POST", url, retry_error, retry_kwargs)
                _raise_proxy_transport_error(retry_error, retry_kwargs)

        await _log_httpx_error("STREAM_POST", url, e, kwargs)
        _raise_proxy_transport_error(e, kwargs)
