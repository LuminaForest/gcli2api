"""
Standalone batch credential generator service.
"""

from contextlib import asynccontextmanager
import json
import os
from pathlib import Path

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from log import log
from src.models import ConfigSaveRequest, ProxyPoolGenerateRequest
from src.panel import batch_generate
from src.proxy_config import generate_proxy_url_from_generator
from src.utils import verify_panel_token


BATCH_PROXY_CONFIG_KEY = "batch_generate_proxy_url"
ORIGIN_BASE_URL_CONFIG_KEY = "gcli2api_base_url"
ORIGIN_PANEL_TOKEN_CONFIG_KEY = "gcli2api_panel_token"
ORIGIN_PANEL_TOKEN_CONFIGURED_KEY = "gcli2api_panel_token_configured"
_ORIGIN_ENV_DEFAULTS = {
    "GCLI2API_BASE_URL": str(os.getenv("GCLI2API_BASE_URL") or ""),
    "GCLI2API_PANEL_TOKEN": str(os.getenv("GCLI2API_PANEL_TOKEN") or ""),
}


def _local_config_path() -> Path:
    configured_path = str(os.getenv("BATCH_GENERATOR_CONFIG_FILE") or "").strip()
    if configured_path:
        return Path(configured_path)
    return Path(os.getenv("CREDENTIALS_DIR") or "./creds") / "batch_generator_config.json"


def _load_local_config() -> dict[str, str]:
    path = _local_config_path()
    if not path.exists():
        return {}

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        log.warning(f"读取独立批量生成配置失败: {path}, {exc}")
        return {}

    if not isinstance(data, dict):
        return {}

    return {str(key): "" if value is None else str(value) for key, value in data.items()}


def _save_local_config() -> None:
    path = _local_config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(_LOCAL_CONFIG, ensure_ascii=False, indent=2, sort_keys=True),
        encoding="utf-8",
    )


_LOCAL_CONFIG: dict[str, str] = _load_local_config()


def _local_or_env_value(config_key: str, env_key: str) -> str:
    local_value = str(_LOCAL_CONFIG.get(config_key) or "").strip()
    if local_value:
        return local_value
    return str(_ORIGIN_ENV_DEFAULTS.get(env_key) or "").strip()


def _sync_origin_env_for_batch_routes() -> None:
    values = {
        "GCLI2API_BASE_URL": _origin_base_url(),
        "GCLI2API_PANEL_TOKEN": _origin_panel_token(),
    }
    for key, value in values.items():
        if value:
            os.environ[key] = value
        else:
            os.environ.pop(key, None)


def _origin_base_url() -> str:
    return _local_or_env_value(ORIGIN_BASE_URL_CONFIG_KEY, "GCLI2API_BASE_URL").rstrip("/")


def _origin_panel_token() -> str:
    return _local_or_env_value(ORIGIN_PANEL_TOKEN_CONFIG_KEY, "GCLI2API_PANEL_TOKEN")


_sync_origin_env_for_batch_routes()


def _origin_headers() -> dict[str, str]:
    token = _origin_panel_token()
    if not token:
        raise HTTPException(status_code=500, detail="未配置 GCLI2API_PANEL_TOKEN")
    return {"Authorization": f"Bearer {token}"}


def _origin_url(path: str) -> str:
    base_url = _origin_base_url()
    if not base_url:
        raise HTTPException(status_code=500, detail="未配置 GCLI2API_BASE_URL")
    return f"{base_url}{path}"


async def verify_generator_token() -> str:
    return ""


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("启动独立批量生成服务")
    if not _origin_base_url():
        log.warning("未配置 GCLI2API_BASE_URL，凭证无法回传原项目")
    if not _origin_panel_token():
        log.warning("未配置 GCLI2API_PANEL_TOKEN，凭证无法回传原项目")
    yield
    log.info("独立批量生成服务已停止")


app = FastAPI(
    title="GCLI2API Batch Generator",
    description="Standalone batch credential generator",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.dependency_overrides[verify_panel_token] = verify_generator_token
app.include_router(batch_generate.router, prefix="", tags=["Batch Generator"])
app.mount("/front", StaticFiles(directory="front"), name="front")


@app.get("/", response_class=HTMLResponse)
async def serve_batch_generator_panel() -> HTMLResponse:
    with open("front/batch_generator_standalone.html", "r", encoding="utf-8") as file:
        return HTMLResponse(file.read())


@app.head("/keepalive")
async def keepalive() -> Response:
    return Response(status_code=200)


@app.get("/config/get")
async def get_config(token: str = Depends(verify_generator_token)):
    config: dict[str, object] = {}
    data: dict[str, object] = {"config": config, "env_locked": []}
    origin_config_error = ""

    if _origin_base_url() and _origin_panel_token():
        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.get(_origin_url("/config/get"), headers=_origin_headers())

            try:
                origin_data = response.json()
            except Exception:
                origin_data = {"detail": response.text}

            if response.status_code >= 400:
                detail = origin_data.get("detail") or origin_data.get("error") or response.text
                origin_config_error = f"原项目配置加载失败: HTTP {response.status_code}, {detail}"
            else:
                data = dict(origin_data)
                config = dict(data.get("config") or {})
        except Exception as exc:
            origin_config_error = f"原项目配置加载失败: {exc}"
    else:
        origin_config_error = "请先配置远程服务地址和连接密码"

    config.pop(ORIGIN_PANEL_TOKEN_CONFIG_KEY, None)
    config[ORIGIN_BASE_URL_CONFIG_KEY] = _origin_base_url()
    config[ORIGIN_PANEL_TOKEN_CONFIGURED_KEY] = bool(_origin_panel_token())
    if BATCH_PROXY_CONFIG_KEY in _LOCAL_CONFIG:
        config[BATCH_PROXY_CONFIG_KEY] = _LOCAL_CONFIG[BATCH_PROXY_CONFIG_KEY]
    elif os.getenv("BATCH_GENERATE_PROXY_URL"):
        config[BATCH_PROXY_CONFIG_KEY] = os.getenv("BATCH_GENERATE_PROXY_URL")
    data["config"] = config
    if origin_config_error:
        data["origin_config_error"] = origin_config_error
    return JSONResponse(content=data)


@app.post("/config/save")
async def save_config(
    request: ConfigSaveRequest,
    token: str = Depends(verify_generator_token),
):
    for key, value in (request.config or {}).items():
        key = str(key)
        value = "" if value is None else str(value)
        if key == ORIGIN_BASE_URL_CONFIG_KEY:
            value = value.strip().rstrip("/")
        elif key == ORIGIN_PANEL_TOKEN_CONFIG_KEY:
            value = value.strip()
            if not value:
                continue
        _LOCAL_CONFIG[key] = value
    try:
        _save_local_config()
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"保存独立批量生成配置失败: {exc}") from exc
    _sync_origin_env_for_batch_routes()
    return JSONResponse(content={"success": True, "message": "配置已保存"})


@app.post("/config/proxy-pool/generate")
async def generate_proxy_pool_url(
    request: ProxyPoolGenerateRequest,
    token: str = Depends(verify_generator_token),
):
    generator_url = str(request.generator_url or "").strip()
    if not generator_url:
        raise HTTPException(status_code=400, detail="请先配置原项目凭证代理生成链接")
    if not (generator_url.startswith("http://") or generator_url.startswith("https://")):
        raise HTTPException(status_code=400, detail="凭证代理生成链接必须以 http:// 或 https:// 开头")

    scheme = str(request.scheme or "http").strip().lower()
    generated_url = await generate_proxy_url_from_generator(generator_url, scheme=scheme)
    if not generated_url:
        raise HTTPException(status_code=502, detail="生成代理URL失败，请检查生成链接返回内容")
    return JSONResponse(content={"url": generated_url})


@app.get("/creds/status")
async def proxy_creds_status(
    request: Request,
    token: str = Depends(verify_generator_token),
):
    query = request.url.query
    path = f"/creds/status?{query}" if query else "/creds/status"
    async with httpx.AsyncClient(timeout=60.0) as client:
        response = await client.get(_origin_url(path), headers=_origin_headers())

    try:
        data = response.json()
    except Exception:
        data = {"detail": response.text}
    return JSONResponse(status_code=response.status_code, content=data)


def main():
    from hypercorn.asyncio import serve
    from hypercorn.config import Config

    async def _run():
        port = int(os.getenv("PORT", "7863"))
        host = os.getenv("HOST", "0.0.0.0")
        config = Config()
        config.bind = [f"{host}:{port}"]
        config.workers = 1
        log.info("=" * 60)
        log.info("启动独立批量生成服务")
        log.info(f"面板地址: http://127.0.0.1:{port}")
        log.info(f"远程服务地址: {_origin_base_url() or '-'}")
        log.info("=" * 60)
        await serve(app, config)

    import asyncio

    asyncio.run(_run())


if __name__ == "__main__":
    main()
