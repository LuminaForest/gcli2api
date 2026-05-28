#!/usr/bin/env python3
"""
Start the local batch generator container and a host Chrome CDP session.

Works on macOS and Windows with Docker Desktop installed.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urljoin


ROOT_DIR = Path(__file__).resolve().parents[1]
COMPOSE_FILE = ROOT_DIR / "docker-compose.batch-generator.yml"
CONTAINER_NAME = "gcli2api-batch-generator"


def log(message: str) -> None:
    print(message, flush=True)


def run(cmd: list[str], *, env: dict[str, str] | None = None, check: bool = True) -> subprocess.CompletedProcess:
    log("+ " + " ".join(cmd))
    return subprocess.run(cmd, cwd=ROOT_DIR, env=env, check=check, text=True, capture_output=False)


def capture(cmd: list[str], *, env: dict[str, str] | None = None, check: bool = True) -> str:
    result = subprocess.run(cmd, cwd=ROOT_DIR, env=env, check=check, text=True, capture_output=True)
    return result.stdout.strip()


def wait_url(url: str, *, timeout: float, label: str) -> bool:
    deadline = time.time() + timeout
    last_error = ""
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if 200 <= response.status < 500:
                    return True
        except Exception as exc:  # noqa: BLE001 - surfacing compact diagnostics only.
            last_error = str(exc)
        time.sleep(0.5)

    log(f"{label} not ready: {url} ({last_error})")
    return False


def wait_container_url(url: str, *, timeout: float, label: str) -> bool:
    deadline = time.time() + timeout
    last_error = ""
    script = (
        "import sys, urllib.request\n"
        f"url = {url!r}\n"
        "try:\n"
        "    response = urllib.request.urlopen(url, timeout=2)\n"
        "    sys.exit(0 if 200 <= response.status < 500 else 1)\n"
        "except Exception as exc:\n"
        "    print(exc)\n"
        "    sys.exit(1)\n"
    )
    while time.time() < deadline:
        result = subprocess.run(
            ["docker", "exec", CONTAINER_NAME, "python", "-c", script],
            cwd=ROOT_DIR,
            text=True,
            capture_output=True,
        )
        if result.returncode == 0:
            return True
        last_error = (result.stdout or result.stderr).strip()
        time.sleep(0.5)

    log(f"{label} not ready: {url} ({last_error})")
    return False


def is_url_ready(url: str) -> bool:
    try:
        with urllib.request.urlopen(url, timeout=1) as response:
            return 200 <= response.status < 500
    except Exception:
        return False


def docker_compose(args: list[str], env: dict[str, str]) -> None:
    run(["docker", "compose", "-f", str(COMPOSE_FILE), *args], env=env)


def resolve_container_host_gateway() -> str:
    script = (
        "import socket\n"
        "infos = socket.getaddrinfo('host.docker.gateway', 9222, socket.AF_INET, socket.SOCK_STREAM)\n"
        "print(infos[0][4][0])\n"
    )
    return capture(["docker", "exec", CONTAINER_NAME, "python", "-c", script])


def chrome_candidates(system: str) -> list[Path]:
    env_path = os.environ.get("CHROME_PATH")
    paths: list[Path] = [Path(env_path)] if env_path else []

    if system == "Darwin":
        paths.extend(
            [
                Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
                Path.home() / "Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            ]
        )
    elif system == "Windows":
        for key in ("PROGRAMFILES", "PROGRAMFILES(X86)", "ProgramFiles", "ProgramFiles(x86)", "LOCALAPPDATA"):
            base = os.environ.get(key)
            if base:
                paths.append(Path(base) / "Google" / "Chrome" / "Application" / "chrome.exe")

    return paths


def find_chrome(system: str, override: str | None) -> Path:
    if override:
        path = Path(override).expanduser()
        if path.exists():
            return path
        raise SystemExit(f"Chrome not found at --chrome-path: {path}")

    for path in chrome_candidates(system):
        if path.exists():
            return path

    raise SystemExit(
        "Chrome executable not found. Install Google Chrome or set CHROME_PATH / --chrome-path."
    )


def start_chrome(system: str, chrome_path: Path, chrome_port: int, user_data_dir: Path) -> None:
    host_cdp_url = f"http://127.0.0.1:{chrome_port}/json/version"
    if is_url_ready(host_cdp_url):
        log(f"Chrome CDP already running on {host_cdp_url}")
        return

    user_data_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(chrome_path),
        "--remote-debugging-address=0.0.0.0",
        f"--remote-debugging-port={chrome_port}",
        f"--user-data-dir={user_data_dir}",
        "--incognito",
        "--no-first-run",
        "--no-default-browser-check",
        "--window-size=1280,900",
        "--lang=en-US",
    ]

    log("Starting host Chrome with CDP enabled...")
    kwargs = {
        "stdout": subprocess.DEVNULL,
        "stderr": subprocess.DEVNULL,
        "stdin": subprocess.DEVNULL,
    }
    if system == "Windows":
        creationflags = 0
        creationflags |= getattr(subprocess, "DETACHED_PROCESS", 0)
        creationflags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        kwargs["creationflags"] = creationflags
    else:
        kwargs["start_new_session"] = True

    subprocess.Popen(cmd, **kwargs)  # noqa: S603 - chrome path is explicit/local.


def print_chrome_version(chrome_port: int) -> None:
    url = f"http://127.0.0.1:{chrome_port}/json/version"
    try:
        with urllib.request.urlopen(url, timeout=2) as response:
            data = json.loads(response.read().decode("utf-8"))
        browser = data.get("Browser") or "Chrome"
        websocket = data.get("webSocketDebuggerUrl") or "-"
        log(f"Chrome CDP ready: {browser}")
        log(f"Chrome WebSocket: {websocket}")
    except (urllib.error.URLError, json.JSONDecodeError, TimeoutError) as exc:
        log(f"Chrome CDP version check failed: {exc}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Start gcli2api batch generator in Docker and host Chrome CDP."
    )
    parser.add_argument("--service-port", type=int, default=int(os.environ.get("BATCH_GENERATOR_PORT", "7863")))
    parser.add_argument("--chrome-port", type=int, default=int(os.environ.get("BATCH_GENERATE_CHROME_CDP_PORT", "9222")))
    parser.add_argument("--chrome-path", default=os.environ.get("CHROME_PATH"))
    parser.add_argument(
        "--user-data-dir",
        default=os.environ.get("BATCH_GENERATE_CHROME_USER_DATA_DIR") or str(Path.home() / ".gcli2api-chrome"),
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    system = platform.system()
    if system not in {"Darwin", "Windows"}:
        raise SystemExit(f"Unsupported host OS: {system}. This script supports macOS and Windows.")
    if not COMPOSE_FILE.exists():
        raise SystemExit(f"Compose file not found: {COMPOSE_FILE}")

    chrome_path = find_chrome(system, args.chrome_path)
    compose_env = os.environ.copy()
    compose_env["BATCH_GENERATOR_PORT"] = str(args.service_port)

    docker_compose(["pull"], compose_env)

    log("Starting batch generator container...")
    docker_compose(["up", "-d", "--force-recreate"], compose_env)

    gateway_ip = resolve_container_host_gateway()
    container_cdp_url = f"http://{gateway_ip}:{args.chrome_port}"
    compose_env["BATCH_GENERATE_CHROME_CDP_URL"] = container_cdp_url

    log(f"Using container CDP URL: {container_cdp_url}")
    docker_compose(["up", "-d", "--force-recreate"], compose_env)

    start_chrome(system, chrome_path, args.chrome_port, Path(args.user_data_dir).expanduser())

    wait_url(f"http://127.0.0.1:{args.chrome_port}/json/version", timeout=20, label="Host Chrome CDP")
    print_chrome_version(args.chrome_port)

    container_check = urljoin(container_cdp_url.rstrip("/") + "/", "json/version")
    wait_container_url(container_check, timeout=10, label="Container to host Chrome CDP")
    wait_url(f"http://127.0.0.1:{args.service_port}/", timeout=20, label="Batch generator web UI")

    log("")
    log(f"Batch generator UI: http://127.0.0.1:{args.service_port}")
    log("Keep the Chrome window open while running generation tasks.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
