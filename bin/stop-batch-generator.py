#!/usr/bin/env python3
"""
Stop the local batch generator container and the host Chrome CDP session.

Works on macOS and Windows with Docker Desktop installed.
"""

from __future__ import annotations

import argparse
import os
import platform
import shlex
import signal
import subprocess
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
COMPOSE_FILE = ROOT_DIR / "docker-compose.batch-generator.yml"


def log(message: str) -> None:
    print(message, flush=True)


def run(cmd: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    log("+ " + " ".join(shlex.quote(part) for part in cmd))
    return subprocess.run(cmd, cwd=ROOT_DIR, check=check, text=True)


def docker_compose_down() -> None:
    if not COMPOSE_FILE.exists():
        raise SystemExit(f"Compose file not found: {COMPOSE_FILE}")
    run(["docker", "compose", "-f", str(COMPOSE_FILE), "down"])


def user_data_arg(path: Path) -> str:
    return f"--user-data-dir={path.expanduser()}"


def stop_chrome_macos(chrome_port: int, user_data_dir: Path) -> None:
    port_arg = f"--remote-debugging-port={chrome_port}"
    profile_arg = user_data_arg(user_data_dir)
    result = subprocess.run(["ps", "-axo", "pid=", "-o", "command="], text=True, capture_output=True)
    if result.returncode != 0:
        log((result.stderr or result.stdout).strip())
        return

    stopped = 0
    for line in result.stdout.splitlines():
        row = line.strip()
        if not row:
            continue
        pid_text, _, command = row.partition(" ")
        if port_arg not in command or profile_arg not in command:
            continue
        try:
            os.kill(int(pid_text), signal.SIGTERM)
            stopped += 1
        except (OSError, ValueError):
            continue

    if stopped:
        log(f"Stopped {stopped} matching host Chrome CDP process(es) on macOS.")
    else:
        log("No matching host Chrome CDP process found on macOS.")


def stop_chrome_windows(chrome_port: int, user_data_dir: Path) -> None:
    user_data = str(user_data_dir.expanduser())
    script = (
        "$ErrorActionPreference = 'SilentlyContinue'\n"
        f"$port = '--remote-debugging-port={chrome_port}'\n"
        f"$userData = '--user-data-dir={user_data}'\n"
        "$procs = Get-CimInstance Win32_Process -Filter \"name = 'chrome.exe'\" | "
        "Where-Object { $_.CommandLine -like \"*$port*\" -and $_.CommandLine -like \"*$userData*\" }\n"
        "foreach ($proc in $procs) { Stop-Process -Id $proc.ProcessId -Force }\n"
    )
    result = subprocess.run(
        ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        text=True,
        capture_output=True,
    )
    if result.returncode == 0:
        log("Stopped matching host Chrome CDP process on Windows.")
    else:
        log((result.stderr or result.stdout).strip())


def stop_chrome(system: str, chrome_port: int, user_data_dir: Path) -> None:
    if system == "Darwin":
        stop_chrome_macos(chrome_port, user_data_dir)
    elif system == "Windows":
        stop_chrome_windows(chrome_port, user_data_dir)
    else:
        log(f"Skip Chrome stop: unsupported host OS {system}.")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Stop gcli2api batch generator Docker service and host Chrome CDP."
    )
    parser.add_argument("--chrome-port", type=int, default=int(os.environ.get("BATCH_GENERATE_CHROME_CDP_PORT", "9222")))
    parser.add_argument(
        "--user-data-dir",
        default=os.environ.get("BATCH_GENERATE_CHROME_USER_DATA_DIR") or str(Path.home() / ".gcli2api-chrome"),
    )
    parser.add_argument("--docker-only", action="store_true", help="Only stop the Docker service.")
    parser.add_argument("--chrome-only", action="store_true", help="Only stop the matching Chrome CDP session.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.docker_only and args.chrome_only:
        raise SystemExit("--docker-only and --chrome-only cannot be used together.")

    system = platform.system()

    if not args.chrome_only:
        docker_compose_down()

    if not args.docker_only:
        stop_chrome(system, args.chrome_port, Path(args.user_data_dir))

    log("Batch generator stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
