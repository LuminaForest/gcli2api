#!/usr/bin/env python3
"""
Simple concurrency load test for gcli2api.

It targets one model through the OpenAI-compatible chat completions endpoint and
prints latency, success/error distribution, and optional server process pressure.

Quick start:
  1. Run on the same server as the Docker container when you want Docker metrics.
  2. Install dependency if needed:
       python3 -m venv /tmp/gcli2api-loadtest-venv
       /tmp/gcli2api-loadtest-venv/bin/python -m pip install -U pip
       /tmp/gcli2api-loadtest-venv/bin/python -m pip install "httpx[socks]>=0.28.1"
  3. Find the container name:
       docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
  4. Smoke test:
       /tmp/gcli2api-loadtest-venv/bin/python /tmp/concurrency_load_test.py \
         --url http://127.0.0.1:7861/v1/chat/completions \
         --api-key your_api_password \
         --model gemini-2.5-pro \
         --prompt hi \
         -c 10 \
         -n 10 \
         --docker-container gcli2api
  5. 1000-concurrency test:
       /tmp/gcli2api-loadtest-venv/bin/python /tmp/concurrency_load_test.py \
         --url http://127.0.0.1:7861/v1/chat/completions \
         --api-key your_api_password \
         --model gemini-2.5-pro \
         --prompt hi \
         -c 1000 \
         -n 1000 \
         --docker-container gcli2api

Parameter notes:
  --api-key: pass only the token after "Bearer", not the word "Bearer".
  -c / --concurrency: max in-flight requests at the same time.
  -n / --requests: total number of requests to send.
  --docker-container: container name/id used for "docker stats" sampling.
  --server-pid: local process PID sampling; usually unnecessary for Docker.
  --ramp-seconds: gradually starts requests instead of sending all at once.
  --progress-interval: prints running progress every N seconds; set 0 to disable.
  --max-tokens: defaults to 1 to reduce upstream token cost during load tests.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import resource
import statistics
import subprocess
import sys
import time
from collections import Counter
from dataclasses import dataclass
from typing import Any

import httpx


DEFAULT_URL = "http://168.144.102.101:7861/v1/chat/completions"
DEFAULT_MODEL = "gemini-2.5-flash"


EXAMPLES = """\
示例 1：远程服务器 Docker 内部本机压测，推荐用于同时查看容器压力
  python3 /tmp/concurrency_load_test.py \\
    --url http://127.0.0.1:7861/v1/chat/completions \\
    --api-key Q7mX9vLp2Kc8 \\
    --model gemini-2.5-pro \\
    --prompt hi \\
    -c 1000 \\
    -n 1000 \\
    --docker-container gcli2api

示例 2：先小并发试跑
  python3 /tmp/concurrency_load_test.py \\
    --url http://127.0.0.1:7861/v1/chat/completions \\
    --api-key Q7mX9vLp2Kc8 \\
    --model gemini-2.5-pro \\
    --prompt hi \\
    -c 10 \\
    -n 10 \\
    --docker-container gcli2api

示例 3：本地电脑压远程服务，只测接口，不采集远程 Docker 指标
  python3 bin/concurrency_load_test.py \\
    --url http://168.144.102.101:7861/v1/chat/completions \\
    --api-key Q7mX9vLp2Kc8 \\
    --model gemini-2.5-pro \\
    --prompt hi \\
    -c 100 \\
    -n 200

参数说明：
  --api-key            只传 Bearer 后面的值，例如 Q7mX9vLp2Kc8
  -c, --concurrency   最大同时进行中的请求数，例如 -c 1000
  -n, --requests      总请求数，例如 -n 1000
  --docker-container  Docker 容器名或 ID，用于采样 CPU/内存/网络/PID
  --server-pid        宿主机本地进程 PID 采样；Docker 场景一般不用
  --ramp-seconds      在指定秒数内逐步启动请求，避免瞬间打满
  --progress-interval 每隔几秒打印一次运行进度；设为 0 可关闭
  --max-tokens        默认 1，减少压测输出 token 消耗
"""


@dataclass
class RequestResult:
    ok: bool
    status_code: int | None
    elapsed_ms: float
    error_type: str
    error_sample: str


@dataclass
class ProcessSample:
    ts: float
    cpu_percent: float
    mem_percent: float
    rss_kb: int


@dataclass
class DockerSample:
    ts: float
    cpu_percent: float
    mem_percent: float
    mem_usage_bytes: float
    mem_limit_bytes: float
    pids: int | None
    net_io: str
    block_io: str


@dataclass
class LoadState:
    total: int
    waiting: int = 0
    in_flight: int = 0
    completed: int = 0
    success: int = 0
    failed: int = 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a high-concurrency load test against gcli2api."
    )
    parser.add_argument(
        "--examples",
        action="store_true",
        help="Print usage examples and parameter notes, then exit.",
    )
    parser.add_argument("--url", default=os.getenv("GCLI2API_TEST_URL", DEFAULT_URL))
    parser.add_argument("--model", default=os.getenv("GCLI2API_TEST_MODEL", DEFAULT_MODEL))
    parser.add_argument(
        "--api-key",
        default=os.getenv("API_PASSWORD") or os.getenv("PASSWORD") or "pwd",
        help="API password. Defaults to API_PASSWORD, PASSWORD, then pwd.",
    )
    parser.add_argument(
        "-c",
        "--concurrency",
        type=int,
        default=int(os.getenv("GCLI2API_TEST_CONCURRENCY", "1000")),
        help="Number of concurrent in-flight requests.",
    )
    parser.add_argument(
        "-n",
        "--requests",
        type=int,
        default=int(os.getenv("GCLI2API_TEST_REQUESTS", "1000")),
        help="Total request count.",
    )
    parser.add_argument("--timeout", type=float, default=300.0)
    parser.add_argument("--max-tokens", type=int, default=1)
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument(
        "--prompt",
        default="Return the single word ok.",
        help="Prompt sent to the model.",
    )
    parser.add_argument(
        "--ramp-seconds",
        type=float,
        default=0.0,
        help="Spread task start over this many seconds. Default starts all at once.",
    )
    parser.add_argument(
        "--progress-interval",
        type=float,
        default=5.0,
        help="Print running progress every N seconds. Set to 0 to disable.",
    )
    parser.add_argument(
        "--server-pid",
        type=int,
        default=None,
        help="Optional gcli2api server PID for CPU/memory sampling.",
    )
    parser.add_argument(
        "--sample-interval",
        type=float,
        default=1.0,
        help="Server process sampling interval in seconds.",
    )
    parser.add_argument(
        "--docker-container",
        default=os.getenv("GCLI2API_TEST_DOCKER_CONTAINER"),
        help="Optional Docker container name/id for docker stats sampling.",
    )
    parser.add_argument(
        "--docker-bin",
        default=os.getenv("DOCKER_BIN", "docker"),
        help="Docker executable path. Defaults to docker.",
    )
    parser.add_argument(
        "--print-errors",
        type=int,
        default=5,
        help="Number of representative error samples to print.",
    )
    return parser.parse_args()


def percentile(values: list[float], percent: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    ordered = sorted(values)
    index = (len(ordered) - 1) * percent / 100.0
    lower = int(index)
    upper = min(lower + 1, len(ordered) - 1)
    weight = index - lower
    return ordered[lower] * (1.0 - weight) + ordered[upper] * weight


def get_fd_limit() -> int | None:
    try:
        soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
        return int(soft)
    except Exception:
        return None


def read_process_sample(pid: int) -> ProcessSample | None:
    try:
        completed = subprocess.run(
            ["ps", "-p", str(pid), "-o", "%cpu=,%mem=,rss="],
            check=False,
            capture_output=True,
            text=True,
            timeout=2.0,
        )
    except Exception:
        return None

    line = completed.stdout.strip()
    if completed.returncode != 0 or not line:
        return None

    parts = line.split()
    if len(parts) < 3:
        return None

    try:
        return ProcessSample(
            ts=time.perf_counter(),
            cpu_percent=float(parts[0]),
            mem_percent=float(parts[1]),
            rss_kb=int(float(parts[2])),
        )
    except ValueError:
        return None


def parse_percent(value: Any) -> float:
    try:
        return float(str(value).strip().rstrip("%"))
    except ValueError:
        return 0.0


def parse_size_to_bytes(value: str) -> float:
    value = str(value or "").strip()
    if not value:
        return 0.0

    match = re.match(r"^\s*([0-9]*\.?[0-9]+)\s*([A-Za-z]+)?\s*$", value)
    if not match:
        return 0.0

    try:
        amount = float(match.group(1))
    except ValueError:
        return 0.0
    unit = match.group(2) or "B"

    multipliers = {
        "b": 1,
        "kb": 1000,
        "mb": 1000**2,
        "gb": 1000**3,
        "tb": 1000**4,
        "kib": 1024,
        "mib": 1024**2,
        "gib": 1024**3,
        "tib": 1024**4,
    }
    return amount * multipliers.get(unit.lower(), 1)


def parse_mem_usage(value: str) -> tuple[float, float]:
    usage, _, limit = str(value or "").partition("/")
    return parse_size_to_bytes(usage.strip()), parse_size_to_bytes(limit.strip())


def read_docker_sample(docker_bin: str, container: str) -> DockerSample | None:
    try:
        completed = subprocess.run(
            [docker_bin, "stats", "--no-stream", "--format", "{{json .}}", container],
            check=False,
            capture_output=True,
            text=True,
            timeout=5.0,
        )
    except Exception:
        return None

    line = completed.stdout.strip()
    if completed.returncode != 0 or not line:
        return None

    try:
        data = json.loads(line.splitlines()[0])
    except json.JSONDecodeError:
        return None

    mem_usage_bytes, mem_limit_bytes = parse_mem_usage(data.get("MemUsage", ""))
    pids = None
    try:
        pids = int(str(data.get("PIDs", "")).strip())
    except ValueError:
        pass

    return DockerSample(
        ts=time.perf_counter(),
        cpu_percent=parse_percent(data.get("CPUPerc")),
        mem_percent=parse_percent(data.get("MemPerc")),
        mem_usage_bytes=mem_usage_bytes,
        mem_limit_bytes=mem_limit_bytes,
        pids=pids,
        net_io=str(data.get("NetIO", "")),
        block_io=str(data.get("BlockIO", "")),
    )


async def sample_process(
    pid: int,
    stop_event: asyncio.Event,
    interval: float,
    samples: list[ProcessSample],
) -> None:
    while not stop_event.is_set():
        sample = await asyncio.to_thread(read_process_sample, pid)
        if sample:
            samples.append(sample)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass


async def sample_docker_container(
    docker_bin: str,
    container: str,
    stop_event: asyncio.Event,
    interval: float,
    samples: list[DockerSample],
) -> None:
    while not stop_event.is_set():
        sample = await asyncio.to_thread(read_docker_sample, docker_bin, container)
        if sample:
            samples.append(sample)
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass


async def print_progress(
    state: LoadState,
    started: float,
    stop_event: asyncio.Event,
    interval: float,
    process_samples: list[ProcessSample],
    docker_samples: list[DockerSample],
) -> None:
    while not stop_event.is_set():
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
            break
        except asyncio.TimeoutError:
            pass

        elapsed = time.perf_counter() - started
        not_started = max(
            state.total - state.waiting - state.in_flight - state.completed,
            0,
        )
        line = (
            f"[进度] elapsed={elapsed:.1f}s completed={state.completed}/{state.total} "
            f"in_flight={state.in_flight} waiting={state.waiting} "
            f"not_started={not_started} success={state.success} failed={state.failed}"
        )

        if process_samples:
            latest_process = process_samples[-1]
            line += (
                f" process_cpu={latest_process.cpu_percent:.1f}% "
                f"process_mem={latest_process.mem_percent:.1f}%"
            )

        if docker_samples:
            latest_docker = docker_samples[-1]
            mem_mb = latest_docker.mem_usage_bytes / 1024.0 / 1024.0
            line += (
                f" docker_cpu={latest_docker.cpu_percent:.1f}% "
                f"docker_mem={latest_docker.mem_percent:.1f}% "
                f"docker_mem_mb={mem_mb:.1f}"
            )

        print(line, flush=True)


async def send_one(
    client: httpx.AsyncClient,
    url: str,
    payload: dict[str, Any],
    start_event: asyncio.Event,
    semaphore: asyncio.Semaphore,
    ramp_delay: float,
    state: LoadState,
) -> RequestResult:
    await start_event.wait()
    if ramp_delay > 0:
        await asyncio.sleep(ramp_delay)

    state.waiting += 1
    async with semaphore:
        state.waiting -= 1
        state.in_flight += 1
        started = time.perf_counter()
        result = None
        try:
            response = await client.post(url, json=payload)
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            text = response.text

            body_error = ""
            try:
                data = response.json()
                if isinstance(data, dict) and data.get("error"):
                    body_error = json.dumps(data.get("error"), ensure_ascii=False)[:500]
            except Exception:
                pass

            ok = 200 <= response.status_code < 300 and not body_error
            error_type = "ok" if ok else f"http_{response.status_code}"
            if body_error:
                error_type = f"{error_type}_body_error"
                error_sample = body_error
            else:
                error_sample = text[:500] if not ok else ""

            result = RequestResult(
                ok,
                response.status_code,
                elapsed_ms,
                error_type,
                error_sample,
            )
            return result

        except Exception as exc:
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            result = RequestResult(
                ok=False,
                status_code=None,
                elapsed_ms=elapsed_ms,
                error_type=type(exc).__name__,
                error_sample=str(exc)[:500],
            )
            return result
        finally:
            state.in_flight -= 1
            state.completed += 1
            if result and result.ok:
                state.success += 1
            else:
                state.failed += 1


async def run_test(args: argparse.Namespace) -> int:
    if args.concurrency <= 0 or args.requests <= 0:
        print("concurrency 和 requests 必须大于 0", file=sys.stderr)
        return 2

    payload = {
        "model": args.model,
        "messages": [{"role": "user", "content": args.prompt}],
        "stream": False,
        "temperature": args.temperature,
        "max_tokens": args.max_tokens,
    }

    fd_limit = get_fd_limit()
    if fd_limit and args.concurrency >= fd_limit:
        print(
            f"警告: 当前文件句柄软限制为 {fd_limit}，并发 {args.concurrency} 可能先撞到客户端系统限制。"
        )

    headers = {
        "Authorization": f"Bearer {args.api_key}",
        "Content-Type": "application/json",
    }
    limits = httpx.Limits(
        max_connections=args.concurrency,
        max_keepalive_connections=min(args.concurrency, 100),
        keepalive_expiry=5.0,
    )
    timeout = httpx.Timeout(args.timeout, connect=min(args.timeout, 30.0))
    semaphore = asyncio.Semaphore(args.concurrency)
    start_event = asyncio.Event()
    stop_sampler = asyncio.Event()
    process_samples: list[ProcessSample] = []
    docker_samples: list[DockerSample] = []
    load_state = LoadState(total=args.requests)

    sampler_tasks = []
    if args.server_pid:
        sampler_tasks.append(
            asyncio.create_task(
                sample_process(args.server_pid, stop_sampler, args.sample_interval, process_samples)
            )
        )
    if args.docker_container:
        sampler_tasks.append(
            asyncio.create_task(
                sample_docker_container(
                    args.docker_bin,
                    args.docker_container,
                    stop_sampler,
                    args.sample_interval,
                    docker_samples,
                )
            )
        )

    print("压测配置:")
    print(f"  url: {args.url}")
    print(f"  model: {args.model}")
    print(f"  requests: {args.requests}")
    print(f"  concurrency: {args.concurrency}")
    print(f"  timeout: {args.timeout}s")
    print(f"  max_tokens: {args.max_tokens}")
    if args.server_pid:
        print(f"  server_pid: {args.server_pid}")
    if args.docker_container:
        print(f"  docker_container: {args.docker_container}")
    print()

    async with httpx.AsyncClient(headers=headers, timeout=timeout, limits=limits) as client:
        tasks = []
        for i in range(args.requests):
            ramp_delay = 0.0
            if args.ramp_seconds > 0 and args.requests > 1:
                ramp_delay = args.ramp_seconds * i / (args.requests - 1)
            tasks.append(
                asyncio.create_task(
                    send_one(
                        client,
                        args.url,
                        payload,
                        start_event,
                        semaphore,
                        ramp_delay,
                        load_state,
                    )
                )
            )

        started = time.perf_counter()
        progress_stop = asyncio.Event()
        progress_task = None
        if args.progress_interval > 0:
            progress_task = asyncio.create_task(
                print_progress(
                    load_state,
                    started,
                    progress_stop,
                    args.progress_interval,
                    process_samples,
                    docker_samples,
                )
            )

        start_event.set()
        try:
            results = await asyncio.gather(*tasks)
        finally:
            progress_stop.set()
            if progress_task:
                await progress_task
        elapsed = time.perf_counter() - started

    stop_sampler.set()
    for sampler_task in sampler_tasks:
        await sampler_task

    ok_count = sum(1 for item in results if item.ok)
    fail_count = len(results) - ok_count
    latencies = [item.elapsed_ms for item in results]
    ok_latencies = [item.elapsed_ms for item in results if item.ok]
    status_counts = Counter(str(item.status_code) if item.status_code else "exception" for item in results)
    error_counts = Counter(item.error_type for item in results if not item.ok)

    print("压测结果:")
    print(f"  total_elapsed: {elapsed:.2f}s")
    print(f"  throughput: {len(results) / elapsed:.2f} req/s")
    print(f"  success: {ok_count}")
    print(f"  failed: {fail_count}")
    print(f"  success_rate: {ok_count / len(results) * 100:.2f}%")
    print(f"  status_counts: {dict(status_counts)}")
    print()

    print("延迟统计，单位 ms:")
    print(f"  all_avg: {statistics.mean(latencies):.1f}")
    print(f"  all_p50: {percentile(latencies, 50):.1f}")
    print(f"  all_p90: {percentile(latencies, 90):.1f}")
    print(f"  all_p95: {percentile(latencies, 95):.1f}")
    print(f"  all_p99: {percentile(latencies, 99):.1f}")
    print(f"  all_max: {max(latencies):.1f}")
    if ok_latencies:
        print(f"  ok_avg: {statistics.mean(ok_latencies):.1f}")
        print(f"  ok_p95: {percentile(ok_latencies, 95):.1f}")
        print(f"  ok_p99: {percentile(ok_latencies, 99):.1f}")
    print()

    if error_counts:
        print("错误分布:")
        for error_type, count in error_counts.most_common():
            print(f"  {error_type}: {count}")

        printed = 0
        seen = set()
        for item in results:
            key = (item.error_type, item.error_sample)
            if item.ok or key in seen:
                continue
            seen.add(key)
            printed += 1
            print(f"  sample[{printed}] {item.error_type}: {item.error_sample}")
            if printed >= args.print_errors:
                break
        print()

    if process_samples:
        cpu_values = [item.cpu_percent for item in process_samples]
        mem_values = [item.mem_percent for item in process_samples]
        rss_values = [item.rss_kb for item in process_samples]
        print("服务器进程采样:")
        print(f"  samples: {len(process_samples)}")
        print(f"  cpu_avg: {statistics.mean(cpu_values):.1f}%")
        print(f"  cpu_max: {max(cpu_values):.1f}%")
        print(f"  mem_max: {max(mem_values):.1f}%")
        print(f"  rss_max_mb: {max(rss_values) / 1024.0:.1f}")
    elif args.server_pid:
        print("服务器进程采样: 未采集到数据，请确认 --server-pid 是否正确。")
    elif not args.docker_container:
        print("服务器进程采样: 未启用。需要采样 CPU/内存时传 --server-pid <PID>。")

    if docker_samples:
        cpu_values = [item.cpu_percent for item in docker_samples]
        mem_values = [item.mem_percent for item in docker_samples]
        mem_usage_values = [item.mem_usage_bytes for item in docker_samples]
        pid_values = [item.pids for item in docker_samples if item.pids is not None]
        latest = docker_samples[-1]
        print()
        print("Docker 容器采样:")
        print(f"  samples: {len(docker_samples)}")
        print(f"  cpu_avg: {statistics.mean(cpu_values):.1f}%")
        print(f"  cpu_max: {max(cpu_values):.1f}%")
        print(f"  mem_max: {max(mem_values):.1f}%")
        print(f"  mem_usage_max_mb: {max(mem_usage_values) / 1024.0 / 1024.0:.1f}")
        if pid_values:
            print(f"  pids_max: {max(pid_values)}")
        print(f"  latest_net_io: {latest.net_io}")
        print(f"  latest_block_io: {latest.block_io}")
    elif args.docker_container:
        print()
        print("Docker 容器采样: 未采集到数据，请确认容器名和 docker 权限。")

    return 0 if fail_count == 0 else 1


def main() -> int:
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

    args = parse_args()
    if args.examples:
        print(EXAMPLES)
        return 0
    try:
        return asyncio.run(run_test(args))
    except KeyboardInterrupt:
        print("已中断。", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
