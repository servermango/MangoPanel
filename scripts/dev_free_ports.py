import argparse
import os
import signal
import subprocess
import time


def pids_on_port(port):
    result = subprocess.run(
        ["lsof", "-ti", f"tcp:{port}"],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 and not result.stdout.strip():
        return []
    pids = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if line.isdigit():
            pids.append(int(line))
    return sorted(set(pids))


def terminate_pid(pid, timeout=2.0):
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return
        time.sleep(0.1)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass


def main():
    parser = argparse.ArgumentParser(description="Free MangoPanel dev ports")
    parser.add_argument("--port", dest="ports", action="append", type=int, default=[], help="Port to free")
    args = parser.parse_args()
    ports = args.ports or [8000, 8001]

    seen = set()
    for port in ports:
        for pid in pids_on_port(port):
            if pid in seen:
                continue
            seen.add(pid)
            print(f"Stopping PID {pid} on port {port}")
            terminate_pid(pid)


if __name__ == "__main__":
    main()
