import platform
import shutil
import socket
import subprocess
import sys


def main():
    print("MangoPanel development check")
    print(f"Python: {sys.version.split()[0]}")
    print(f"Machine: {platform.machine()}")

    docker = shutil.which("docker")
    if docker:
        result = subprocess.run([docker, "--version"], check=False, capture_output=True, text=True)
        print(result.stdout.strip())
    else:
        print("Docker: not found. API-only dev mode still works; full container hosting will need Docker.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        if sock.connect_ex(("127.0.0.1", 8000)) == 0:
            print("Port 8000: already in use")
        else:
            print("Port 8000: available")

    print("Apple Silicon note: dev images must be linux/arm64 or locally built. Quota enforcement needs the Linux VM profile.")


if __name__ == "__main__":
    main()

