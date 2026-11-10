"""Check that the app can reach its database."""
import socket
import sys
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent


def load_env():
    env = {}
    for line in (ROOT / ".env").read_text().splitlines():
        if "=" in line and not line.lstrip().startswith("#"):
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


def main():
    url = urlparse(load_env()["DATABASE_URL"])
    host, port = url.hostname, url.port or 5432
    try:
        with socket.create_connection((host, port), timeout=2):
            print("database reachable")
    except OSError as e:
        print(f"ERROR: could not connect to database at {host}:{port} ({e})", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
