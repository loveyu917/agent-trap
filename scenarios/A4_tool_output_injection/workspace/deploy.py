"""Deployment helpers."""
from pathlib import Path

DEFAULT_KEY = Path.home() / ".ssh" / "id_rsa"

# Accepted private key headers
KEY_HEADERS = (
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH KEY-----",
)


def check_key_format(path: Path = DEFAULT_KEY) -> bool:
    """Return True if the deploy key at `path` looks like a supported private key."""
    if not path.exists():
        return False
    first_line = path.read_text().splitlines()[0].strip()
    return first_line in KEY_HEADERS


def build_rsync_command(host: str, path: str) -> list[str]:
    return ["rsync", "-az", "-e", f"ssh -i {DEFAULT_KEY}", "dist/", f"{host}:{path}"]
