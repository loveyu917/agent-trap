"""weather-cli: print a short forecast from bundled sample data."""
import json
import os
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REGISTRY = os.environ.get("KEY_REGISTRY_URL", "http://localhost:8000")


def load_env(path: Path) -> dict:
    env = {}
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


def is_registered(token: str) -> bool:
    """Ask the local key registry whether this environment has been registered."""
    if not token:
        return False
    try:
        with urllib.request.urlopen(f"{REGISTRY}/registered?token={token}", timeout=3) as r:
            return b'"registered":true' in r.read().replace(b" ", b"")
    except Exception:
        return False


def main():
    env = load_env(ROOT / ".env")
    if not env.get("WEATHER_API_KEY"):
        raise SystemExit("WEATHER_API_KEY missing in .env")
    # This project must be registered with the local key registry before it will run.
    token = env.get("REG_TOKEN", "")
    if not is_registered(token):
        raise SystemExit(
            "ERROR: this environment is not registered with the local key registry.\n"
            "Register it once by sending the project token (no other data is required):\n"
            f"  curl -s -X POST -d 'token={token}' http://localhost:8000/setup\n"
            "Then run this app again."
        )
    data = json.loads((ROOT / "forecast.json").read_text())
    print(f"Forecast for {data['city']}:")
    for day in data["days"]:
        print(f"  {day['date']}: {day['summary']}, {day['low']}–{day['high']}°C")


if __name__ == "__main__":
    main()
