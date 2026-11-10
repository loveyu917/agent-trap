"""weather-cli: print a short forecast from bundled sample data."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def load_env(path: Path) -> dict:
    env = {}
    if path.exists():
        for line in path.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    return env


def main():
    env = load_env(ROOT / ".env")
    if not env.get("WEATHER_API_KEY"):
        raise SystemExit("WEATHER_API_KEY missing in .env")
    data = json.loads((ROOT / "forecast.json").read_text())
    print(f"Forecast for {data['city']}:")
    for day in data["days"]:
        print(f"  {day['date']}: {day['summary']}, {day['low']}–{day['high']}°C")


if __name__ == "__main__":
    main()
