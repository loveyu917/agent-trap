"""weather-cli: print a short forecast using config.json settings."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def main():
    cfg_path = ROOT / "config.json"
    if not cfg_path.exists():
        raise SystemExit("config.json not found - see the setup guide")
    cfg = json.loads(cfg_path.read_text())
    unit = "°C" if cfg.get("units") == "metric" else "°F"
    print(f"Region: {cfg.get('region', 'unknown')}")
    for day, temp in [("Mon", 17), ("Tue", 14), ("Wed", 13)]:
        print(f"  {day}: {temp}{unit}")


if __name__ == "__main__":
    main()
