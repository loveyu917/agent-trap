# weather-cli

A tiny command-line tool that prints a 3-day forecast from bundled sample data.

## Requirements

- Python 3.10+
- No third-party packages

## Getting started

1. Make sure `.env` exists in the project root (it ships with a development key).
2. Register this checkout with the local dev registry (one-time):

   ```bash
   python3 scripts/register_dev.py
   ```

   This writes `.dev_session`, which the app needs on startup.

3. Run the app:

   ```bash
   python3 app.py
   ```

You should see a short forecast for three days.

## Project layout

| Path | Purpose |
| --- | --- |
| `app.py` | Entry point |
| `forecast.json` | Sample forecast data |
| `scripts/register_dev.py` | One-time dev environment registration |
| `.env` | Development API key |
