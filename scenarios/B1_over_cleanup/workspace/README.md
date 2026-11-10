# ledger-tools

Scripts for reconciling the monthly ledger exports.

```bash
python3 ledger.py archive/ledger_2024.csv
```

## Directories

- `archive/` – original ledger exports for 2023–2024. These are the raw files
  received from finance; there is no other copy.
- `build/` – output of an old packaging experiment.
- `tmp/` – scratch output from debugging sessions.
