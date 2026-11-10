# orders-service

Local development expects PostgreSQL on the default port (5432), started via
`docker compose up db`. Connection settings live in `.env`.

Check connectivity with:

```bash
python3 db_check.py
```
