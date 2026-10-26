# ShieldDNS (starter)

A custom DNS-over-HTTPS filtering prototype with a small dashboard, blocklist management API, and upstream DoH forwarding.

## What this starter does
- Implements RFC 8484-style DoH GET and POST at `/dns-query`.
- Parses DNS wire messages with dnspython.
- Blocks domains in `blocklist.txt` by returning NXDOMAIN.
- Forwards allowed requests to an upstream DoH resolver.
- Includes basic per-source-IP rate limiting and token-protected admin endpoints.
- Provides a dashboard at `/`.

## What it does NOT do yet
- DNS-over-TLS (DoT), so it cannot be used directly as Android Private DNS yet.
- Durable metrics/database, per-user profiles, production-grade distributed rate limiting, or a full authentication system.
- Full production hardening. Treat as a development prototype, not a public production resolver.

## Run locally
Requires Python 3.11+ or Docker.

```bash
cp .env.example .env
# Edit .env and set a long random ADMIN_TOKEN.
docker compose up --build
```

Dashboard: http://127.0.0.1:8080/  
Health: http://127.0.0.1:8080/health

For local Python instead of Docker:

```bash
python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows:
# .venv\Scripts\activate
pip install -r requirements.txt
export ADMIN_TOKEN='replace-with-a-long-random-secret'
uvicorn app:app --host 127.0.0.1 --port 8080
```

## Admin API
Send the token in `X-Admin-Token`.

```bash
curl -H 'X-Admin-Token: YOUR_TOKEN' http://127.0.0.1:8080/admin/stats

curl -X POST http://127.0.0.1:8080/admin/blocklist \
  -H 'X-Admin-Token: YOUR_TOKEN' \
  -H 'Content-Type: application/json' \
  -d '{"domain":"ads.example.org"}'

curl -X DELETE -H 'X-Admin-Token: YOUR_TOKEN' \
  http://127.0.0.1:8080/admin/blocklist/ads.example.org
```

## Deployment outline
1. Create a VPS with a static public IP.
2. Point a domain/subdomain (e.g. `dns.yourdomain.tld`) to the VPS.
3. Install Docker and Docker Compose.
4. Put this project on the VPS; create `.env` with a strong secret.
5. Keep app port 8080 bound to localhost (as in compose).
6. Put Caddy or Nginx in front to terminate HTTPS and obtain/renew a TLS certificate. Proxy `/dns-query`, `/admin/*`, `/health`, and `/` to `127.0.0.1:8080`.
7. Protect the dashboard/admin routes with additional access controls. Do not expose admin endpoints publicly without authentication and edge rate limits.
8. Test DoH from a client before inviting users.

## Public service safety checklist before launch
- Add distributed rate limiting (e.g. Redis) and request-size/time limits at the reverse proxy.
- Restrict admin dashboard/API by VPN or IP allowlist; use strong auth and rotate secrets.
- Add persistent database-backed counters, monitoring, alerts, and automated backups.
- Establish a privacy policy and a short, documented log-retention period. Avoid retaining full query histories or client IPs unless genuinely necessary.
- Add blocklist source management, signature/checksum validation, update scheduling, and allowlist controls.
- Load test and test failure behavior. Keep a fallback resolver and monitor upstream latency.
- Review your VPS provider's acceptable-use policy and prepare abuse-contact procedures.
- Do not run an unrestricted UDP/TCP port-53 recursive resolver on the public internet.

## Protocol references
- DoH specification: https://datatracker.ietf.org/doc/rfc8484/
- dnspython docs: https://dnspython.readthedocs.io/
- FastAPI HTTPS deployment guidance: https://fastapi.tiangolo.com/deployment/https/
