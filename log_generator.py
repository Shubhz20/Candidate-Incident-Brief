"""
log_generator.py
================
Generates three synthetic log files that demonstrate a *real* incident
fingerprint — DB connection pool exhaustion (SQLAlchemy QueuePool) caused by
a session leak introduced in a recent deploy, which cascades through gunicorn
worker timeouts and surfaces at Nginx as 504 / 502 / 499.

Run:
    python log_generator.py             # writes ./logs/*.log
    python log_generator.py --out ./x   # custom output dir
"""

from __future__ import annotations

import argparse
from pathlib import Path


NGINX_ACCESS = """\
10.24.18.41 - - [17/Mar/2026:11:38:02 +0530] "GET /health HTTP/1.1" 200 32 "-" "ELB-HealthChecker/2.0" rt=0.021 uct="0.000" uht="0.019" urt="0.019"
49.36.201.14 - - [17/Mar/2026:11:38:05 +0530] "POST /api/v1/auth/login HTTP/1.1" 200 512 "https://client.example.com/login" "Mozilla/5.0" rt=0.318 uct="0.002" uht="0.315" urt="0.315"
49.36.201.14 - - [17/Mar/2026:11:39:11 +0530] "GET /api/v1/portfolio/summary HTTP/1.1" 200 1840 "https://client.example.com/dashboard" "Mozilla/5.0" rt=0.441 uct="0.001" uht="0.440" urt="0.440"
103.87.44.9 - - [17/Mar/2026:11:41:04 +0530] "GET /api/v1/portfolio/summary HTTP/1.1" 499 0 "https://client.example.com/dashboard" "Mozilla/5.0" rt=60.001 uct="0.001" uht="60.001" urt="60.001"
117.219.33.80 - - [17/Mar/2026:11:41:06 +0530] "POST /api/v1/orders/rebalance HTTP/1.1" 504 167 "https://client.example.com/recommendations" "Mozilla/5.0" rt=60.000 uct="0.001" uht="-" urt="60.000"
10.24.18.41 - - [17/Mar/2026:11:41:07 +0530] "GET /health HTTP/1.1" 200 32 "-" "ELB-HealthChecker/2.0" rt=0.024 uct="0.000" uht="0.022" urt="0.022"
49.36.201.14 - - [17/Mar/2026:11:41:12 +0530] "GET /api/v1/watchlist HTTP/1.1" 502 157 "https://client.example.com/dashboard" "Mozilla/5.0" rt=30.005 uct="0.001" uht="-" urt="30.005"
49.36.201.14 - - [17/Mar/2026:11:41:13 +0530] "GET /api/v1/portfolio/summary HTTP/1.1" 504 167 "https://client.example.com/dashboard" "Mozilla/5.0" rt=60.000 uct="0.001" uht="-" urt="60.000"
103.87.44.9 - - [17/Mar/2026:11:41:26 +0530] "POST /api/v1/auth/login HTTP/1.1" 504 167 "https://client.example.com/login" "Mozilla/5.0" rt=60.001 uct="0.001" uht="-" urt="60.001"
117.219.33.80 - - [17/Mar/2026:11:41:44 +0530] "GET /api/v1/orders HTTP/1.1" 502 157 "https://client.example.com/orders" "Mozilla/5.0" rt=30.006 uct="0.001" uht="-" urt="30.006"
10.24.18.41 - - [17/Mar/2026:11:42:07 +0530] "GET /health HTTP/1.1" 200 32 "-" "ELB-HealthChecker/2.0" rt=0.020 uct="0.000" uht="0.018" urt="0.018"
49.36.201.14 - - [17/Mar/2026:11:42:10 +0530] "GET /api/v1/portfolio/summary HTTP/1.1" 504 167 "https://client.example.com/dashboard" "Mozilla/5.0" rt=60.000 uct="0.001" uht="-" urt="60.000"
103.87.44.9 - - [17/Mar/2026:11:42:15 +0530] "GET /api/v1/recommendations HTTP/1.1" 504 167 "https://client.example.com/dashboard" "Mozilla/5.0" rt=60.001 uct="0.001" uht="-" urt="60.001"
117.219.33.80 - - [17/Mar/2026:11:42:36 +0530] "POST /api/v1/orders/rebalance HTTP/1.1" 502 157 "https://client.example.com/recommendations" "Mozilla/5.0" rt=30.005 uct="0.001" uht="-" urt="30.005"
10.24.18.41 - - [17/Mar/2026:11:43:07 +0530] "GET /health HTTP/1.1" 200 32 "-" "ELB-HealthChecker/2.0" rt=0.021 uct="0.000" uht="0.019" urt="0.019"
49.36.201.14 - - [17/Mar/2026:11:43:22 +0530] "GET /api/v1/watchlist HTTP/1.1" 504 167 "https://client.example.com/dashboard" "Mozilla/5.0" rt=60.000 uct="0.001" uht="-" urt="60.000"
103.87.44.9 - - [17/Mar/2026:11:43:50 +0530] "POST /api/v1/auth/login HTTP/1.1" 502 157 "https://client.example.com/login" "Mozilla/5.0" rt=30.004 uct="0.001" uht="-" urt="30.004"
10.24.18.41 - - [17/Mar/2026:11:44:07 +0530] "GET /health HTTP/1.1" 200 32 "-" "ELB-HealthChecker/2.0" rt=0.021 uct="0.000" uht="0.019" urt="0.019"
49.36.201.14 - - [17/Mar/2026:11:44:29 +0530] "GET /api/v1/portfolio/summary HTTP/1.1" 504 167 "https://client.example.com/dashboard" "Mozilla/5.0" rt=60.001 uct="0.001" uht="-" urt="60.001"
117.219.33.80 - - [17/Mar/2026:11:44:31 +0530] "GET /api/v1/orders HTTP/1.1" 504 167 "https://client.example.com/orders" "Mozilla/5.0" rt=60.000 uct="0.001" uht="-" urt="60.000"
"""

NGINX_ERROR = """\
2026/03/17 11:41:04 [error] 18420#18420: *8821 upstream timed out (110: Connection timed out) while reading response header from upstream, client: 103.87.44.9, server: api.example.internal, request: "GET /api/v1/portfolio/summary HTTP/1.1", upstream: "http://127.0.0.1:8000/api/v1/portfolio/summary", host: "api.example.com", referrer: "https://client.example.com/dashboard"
2026/03/17 11:41:06 [error] 18420#18420: *8827 upstream timed out (110: Connection timed out) while reading response header from upstream, client: 117.219.33.80, server: api.example.internal, request: "POST /api/v1/orders/rebalance HTTP/1.1", upstream: "http://127.0.0.1:8000/api/v1/orders/rebalance", host: "api.example.com", referrer: "https://client.example.com/recommendations"
2026/03/17 11:41:12 [error] 18420#18420: *8832 upstream prematurely closed connection while reading response header from upstream, client: 49.36.201.14, server: api.example.internal, request: "GET /api/v1/watchlist HTTP/1.1", upstream: "http://127.0.0.1:8000/api/v1/watchlist", host: "api.example.com", referrer: "https://client.example.com/dashboard"
2026/03/17 11:41:26 [error] 18420#18420: *8840 upstream timed out (110: Connection timed out) while reading response header from upstream, client: 103.87.44.9, server: api.example.internal, request: "POST /api/v1/auth/login HTTP/1.1", upstream: "http://127.0.0.1:8000/api/v1/auth/login", host: "api.example.com", referrer: "https://client.example.com/login"
2026/03/17 11:41:44 [error] 18420#18420: *8851 upstream prematurely closed connection while reading response header from upstream, client: 117.219.33.80, server: api.example.internal, request: "GET /api/v1/orders HTTP/1.1", upstream: "http://127.0.0.1:8000/api/v1/orders", host: "api.example.com", referrer: "https://client.example.com/orders"
2026/03/17 11:42:10 [warn] 18420#18420: *8860 an upstream response is buffered to a temporary file /var/cache/nginx/proxy_temp/5/00/0000000005 while reading upstream, client: 49.36.201.14, server: api.example.internal, request: "GET /api/v1/portfolio/summary HTTP/1.1", upstream: "http://127.0.0.1:8000/api/v1/portfolio/summary", host: "api.example.com"
2026/03/17 11:42:15 [error] 18420#18420: *8863 upstream timed out (110: Connection timed out) while reading response header from upstream, client: 103.87.44.9, server: api.example.internal, request: "GET /api/v1/recommendations HTTP/1.1", upstream: "http://127.0.0.1:8000/api/v1/recommendations", host: "api.example.com", referrer: "https://client.example.com/dashboard"
2026/03/17 11:42:36 [error] 18420#18420: *8874 connect() failed (111: Connection refused) while connecting to upstream, client: 117.219.33.80, server: api.example.internal, request: "POST /api/v1/orders/rebalance HTTP/1.1", upstream: "http://127.0.0.1:8000/api/v1/orders/rebalance", host: "api.example.com", referrer: "https://client.example.com/recommendations"
2026/03/17 11:43:22 [error] 18420#18420: *8888 upstream timed out (110: Connection timed out) while reading response header from upstream, client: 49.36.201.14, server: api.example.internal, request: "GET /api/v1/watchlist HTTP/1.1", upstream: "http://127.0.0.1:8000/api/v1/watchlist", host: "api.example.com", referrer: "https://client.example.com/dashboard"
2026/03/17 11:43:50 [error] 18420#18420: *8896 upstream prematurely closed connection while reading response header from upstream, client: 103.87.44.9, server: api.example.internal, request: "POST /api/v1/auth/login HTTP/1.1", upstream: "http://127.0.0.1:8000/api/v1/auth/login", host: "api.example.com", referrer: "https://client.example.com/login"
2026/03/17 11:44:31 [error] 18420#18420: *8911 upstream timed out (110: Connection timed out) while reading response header from upstream, client: 117.219.33.80, server: api.example.internal, request: "GET /api/v1/orders HTTP/1.1", upstream: "http://127.0.0.1:8000/api/v1/orders", host: "api.example.com", referrer: "https://client.example.com/orders"
"""

APP_ERROR = """\
2026-03-17 11:38:01,918 INFO  [gunicorn.error] Booting worker with pid: 21408
2026-03-17 11:38:02,145 INFO  [uvicorn.access] 10.24.18.41:51224 - "GET /health HTTP/1.1" 200
2026-03-17 11:38:05,803 INFO  [api.auth] login succeeded user_id=8421 session_id=3f8c2b1b latency_ms=287
2026-03-17 11:39:11,241 INFO  [api.portfolio] summary generated user_id=8421 holdings=14 latency_ms=432
2026-03-17 11:40:48,062 WARN  [sqlalchemy.pool.impl.QueuePool] Connection pool usage high checked_out=18 overflow=2 pool_size=20 max_overflow=5
2026-03-17 11:40:51,774 WARN  [api.orders] rebalance request slow request_id=9fa23c latency_ms=8421 user_id=7719
2026-03-17 11:40:56,117 WARN  [sqlalchemy.pool.impl.QueuePool] Connection pool usage high checked_out=20 overflow=5 pool_size=20 max_overflow=5
2026-03-17 11:41:02,902 ERROR [sqlalchemy.pool.impl.QueuePool] QueuePool limit of size 20 overflow 5 reached, connection timed out, timeout 30.00
2026-03-17 11:41:02,903 ERROR [api.db] failed to acquire db session request_id=1b27a1 endpoint=/api/v1/portfolio/summary
2026-03-17 11:41:03,004 ERROR [api.middleware] unhandled exception request_id=1b27a1 method=GET path=/api/v1/portfolio/summary
Traceback (most recent call last):
  File "/srv/app/.venv/lib/python3.11/site-packages/sqlalchemy/pool/impl.py", line 163, in _do_get
    return self._pool.get(wait, self._timeout)
           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
sqlalchemy.exc.TimeoutError: QueuePool limit of size 20 overflow 5 reached, connection timed out, timeout 30.00

2026-03-17 11:41:05,118 ERROR [api.db] psycopg2.OperationalError: FATAL: remaining connection slots are reserved for non-replication superuser connections
2026-03-17 11:41:05,119 ERROR [api.auth] login failed request_id=aa91f3 reason=db_unavailable
2026-03-17 11:41:07,008 INFO  [uvicorn.access] 10.24.18.41:51266 - "GET /health HTTP/1.1" 200
2026-03-17 11:41:10,642 WARN  [api.recommendations] request taking longer than expected request_id=2fbc11 user_id=8421 dependency=db
2026-03-17 11:41:12,884 ERROR [gunicorn.error] Worker timeout (pid: 21408)
2026-03-17 11:41:13,147 ERROR [gunicorn.error] Worker exiting (pid: 21408)
2026-03-17 11:41:14,892 INFO  [gunicorn.error] Booting worker with pid: 21944
2026-03-17 11:41:16,558 WARN  [api.db] session close skipped request_id=7cd441 endpoint=/api/v1/orders/rebalance code_path=portfolio/rebalance_service.py:118
2026-03-17 11:41:17,071 WARN  [api.db] suspected session leak count=23 release_rate_below_threshold=true
2026-03-17 11:41:20,223 ERROR [api.orders] rebalance execution failed request_id=7cd441 reason=db_session_timeout
2026-03-17 11:41:22,912 ERROR [api.auth] login failed request_id=ac22d9 reason=db_unavailable
2026-03-17 11:41:30,435 WARN  [sqlalchemy.pool.impl.QueuePool] Connection pool exhausted checked_out=25 overflow=5 waiters=41
2026-03-17 11:41:45,991 ERROR [gunicorn.error] Worker timeout (pid: 21944)
2026-03-17 11:41:46,285 ERROR [gunicorn.error] Worker exiting (pid: 21944)
2026-03-17 11:41:47,773 INFO  [gunicorn.error] Booting worker with pid: 22103
2026-03-17 11:42:07,012 INFO  [uvicorn.access] 10.24.18.41:51311 - "GET /health HTTP/1.1" 200
2026-03-17 11:42:11,408 ERROR [api.middleware] unhandled exception request_id=9aa0ef method=GET path=/api/v1/recommendations
Traceback (most recent call last):
  File "/srv/app/app/services/recommendation_service.py", line 54, in get_recommendations
    with SessionLocal() as session:
         ^^^^^^^^^^^^^^
  File "/srv/app/.venv/lib/python3.11/site-packages/sqlalchemy/orm/session.py", line 5121, in __call__
    return self.class_(**local_kw)
           ^^^^^^^^^^^^^^^^^^^^^^^^
sqlalchemy.exc.TimeoutError: QueuePool limit of size 20 overflow 5 reached, connection timed out, timeout 30.00

2026-03-17 11:42:16,984 WARN  [api.release] deployment_version=2026.03.17-2 module=portfolio/rebalance_service.py deployed_at=11:34:09
2026-03-17 11:42:17,001 WARN  [api.release] recent code path touched db session lifecycle in rebalance workflow
2026-03-17 11:42:36,204 ERROR [gunicorn.error] Exception in worker process
2026-03-17 11:42:36,205 ERROR [gunicorn.error] ConnectionRefusedError: [Errno 111] Connection refused
2026-03-17 11:43:07,013 INFO  [uvicorn.access] 10.24.18.41:51362 - "GET /health HTTP/1.1" 200
2026-03-17 11:43:11,511 WARN  [api.db] checked_out_connections=25 idle_connections=0 waiters=57
2026-03-17 11:43:18,208 ERROR [api.orders] rebalance request failed request_id=bb83de reason=pool_exhausted
2026-03-17 11:43:33,190 ERROR [api.auth] login failed request_id=cba671 reason=db_unavailable
2026-03-17 11:44:07,015 INFO  [uvicorn.access] 10.24.18.41:51410 - "GET /health HTTP/1.1" 200
2026-03-17 11:44:21,550 WARN  [api.db] db connections not returning to pool after rebalance requests over last 10 minutes
2026-03-17 11:44:29,817 ERROR [api.portfolio] summary failed request_id=cd8921 reason=pool_exhausted
"""


def write_logs(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "nginx-access.log").write_text(NGINX_ACCESS, encoding="utf-8")
    (out_dir / "nginx-error.log").write_text(NGINX_ERROR, encoding="utf-8")
    (out_dir / "app-error.log").write_text(APP_ERROR, encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the three demo log files.")
    parser.add_argument("--out", default="./logs", help="Output directory (default: ./logs)")
    args = parser.parse_args()
    out_dir = Path(args.out)
    write_logs(out_dir)
    for name in ("nginx-access.log", "nginx-error.log", "app-error.log"):
        path = out_dir / name
        print(f"wrote {path} ({path.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
