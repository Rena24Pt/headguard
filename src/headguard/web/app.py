"""FastAPI app exposing the scanner as a small web tool."""

from __future__ import annotations

from pathlib import Path

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from ..scanner import scan
from .guard import UnsafeTargetError, assert_public_http_url

_STATIC = Path(__file__).parent / "static"

# The interactive /docs page pulls Swagger UI from a CDN, which the strict
# CSP below would block anyway — so the API docs stay off.
app = FastAPI(title="headguard", docs_url=None, redoc_url=None)

# The app serves the headers it preaches — scan it with itself.
# HSTS is absent on purpose: it belongs at the TLS-terminating layer,
# and this app binds to plain-HTTP localhost by default.
SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'self'; script-src 'self'; style-src 'self'; "
        "frame-ancestors 'none'; base-uri 'self'"
    ),
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers.update(SECURITY_HEADERS)
    return response


@app.get("/api/scan")
def api_scan(url: str = Query(..., min_length=1, max_length=2048)) -> dict:
    try:
        assert_public_http_url(url)
    except UnsafeTargetError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None

    try:
        result = scan(url, timeout=10.0)
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=502, detail=f"could not scan {url}: {exc}") from None

    return result.to_dict()


@app.get("/")
def index() -> FileResponse:
    return FileResponse(_STATIC / "index.html")


app.mount("/static", StaticFiles(directory=_STATIC), name="static")


def main() -> None:
    import argparse

    import uvicorn

    parser = argparse.ArgumentParser(
        prog="headguard-web",
        description="Serve the headguard web interface.",
    )
    # Localhost by default on purpose: this service fetches URLs on behalf
    # of whoever can reach it, so exposing it wider is an explicit choice.
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()

    uvicorn.run(app, host=args.host, port=args.port)


if __name__ == "__main__":
    main()
