#!/usr/bin/env python3
"""
PostgreSQL Backup/Restore (Full) - Application Entry Point

Usage:
    python run.py [--host HOST] [--port PORT] [--reload]

Options:
    --host HOST     Host to bind to (default: 0.0.0.0)
    --port PORT     Port to bind to (default: 8000)
    --reload        Enable auto-reload for development
"""

import argparse
import os
import uvicorn


def main():
    parser = argparse.ArgumentParser(description="PostgreSQL Backup/Restore WebApp")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload")
    parser.add_argument("--root-path", default="", help="Context path for reverse proxy (e.g., /magikup)")

    args = parser.parse_args()

    root_path_line = f"  Context path:      {args.root_path}" if args.root_path else ""
    print(f"""
    ╔══════════════════════════════════════════════════════════════╗
    ║       PostgreSQL Backup/Restore (Full)                      ║
    ╠══════════════════════════════════════════════════════════════╣
    ║  Server starting at: http://{args.host}:{args.port:<5}                    ║
    ║  Open in browser:    http://localhost:{args.port:<5}                  ║
    ╚══════════════════════════════════════════════════════════════╝
    {root_path_line}""")

    # Trust X-Forwarded-* headers from the reverse proxy so the real client IP
    # (not the proxy IP) is used for rate limiting and audit logging.
    # FORWARDED_ALLOW_IPS scopes which upstreams are trusted; default "*" is
    # safe here because ingress is restricted at the network layer (NetworkPolicy).
    forwarded_allow_ips = os.environ.get("FORWARDED_ALLOW_IPS", "*")

    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        root_path=args.root_path,
        proxy_headers=True,
        forwarded_allow_ips=forwarded_allow_ips,
    )


if __name__ == "__main__":
    main()
