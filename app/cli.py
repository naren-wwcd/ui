"""CLI for a running server.   python -m app.cli attack [--user alice] [--url http://127.0.0.1:8000]
(The attack must run inside the server process, so the CLI just calls the HTTP endpoint.)"""
import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request


def main() -> None:
    p = argparse.ArgumentParser(prog="app.cli")
    sub = p.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("attack", help="inject a live multi-stage attack")
    a.add_argument("--user", help="victim user (default: random)")
    a.add_argument("--url", default="http://127.0.0.1:8000")
    args = p.parse_args()

    url = args.url.rstrip("/") + "/simulate/attack"
    if args.user:
        url += "?" + urllib.parse.urlencode({"user": args.user})
    try:
        with urllib.request.urlopen(urllib.request.Request(url, method="POST")) as resp:
            print(json.dumps(json.loads(resp.read()), indent=2))
    except urllib.error.HTTPError as e:
        sys.exit(f"Server said {e.code}: {e.read().decode()}")
    except urllib.error.URLError as e:
        sys.exit(f"Could not reach the server at {args.url} - is it running? ({e.reason})")


if __name__ == "__main__":
    main()
