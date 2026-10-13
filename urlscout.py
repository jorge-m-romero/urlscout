#!/usr/bin/env python3
"""urlscout - check a list of URLs against VirusTotal.

Accepts defanged input (hxxp://evil[.]com), skips internal URLs, and can
optionally submit URLs VirusTotal has never seen.

Standard library only: no pip install needed.
"""

from __future__ import annotations

import argparse
import base64
import csv
import http.client
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

__version__ = "0.1.0"

USER_AGENT = f"urlscout/{__version__}"
VT_API = "https://www.virustotal.com/api/v3"
VT_GUI_URL = "https://www.virustotal.com/gui/url/{id}"
MAX_RESPONSE_BYTES = 1_000_000
CSV_FORMULA_CHARS = ("=", "+", "-", "@", "\t", "\r")
INTERNAL_SUFFIXES = (".localhost", ".local", ".internal", ".lan", ".home.arpa", ".corp")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

FIELDS = [
    "url", "scope", "domain", "vt_verdict", "vt_malicious", "vt_suspicious",
    "vt_harmless", "vt_undetected", "vt_reputation", "vt_categories",
    "vt_final_url", "vt_title", "vt_last_analysis", "vt_link", "error",
]


class RateLimited(Exception):
    """Raised when an API answers HTTP 429. Carries no URL, so tokens can't leak."""


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects: urllib would otherwise forward our API-key header to
    whatever host the redirect points at."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_opener = urllib.request.build_opener(NoRedirect)


def clean(value):
    """Drop control characters (e.g. ANSI escapes) from text that came from
    the input or an API, so it can't mess with the terminal or files."""
    return "".join(ch for ch in str(value or "") if ch.isprintable())


# --------------------------------------------------------------------------- input

_REFANG = [
    (re.compile(r"^h(xx|\*\*|XX)p", re.I), "http"),
    (re.compile(r"\[\s*(\.|dot)\s*\]|\(\s*(\.|dot)\s*\)|\{\s*(\.|dot)\s*\}", re.I), "."),
    (re.compile(r"\[\s*:\s*\]"), ":"),
    (re.compile(r"\[\s*://\s*\]"), "://"),
]


def refang(text):
    """Undo common defanging: hxxp -> http, [.] / (.) / [dot] -> ., [:] -> :"""
    text = text.strip().strip("<>\"'")
    for pattern, repl in _REFANG:
        text = pattern.sub(repl, text)
    return text


def defang(url):
    """Make a URL safe to paste into chat/tickets: http -> hxxp, dots in the host -> [.]"""
    parts = urllib.parse.urlsplit(url)
    scheme = parts.scheme.replace("http", "hxxp", 1)
    netloc = parts.netloc.replace(".", "[.]")
    return urllib.parse.urlunsplit((scheme, netloc, parts.path, parts.query, parts.fragment))


def normalise_url(text):
    """Refang and validate one URL. Adds http:// when no scheme is given.
    Returns the URL, or None if it isn't a usable http(s) URL."""
    url = refang(text)
    if not url or not url.isprintable() or any(ch.isspace() for ch in url):
        return None
    if "://" not in url:
        url = "http://" + url
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return None
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return None
    return url


def is_internal(url):
    """True for URLs pointing at private IPs, localhost or internal-looking names.
    These are never sent to VirusTotal, so internal hostnames don't leak."""
    host = (urllib.parse.urlsplit(url).hostname or "").rstrip(".")  # "localhost." == "localhost"
    try:
        return not ipaddress.ip_address(host).is_global
    except ValueError:
        pass
    if re.fullmatch(r"[0-9a-fx.]+", host):
        # Legacy IPv4 forms browsers still accept (127.1, 0177.0.0.1, 0x7f000001)
        try:
            return not ipaddress.IPv4Address(socket.inet_aton(host)).is_global
        except OSError:
            pass
    return host == "localhost" or "." not in host or host.endswith(INTERNAL_SUFFIXES)


def ascii_host(url):
    """The host in its real (punycode) form, so look-alike Unicode domains
    such as 'gооgle.com' with Cyrillic o's show up as 'xn--...'."""
    host = urllib.parse.urlsplit(url).hostname or ""
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def load_urls(lines):
    """Parse URLs from an iterable of lines.

    Blank lines and lines starting with '#' are ignored, as is a ' #' comment
    after the URL (a '#' with no space before it is kept, since URLs use it
    for fragments). Duplicates are dropped (first one wins, order kept).
    Returns (urls, invalid) where invalid is a list of (line_number, text) tuples.
    """
    seen, urls, invalid = set(), [], []
    for lineno, line in enumerate(lines, 1):
        entry = re.split(r"\s#", line, maxsplit=1)[0].strip()
        if not entry or entry.startswith("#"):
            continue
        url = normalise_url(entry)
        if url is None:
            invalid.append((lineno, clean(entry)))
            continue
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls, invalid


# ----------------------------------------------------------------------- lookups

def http_json(url, headers=None, form=None, timeout=15):
    """GET (or POST, when form is given) a URL and decode JSON.
    Returns (status_code, data_or_None)."""
    data = urllib.parse.urlencode(form).encode() if form is not None else None
    req = urllib.request.Request(url, data=data,
                                 headers={"User-Agent": USER_AGENT, **(headers or {})})
    try:
        with _opener.open(req, timeout=timeout) as resp:
            body = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise ValueError("response too large")
            parsed = json.loads(body)
            return resp.status, parsed if isinstance(parsed, dict) else None
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise RateLimited() from None
        return e.code, None


def vt_url_id(url):
    """VirusTotal's URL identifier: unpadded URL-safe base64 of the URL."""
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")


def vt_verdict(stats):
    if not stats:
        return ""
    if stats.get("malicious", 0) > 0:
        return "MALICIOUS"
    if stats.get("suspicious", 0) > 0:
        return "SUSPICIOUS"
    return "clean"


def int_stats(stats):
    return {k: v for k, v in (stats or {}).items() if isinstance(v, int)}


def stats_fields(stats, sha):
    """The verdict/count fields shared by URL reports and fresh analyses."""
    row = {
        "vt_verdict": vt_verdict(stats) or "not analysed",
        "vt_malicious": stats.get("malicious", 0),
        "vt_suspicious": stats.get("suspicious", 0),
        "vt_harmless": stats.get("harmless", 0),
        "vt_undetected": stats.get("undetected", 0),
    }
    if isinstance(sha, str) and SHA256_RE.match(sha):
        row["vt_link"] = VT_GUI_URL.format(id=sha)
    return row


def check_auth(status):
    if status == 401:
        raise SystemExit("VirusTotal rejected the API key (HTTP 401).")


def vt_lookup(url, api_key):
    """Fetch VirusTotal's existing report for a URL (no submission)."""
    status, data = http_json(f"{VT_API}/urls/{vt_url_id(url)}", headers={"x-apikey": api_key})
    check_auth(status)
    if status == 404:
        return {"vt_verdict": "not found"}
    if status != 200 or not data:
        return {"error": f"VirusTotal: unexpected response (HTTP {status})"}
    obj = data.get("data") or {}
    attrs = obj.get("attributes") or {}
    row = stats_fields(int_stats(attrs.get("last_analysis_stats")), obj.get("id"))
    reputation = attrs.get("reputation")
    categories = attrs.get("categories")
    when = attrs.get("last_analysis_date")
    row.update({
        "vt_reputation": reputation if isinstance(reputation, int) else 0,
        "vt_categories": ", ".join(sorted({clean(c).lower() for c in categories.values()}))
                         if isinstance(categories, dict) else "",
        "vt_final_url": clean(attrs.get("last_final_url")),
        "vt_title": clean(attrs.get("title")),
        "vt_last_analysis": datetime.fromtimestamp(when, timezone.utc).strftime("%Y-%m-%d %H:%M")
                            if isinstance(when, int) else "",
    })
    return row


def vt_submit(url, api_key):
    """Submit a URL for scanning. Returns {'analysis_id': ...} or an error."""
    status, data = http_json(f"{VT_API}/urls", headers={"x-apikey": api_key}, form={"url": url})
    check_auth(status)
    analysis_id = ((data or {}).get("data") or {}).get("id")
    if status != 200 or not isinstance(analysis_id, str):
        return {"error": f"VirusTotal submit: unexpected response (HTTP {status})"}
    return {"analysis_id": analysis_id}


def vt_analysis(analysis_id, api_key):
    """Poll a submitted analysis. Returns {'status': 'queued'|'completed'|...} plus
    verdict fields once completed."""
    status, data = http_json(f"{VT_API}/analyses/{urllib.parse.quote(analysis_id, safe='')}",
                             headers={"x-apikey": api_key})
    check_auth(status)
    if status != 200 or not data:
        return {"error": f"VirusTotal analysis: unexpected response (HTTP {status})"}
    attrs = (data.get("data") or {}).get("attributes") or {}
    state = clean(attrs.get("status"))
    if state != "completed":
        return {"status": state or "unknown"}
    sha = ((data.get("meta") or {}).get("url_info") or {}).get("id")
    return {"status": "completed", **stats_fields(int_stats(attrs.get("stats")), sha)}


def with_retry(func, *args, wait=60, log=print):
    """Call func, waiting and retrying once if the API rate-limits us.
    Network and parsing errors become an 'error' field instead of a crash."""
    for attempt in (1, 2):
        try:
            return func(*args)
        except RateLimited:
            if attempt == 2:
                return {"error": "rate limited"}
            log(f"  rate limited, waiting {wait}s...")
            time.sleep(wait)
        except urllib.error.URLError as e:
            return {"error": f"network error: {clean(e.reason)}"}
        except (OSError, http.client.HTTPException, ValueError, OverflowError,
                RecursionError) as e:
            return {"error": f"{type(e).__name__}: {clean(e)}"}


class Throttle:
    """Keeps at least `delay` seconds between VirusTotal calls (free tier: 4/min)."""

    def __init__(self, delay):
        self.delay = delay
        self.last = None

    def wait(self, at_least=0.0):
        gap = max(self.delay, at_least)
        if self.last is not None:
            remaining = self.last + gap - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)
        self.last = time.monotonic()


def submit_and_wait(url, api_key, throttle, polls=4, poll_wait=20.0, log=print):
    """Submit an unknown URL, then poll until the analysis completes."""
    throttle.wait()
    sub = with_retry(vt_submit, url, api_key, log=log)
    if "error" in sub:
        return sub
    for _ in range(polls):
        throttle.wait(at_least=poll_wait)
        result = with_retry(vt_analysis, sub["analysis_id"], api_key, log=log)
        if "error" in result or result.get("status") == "completed":
            result.pop("status", None)
            return result
    return {"vt_verdict": "queued"}


def scan(url, api_key, throttle, submit=False, log=print):
    """Build the result row for one URL."""
    row = {"url": url, "domain": ascii_host(url)}
    if row["domain"] != urllib.parse.urlsplit(url).hostname:
        log(f"  note: non-ASCII host, real domain is {clean(row['domain'])} (look-alike characters?)")
    if is_internal(url):
        row["scope"] = "internal"
        return row
    row["scope"] = "public"
    throttle.wait()
    result = with_retry(vt_lookup, url, api_key, log=log)
    if result.get("vt_verdict") == "not found" and submit:
        log("  not known to VirusTotal, submitting for a scan...")
        result = submit_and_wait(url, api_key, throttle, log=log)
    row.update(result)
    return row


# ------------------------------------------------------------------------ output

def defang_row(row):
    out = dict(row, url=defang(row["url"]))
    if out.get("vt_final_url"):
        out["vt_final_url"] = defang(out["vt_final_url"])
    return out


def vt_summary(row):
    """Short VirusTotal cell for the console, e.g. 'MALICIOUS (5 mal, 1 sus)'."""
    if row["scope"] == "internal":
        return "(internal, skipped)"
    if "vt_malicious" in row:
        return f"{row['vt_verdict']} ({row['vt_malicious']} mal, {row['vt_suspicious']} sus)"
    return row.get("vt_verdict") or ("error" if row.get("error") else "-")


def print_table(rows, out=sys.stdout):
    cols = [("URL", "url", 60), ("VirusTotal", "vt", 28), ("Categories", "vt_categories", 30),
            ("Title", "vt_title", 30)]
    display = [dict(r, vt=vt_summary(r)) for r in rows]
    widths = [min(w, max([len(h)] + [len(str(d.get(k, ""))) for d in display]))
              for h, k, w in cols]
    fmt = "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*[h for h, _, _ in cols]), file=out)
    print(fmt.format(*["-" * w for w in widths]), file=out)
    for d in display:
        print(fmt.format(*[str(d.get(k, ""))[:w] for (_, k, _), w in zip(cols, widths)]), file=out)


def csv_safe(value):
    """Stop spreadsheet apps treating attacker-controlled text (e.g. a page title
    of '=HYPERLINK(...)') as a formula, by prefixing it with a quote."""
    if isinstance(value, str) and value.startswith(CSV_FORMULA_CHARS):
        return "'" + value
    return value


def write_csv(rows, path):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows({k: csv_safe(v) for k, v in r.items()} for r in rows)


def write_json(rows, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump([{k: r.get(k, "") for k in FIELDS} for r in rows], f, indent=2)


# -------------------------------------------------------------------------- main

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Check a list of URLs against VirusTotal. Defanged URLs "
                    "(hxxp://evil[.]com) are accepted.",
        epilog="The API key is read from the VT_API_KEY environment variable, so it "
               "doesn't end up in your shell history.",
    )
    p.add_argument("file", nargs="?",
                   help="text file with one URL per line ('-' for stdin)")
    p.add_argument("-u", "--url", action="append", default=[], metavar="URL",
                   help="URL to check; can be repeated, and combined with a file")
    p.add_argument("--submit", action="store_true",
                   help="submit URLs VirusTotal has never seen for a fresh scan. "
                        "Submitted URLs become visible to other VirusTotal users.")
    p.add_argument("--defang", action="store_true",
                   help="defang URLs in the output (hxxp://evil[.]com)")
    p.add_argument("--csv", metavar="PATH", help="also write results to CSV")
    p.add_argument("--json", metavar="PATH", help="also write results to JSON")
    p.add_argument("--vt-delay", type=float, default=15.0, metavar="SECONDS",
                   help="pause between VirusTotal calls (default 15, the free tier's 4/min; "
                        "use 0 for a premium key)")
    p.add_argument("-q", "--quiet", action="store_true", help="no progress messages")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)
    if not args.file and not args.url:
        p.error("give a file of URLs, '-' for stdin, or at least one --url")
    return args


def main(argv=None):
    args = parse_args(argv)
    log = (lambda *a, **k: None) if args.quiet else (lambda *a, **k: print(*a, file=sys.stderr, **k))

    vt_key = os.environ.get("VT_API_KEY", "").strip()
    if not vt_key:
        sys.exit("urlscout needs a VirusTotal API key in the VT_API_KEY environment variable.")
    if not vt_key.isprintable() or any(ch.isspace() for ch in vt_key):
        # http.client would echo the bad value (the key) in its error message
        sys.exit("VT_API_KEY contains spaces or control characters; check how it was set.")

    lines = list(args.url)
    try:
        if args.file == "-":
            lines += sys.stdin.readlines()
        elif args.file:
            with open(args.file, encoding="utf-8") as f:
                lines += f.readlines()
    except OSError as e:
        sys.exit(f"Cannot read {args.file}: {e.strerror}")
    urls, invalid = load_urls(lines)

    for lineno, text in invalid:
        log(f"warning: entry {lineno}: not an http(s) URL: {text!r}")
    if not urls:
        sys.exit("No valid URLs found.")

    public = sum(not is_internal(u) for u in urls)
    log(f"Checking {len(urls)} URL(s) ({public} on VirusTotal"
        + (f", ~{int(public * args.vt_delay)}s at {args.vt_delay:g}s apart" if args.vt_delay else "")
        + ")...")
    throttle = Throttle(args.vt_delay)
    rows = []
    for i, url in enumerate(urls, 1):
        log(f"  [{i}/{len(urls)}] {defang(url)}")
        rows.append(scan(url, vt_key, throttle, submit=args.submit, log=log))

    if args.defang:
        rows = [defang_row(r) for r in rows]
    print_table(rows)
    if args.csv:
        write_csv(rows, args.csv)
        log(f"CSV written to {args.csv}")
    if args.json:
        write_json(rows, args.json)
        log(f"JSON written to {args.json}")

    errors = [r for r in rows if r.get("error")]
    for r in errors:
        log(f"error: {r['url']}: {r['error']}")
    return 1 if errors else 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
