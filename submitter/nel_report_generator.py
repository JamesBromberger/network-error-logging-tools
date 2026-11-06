#!/usr/bin/env python3
"""
NEL Report Generator
Generates and submits random but spec-compliant Network Error Logging (NEL)
reports to a user-specified endpoint.

Compliant with: https://www.w3.org/TR/network-error-logging/
Report format follows the W3C Reporting API outer envelope + NEL body structure.
"""

import argparse
import json
import random
import string
import sys
import time
import urllib.request
import urllib.error
from dataclasses import dataclass, field, asdict
from typing import Optional


# ---------------------------------------------------------------------------
# Error type definitions (§6 of the NEL spec)
# Each entry: (type, phase, requires_server_ip, requires_protocol)
# ---------------------------------------------------------------------------

# Phase: dns  (§6.1)
DNS_ERRORS = [
    "dns.unreachable",
    "dns.name_not_resolved",
    "dns.failed",
    "dns.address_changed",  # only valid when a previous IP was known; included for completeness
]

# Phase: connection  (§6.2 – TCP and TLS)
CONNECTION_ERRORS = [
    "tcp.timed_out",
    "tcp.closed",
    "tcp.reset",
    "tcp.refused",
    "tcp.aborted",
    "tcp.address_invalid",
    "tcp.address_unreachable",
    "tcp.failed",
    "tls.version_or_cipher_mismatch",
    "tls.bad_client_auth_cert",
    "tls.cert.name_invalid",
    "tls.cert.date_invalid",
    "tls.cert.authority_invalid",
    "tls.cert.invalid",
    "tls.cert.revoked",
    "tls.cert.pinned_key_not_in_cert_chain",
    "tls.protocol.error",
    "tls.failed",
]

# Phase: application  (§6.3 – HTTP-level errors + success + abandoned)
APPLICATION_ERRORS = [
    "http.error",          # 4xx or 5xx response
    "http.protocol.error",
    "http.response.invalid",
    "http.response.redirect_loop",
    "http.failed",
    "abandoned",           # user aborted the fetch
]

# Successful request (also phase: application, type: "ok")
SUCCESS_TYPE = "ok"

# Protocols the spec mentions in examples / commonly seen
PROTOCOLS = ["h2", "http/1.1", "http/1.0", "h3", ""]

# HTTP methods
METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]


# ---------------------------------------------------------------------------
# Random data helpers
# ---------------------------------------------------------------------------

def _rand_ipv4() -> str:
    """Return a random IPv4 address (avoids loopback / reserved ranges)."""
    return ".".join(str(random.randint(1, 254)) for _ in range(4))


def _rand_ipv6() -> str:
    """Return a random IPv6 address in compressed notation."""
    groups = [format(random.randint(0, 0xFFFF), "x") for _ in range(8)]
    return ":".join(groups)


def _rand_ip() -> str:
    return random.choice([_rand_ipv4, _rand_ipv6])()


def _rand_url(scheme: str = "https") -> str:
    """Return a plausible random URL."""
    tlds = ["com", "net", "org", "io", "dev"]
    paths = ["/", "/api/v1/data", "/assets/main.js", "/images/logo.png",
             "/styles/app.css", "/fonts/roboto.woff2", "/page", "/resource"]
    name_len = random.randint(4, 12)
    name = "".join(random.choices(string.ascii_lowercase, k=name_len))
    tld = random.choice(tlds)
    path = random.choice(paths)
    return f"{scheme}://{name}.{tld}{path}"


def _rand_referrer() -> str:
    return random.choice([_rand_url("https"), _rand_url("http"), ""])


def _rand_status_code(phase: str, error_type: str) -> int:
    """
    Spec §5.4: status_code is 0 when no HTTP response was received (dns /
    connection phase), otherwise the actual HTTP status code.
    """
    if phase in ("dns", "connection"):
        return 0
    if error_type == SUCCESS_TYPE:
        return random.choice([200, 201, 204, 301, 302, 304])
    if error_type == "http.error":
        return random.choice([400, 401, 403, 404, 429, 500, 502, 503, 504])
    if error_type == "abandoned":
        # Abandon can happen before a response arrives
        return random.choice([0, 200])
    return 0


def _rand_protocol(phase: str) -> str:
    """
    Spec §5.4: protocol is the empty string when DNS resolution failed
    (no connection was established).
    """
    if phase == "dns":
        return ""
    return random.choice(PROTOCOLS)


def _rand_server_ip(phase: str) -> str:
    """
    Spec §5.4: server_ip is empty when DNS failed.
    """
    if phase == "dns":
        return ""
    # Connection phase: we have an IP but might not have connected
    return _rand_ip()


# ---------------------------------------------------------------------------
# Report generation
# ---------------------------------------------------------------------------

@dataclass
class NelReportBody:
    """The body of a NEL report as specified in §5.4."""
    sampling_fraction: float
    referrer: str
    server_ip: str
    protocol: str
    method: str
    request_headers: dict
    response_headers: dict
    status_code: int
    elapsed_time: int   # milliseconds
    phase: str
    type: str


@dataclass
class ReportingApiReport:
    """
    Outer Reporting API envelope (§5.5).
    The spec mandates the shape:
      { "age": <ms>, "type": "network-error", "url": <str>, "body": { ... } }
    """
    age: int
    type: str
    url: str
    body: NelReportBody

    def to_dict(self) -> dict:
        d = asdict(self)
        # asdict() recurses into dataclasses, so body is already a plain dict
        return d


def generate_report(
    url: Optional[str] = None,
    force_error_type: Optional[str] = None,
    force_phase: Optional[str] = None,
    force_success: bool = False,
) -> ReportingApiReport:
    """
    Generate a single random but spec-compliant NEL report.

    Parameters
    ----------
    url : str, optional
        The URL the (simulated) request was made to. If None, a random URL
        is generated.
    force_error_type : str, optional
        Pin a specific NEL error type string (e.g. "dns.name_not_resolved").
    force_phase : str, optional
        Pin a specific phase ("dns", "connection", "application").
    force_success : bool
        If True, generate a successful ("ok") report instead of an error.
    """
    # --- Pick phase & type ---------------------------------------------------
    if force_success:
        phase = "application"
        error_type = SUCCESS_TYPE
    elif force_error_type:
        error_type = force_error_type
        # Infer phase from type prefix if not overridden
        if force_phase:
            phase = force_phase
        elif error_type.startswith("dns."):
            phase = "dns"
        elif error_type.startswith(("tcp.", "tls.")):
            phase = "connection"
        else:
            phase = "application"
    elif force_phase:
        phase = force_phase
        if phase == "dns":
            error_type = random.choice(DNS_ERRORS)
        elif phase == "connection":
            error_type = random.choice(CONNECTION_ERRORS)
        else:
            error_type = random.choice(APPLICATION_ERRORS + [SUCCESS_TYPE])
    else:
        # Weighted random: failures are more interesting, but include some successes
        bucket = random.choices(
            ["dns", "connection", "application_error", "success"],
            weights=[20, 30, 35, 15],
        )[0]
        if bucket == "dns":
            phase = "dns"
            error_type = random.choice(DNS_ERRORS)
        elif bucket == "connection":
            phase = "connection"
            error_type = random.choice(CONNECTION_ERRORS)
        elif bucket == "application_error":
            phase = "application"
            error_type = random.choice(APPLICATION_ERRORS)
        else:
            phase = "application"
            error_type = SUCCESS_TYPE

    # --- Build report fields ------------------------------------------------
    report_url = url or _rand_url()
    referrer = _rand_referrer()
    server_ip = _rand_server_ip(phase)
    protocol = _rand_protocol(phase)
    method = random.choice(METHODS)
    status_code = _rand_status_code(phase, error_type)
    elapsed_time = random.randint(0, 30_000)   # 0–30 s in milliseconds
    sampling_fraction = round(random.uniform(0.1, 1.0), 2)

    # request_headers / response_headers: spec allows arbitrary recorded headers.
    # We include a realistic but empty or minimal set.
    request_headers: dict = {}
    response_headers: dict = {}

    # Only populate headers when we actually got a response (application phase)
    if phase == "application" and status_code > 0:
        if random.random() > 0.5:
            response_headers = {
                "ETag": '"' + "".join(random.choices(string.hexdigits, k=16)) + '"'
            }
        if random.random() > 0.7:
            request_headers = {"If-None-Match": response_headers.get("ETag", "")}

    # Spec §5.4 note: when phase is "dns", clear request_headers, response_headers
    # and server_ip is empty — already handled above.
    if phase == "dns":
        request_headers = {}
        response_headers = {}

    body = NelReportBody(
        sampling_fraction=sampling_fraction,
        referrer=referrer,
        server_ip=server_ip,
        protocol=protocol,
        method=method,
        request_headers=request_headers,
        response_headers=response_headers,
        status_code=status_code,
        elapsed_time=elapsed_time,
        phase=phase,
        type=error_type,
    )

    # age: milliseconds since the report was generated (0 = fresh)
    age = random.choice([0, random.randint(0, 60_000)])

    return ReportingApiReport(age=age, type="network-error", url=report_url, body=body)


# ---------------------------------------------------------------------------
# HTTP delivery
# ---------------------------------------------------------------------------

def deliver_report(endpoint: str, reports: list[dict], timeout: int = 10) -> tuple[int, str]:
    """
    POST the report batch to the endpoint.

    The spec (§5.5) and the Reporting API specify:
      - Method: POST
      - Content-Type: application/reports+json
      - Body: JSON array of report objects
    """
    payload = json.dumps(reports, indent=2).encode("utf-8")

    req = urllib.request.Request(
        url=endpoint,
        data=payload,
        method="POST",
        headers={
            "Content-Type": "application/reports+json",
            "User-Agent": "NEL-Report-Generator/1.0 (python)",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, body
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return exc.code, body
    except urllib.error.URLError as exc:
        return -1, str(exc.reason)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nel_report_generator.py",
        description=(
            "Generate and submit random W3C-compliant Network Error Logging "
            "(NEL) reports to a chosen endpoint."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Submit 3 random reports to a local collector
  python nel_report_generator.py --endpoint http://localhost:8080/report --count 3

  # Force a specific error type
  python nel_report_generator.py --endpoint http://collector.example.com/nel \\
      --error-type dns.name_not_resolved

  # Generate only successful reports and just print them (dry-run)
  python nel_report_generator.py --endpoint http://collector.example.com/nel \\
      --success --dry-run

  # Pin the URL the report pretends to be about
  python nel_report_generator.py --endpoint http://collector.example.com/nel \\
      --url https://myapp.example.com/api/data

Valid phases  : dns | connection | application
Valid types   : dns.unreachable, dns.name_not_resolved, dns.failed,
                dns.address_changed,
                tcp.timed_out, tcp.closed, tcp.reset, tcp.refused,
                tcp.aborted, tcp.address_invalid, tcp.address_unreachable,
                tcp.failed,
                tls.version_or_cipher_mismatch, tls.bad_client_auth_cert,
                tls.cert.name_invalid, tls.cert.date_invalid,
                tls.cert.authority_invalid, tls.cert.invalid,
                tls.cert.revoked, tls.cert.pinned_key_not_in_cert_chain,
                tls.protocol.error, tls.failed,
                http.error, http.protocol.error, http.response.invalid,
                http.response.redirect_loop, http.failed, abandoned, ok
""",
    )

    parser.add_argument(
        "--endpoint", "-e",
        required=True,
        metavar="URL",
        help="NEL collector endpoint URL (e.g. https://collector.example.com/reports)",
    )
    parser.add_argument(
        "--count", "-n",
        type=int,
        default=1,
        metavar="N",
        help="Number of reports to generate and send in a single batch (default: 1)",
    )
    parser.add_argument(
        "--url", "-u",
        default=None,
        metavar="URL",
        help="URL the simulated request was made to (random if omitted)",
    )
    parser.add_argument(
        "--error-type", "-t",
        default=None,
        metavar="TYPE",
        dest="error_type",
        help="Force a specific NEL error type string (see valid types below)",
    )
    parser.add_argument(
        "--phase", "-p",
        choices=["dns", "connection", "application"],
        default=None,
        help="Force a specific phase (dns | connection | application)",
    )
    parser.add_argument(
        "--success",
        action="store_true",
        help='Generate a successful report (phase=application, type="ok")',
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the report(s) as JSON and exit without sending",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SECS",
        help="HTTP request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        metavar="INT",
        help="Random seed for reproducible output",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON to stdout (implied by --dry-run)",
    )

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.seed is not None:
        random.seed(args.seed)

    # Validate mutually exclusive options
    if args.success and args.error_type:
        parser.error("--success and --error-type are mutually exclusive")
    if args.success and args.phase and args.phase != "application":
        parser.error("--success requires phase=application (or omit --phase)")

    # Generate reports
    reports_dicts: list[dict] = []
    for i in range(args.count):
        report = generate_report(
            url=args.url,
            force_error_type=args.error_type,
            force_phase=args.phase,
            force_success=args.success,
        )
        reports_dicts.append(report.to_dict())

    indent = 2 if (args.dry_run or args.pretty) else None
    json_output = json.dumps(reports_dicts, indent=indent)

    if args.dry_run:
        print(json_output)
        return

    if args.pretty:
        print("Generated report batch:")
        print(json_output)
        print()

    # Deliver
    print(f"Submitting {args.count} report(s) to {args.endpoint} …")
    t0 = time.monotonic()
    status, response_body = deliver_report(args.endpoint, reports_dicts, timeout=args.timeout)
    elapsed = (time.monotonic() - t0) * 1000

    if status == -1:
        print(f"  ✗  Connection error: {response_body}", file=sys.stderr)
        sys.exit(1)
    elif 200 <= status < 300:
        print(f"  ✓  HTTP {status}  ({elapsed:.0f} ms)")
        if response_body:
            print(f"     Response: {response_body[:200]}")
    else:
        print(f"  ✗  HTTP {status}  ({elapsed:.0f} ms)", file=sys.stderr)
        if response_body:
            print(f"     Response: {response_body[:400]}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
