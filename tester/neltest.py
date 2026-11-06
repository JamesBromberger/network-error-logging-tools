import re
import sys
import json
import requests
import socket
import logging
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)
RED = '\033[31m'
GREEN = '\033[32m'
YELLOW = '\033[33m'
RESET = '\033[0m'


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def is_int(val):
    try:
        int(val)
        return True
    except (ValueError, TypeError):
        return False


def resolve_hostname(hostname):
    """Return (ips, error_message).  error_message is None on success."""
    try:
        results = socket.getaddrinfo(hostname, None)
        ips = set(res[4][0] for res in results)
        logger.debug(f"IPs for {hostname}: {list(ips)}")
        return ips, None
    except socket.gaierror as exc:
        return set(), str(exc)


# ---------------------------------------------------------------------------
# NEL header checks
# ---------------------------------------------------------------------------

def check_secure_origin(url):
    """Verify the URL under test uses HTTPS (secure origin required by NEL spec)."""
    issues = {}
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https":
        issues["insecure_origin"] = (
            f"NEL requires a secure origin; URL scheme is '{parsed.scheme}', expected 'https'"
        )
    return issues


def check_nel_header_count_is_one(headers):
    """Count occurrences of the NEL header (case-insensitive)."""
    logger.debug("Checking nel_count")
    # requests uses a case-insensitive mapping, so we check via .get() presence
    # and rely on the raw header list when available; fall back to get() here.
    nel_count = sum(1 for h in headers if h.lower() == "nel")
    issues = {}
    if nel_count > 1:
        logger.debug("Multiple NEL headers found")
        issues["header_count"] = (
            f"NEL header appears {nel_count} times; only one is allowed"
        )
    elif nel_count == 0:
        logger.debug("NEL not found")
        issues["header_count"] = "NEL header not found"
    return issues


def check_nel_header_caps(headers):
    """Warn if the NEL header name is not capitalised as 'nel'.

    Note: requests normalises header names, so this check only works when the
    raw header names are preserved (e.g. via http.client directly). It is kept
    here for completeness and future use with raw response objects.
    """
    logger.debug("Checking nel header capitalisation")
    issues = {}
    for h in headers:
        if h.lower() == "nel" and h != "NEL":
            issues["header_wrong_capitalisation"] = (
                f"NEL header is capitalised as '{h}'; expected 'NEL'"
            )
    return issues


def check_nel_report_to(nel_json):
    issues = {}
    if "report_to" not in nel_json:
        issues["report_to_missing"] = "'report_to' field is missing in NEL"
    elif not isinstance(nel_json["report_to"], str):
        issues["report_to_not_string"] = (
            f"'report_to' must be a string (endpoint name), "
            f"got {type(nel_json['report_to']).__name__}"
        )
    return issues


def check_nel_max_age(nel_json):
    issues = {}
    if "max_age" not in nel_json:
        issues["max_age_not_set"] = "'max_age' field is missing"
    elif not is_int(nel_json["max_age"]):
        issues["max_age_not_numeric"] = "'max_age' must be an integer"
    elif int(nel_json["max_age"]) < 0:
        issues["max_age_is_neg"] = f"'max_age' is negative ({nel_json['max_age']})"
    elif int(nel_json["max_age"]) < 86400:
        issues["max_age_short"] = (
            f"'max_age' is {nel_json['max_age']}s, which is less than one day (86400s)"
        )
    return issues


def check_nel_subdomains(nel_json):
    issues = {}
    if "include_subdomains" not in nel_json:
        return issues
    if not isinstance(nel_json["include_subdomains"], bool):
        issues["include_subdomains_not_boolean"] = (
            f"'include_subdomains' must be a boolean (true/false), "
            f"got {type(nel_json['include_subdomains']).__name__}"
        )
    return issues


def check_nel_fraction(nel_json, name):
    issues = {}
    if name not in nel_json:
        return issues
    sf = nel_json[name]
    if not isinstance(sf, (int, float)) or isinstance(sf, bool):
        issues[f"{name}_not_numeric"] = f"'{name}' must be a number"
    elif sf < 0:
        issues[f"{name}_negative"] = f"'{name}' is negative ({sf})"
    elif sf > 1:
        issues[f"{name}_too_big"] = f"'{name}' is greater than 1 ({sf})"
    return issues


def check_nel_headers_list(nel_json, name):
    issues = {}
    if name in nel_json:
        if not isinstance(nel_json[name], list):
            issues[f"{name}_not_list"] = f"'{name}' must be a list"
    return issues


def check_nel(headers):
    """Validate the NEL header and its JSON payload.

    Returns a dict of issues.  Exits early if NEL is absent or unparseable.
    """
    issues = {}
    issues.update(check_nel_header_count_is_one(headers))
    issues.update(check_nel_header_caps(headers))

    # If NEL is absent there is nothing further to validate.
    if "header_count" in issues and headers.get("NEL") is None:
        return issues

    try:
        nel = json.loads(headers["NEL"])
    except (json.JSONDecodeError, KeyError) as exc:
        logger.info("NEL header is not valid JSON")
        issues["nel_invalid_json"] = f"NEL value is not valid JSON: {exc}"
        return issues

    issues.update(check_nel_report_to(nel))
    issues.update(check_nel_max_age(nel))
    issues.update(check_nel_subdomains(nel))
    issues.update(check_nel_fraction(nel, "success_fraction"))
    issues.update(check_nel_fraction(nel, "failure_fraction"))
    issues.update(check_nel_headers_list(nel, "request_headers"))
    issues.update(check_nel_headers_list(nel, "response_headers"))
    return issues


# ---------------------------------------------------------------------------
# Report-To (legacy) checks
# ---------------------------------------------------------------------------

def check_report_to_reporting_endpoints_valid(endpoints):
    issues = {}
    for idx, endpoint in enumerate(endpoints, start=1):
        if "url" not in endpoint:
            issues[f"report_to_{idx}_no_url"] = "No URL defined for endpoint"
            continue
        url = urlsplit(endpoint["url"])
        ips, err = resolve_hostname(url.netloc)
        if err:
            issues[f"report_to_{idx}_url_hostname_unresolvable"] = (
                f"Hostname '{url.netloc}' not resolvable: {err}"
            )
        if url.scheme.lower() != "https":
            issues[f"report_to_{idx}_url_not_https"] = (
                "The report URL scheme is not HTTPS"
            )
    return issues


def check_report_to_group(rt_json):
    issues = {}
    if "max_age" not in rt_json:
        issues["report_to_no_max_age"] = "No max_age in Report-To group"
    elif not is_int(rt_json["max_age"]):
        issues["report_to_max_age_not_int"] = (
            "The Report-To max_age parameter is not an integer"
        )
    elif int(rt_json["max_age"]) < 86400:
        # Fixed: was incorrectly keyed as rt_json['max_age'] (hyphen)
        issues["report_to_max_age_low"] = (
            f"The Report-To max_age is lower than a day ({rt_json['max_age']})"
        )

    if "endpoints" not in rt_json:
        issues["report_to_no_endpoints"] = (
            f"No endpoints defined in Report-To group: {rt_json}"
        )
    else:
        issues.update(check_report_to_reporting_endpoints_valid(rt_json["endpoints"]))
    return issues


def check_report_to(headers):
    issues = {}
    if "Report-To" not in headers:
        return issues

    issues["report_to_deprecated"] = (
        "Report-To is deprecated; migrate to Reporting-Endpoints"
    )
    try:
        # The header value is a JSON object or comma-separated JSON objects.
        # Wrap in [] to parse as a list regardless.
        report_to = json.loads("[" + headers["Report-To"] + "]")
    except json.JSONDecodeError as exc:
        issues["report_to_invalid_json"] = (
            f"Report-To value is not valid JSON: {exc}"
        )
        return issues

    for group in report_to:
        issues.update(check_report_to_group(group))
    return issues


# ---------------------------------------------------------------------------
# Reporting-Endpoints checks
# ---------------------------------------------------------------------------

# Matches:  name="https://example.com/endpoint"
# Handles URLs that contain '=' (e.g. query strings).
_RE_REPORTING_ENDPOINT = re.compile(
    r"""([^,=\s]+)\s*=\s*"([^"]+)"""
)


def dict_reporting_endpoints(headers):
    """Parse Reporting-Endpoints header into {name: SplitResult} and issues."""
    parsed = {}
    issues = {}
    header_value = headers.get("Reporting-Endpoints", "")

    for match in _RE_REPORTING_ENDPOINT.finditer(header_value):
        name = match.group(1).strip()
        url_str = match.group(2).strip()
        url = urlsplit(url_str)
        parsed[name] = url

        ips, err = resolve_hostname(url.netloc)
        if err:
            issues[f"reporting_endpoint_{name}_unresolvable"] = (
                f"Hostname '{url.netloc}' for endpoint '{name}' is not resolvable: {err}"
            )
        if url.scheme.lower() != "https":
            issues[f"reporting_endpoint_{name}_not_https"] = (
                f"Endpoint '{name}' URL scheme is not HTTPS"
            )

    return parsed, issues


def check_header_reporting_endpoints(headers):
    issues = {}
    if "Reporting-Endpoints" not in headers:
        issues["reporting_endpoints_missing"] = (
            "The Reporting-Endpoints header is missing"
        )
        return issues
    _, new_issues = dict_reporting_endpoints(headers)
    issues.update(new_issues)
    return issues


# ---------------------------------------------------------------------------
# Cross-header consistency checks
# ---------------------------------------------------------------------------

def check_nel_report_to_cross_reference(nel, headers):
    """Verify the group/endpoint named in NEL actually exists."""
    issues = {}
    report_to_name = nel.get("report_to")
    if not report_to_name:
        return issues  # already caught by check_nel_report_to

    if "Report-To" in headers:
        try:
            report_to = json.loads("[" + headers["Report-To"] + "]")
        except json.JSONDecodeError:
            return issues  # JSON error already reported elsewhere
        group_names = {g.get("group") for g in report_to}
        if report_to_name not in group_names:
            issues["nel_report_to_group_not_found"] = (
                f"The Report-To group '{report_to_name}' named in NEL "
                f"was not found in the Report-To header"
            )

    if "Reporting-Endpoints" in headers:
        dict_endpoints, _ = dict_reporting_endpoints(headers)
        if report_to_name not in dict_endpoints:
            issues["reporting_endpoint_named_in_nel_missing"] = (
                f"The endpoint '{report_to_name}' listed in NEL "
                f"was not found in Reporting-Endpoints"
            )

    return issues


# ---------------------------------------------------------------------------
# Top-level check
# ---------------------------------------------------------------------------

def check_all(headers, url=None):
    """Validate NEL, Report-To, and Reporting-Endpoints headers.

    Returns a dict of issues keyed by issue name with a descriptive message.
    """
    issues = {}

    # --- Secure origin (required by NEL spec) ---
    if url is not None:
        issues.update(check_secure_origin(url))

    # --- NEL header ---
    nel_issues = check_nel(headers)
    issues.update(nel_issues)

    # If NEL JSON is unparseable, skip checks that require the parsed value.
    if "nel_invalid_json" in issues or "header_count" in issues:
        issues.update(check_report_to(headers))
        issues.update(check_header_reporting_endpoints(headers))
        return issues

    # Safe to parse NEL now (check_nel already validated it).
    nel = json.loads(headers["NEL"])

    issues.update(check_report_to(headers))
    issues.update(check_header_reporting_endpoints(headers))
    issues.update(check_nel_report_to_cross_reference(nel, headers))

    return issues


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(url):
    """Fetch *url* and validate its NEL, Report-To, and Reporting-Endpoints headers."""
    try:
        response = requests.get(url, timeout=10)
    except requests.exceptions.RequestException as exc:
        print(f"{RED}Request failed: {exc}{RESET}")
        sys.exit(1)

    headers = response.headers

    if {'NEL', 'Report-To', 'Reporting-Endpoints'} & headers.keys():
        print(f"{GREEN}Headers found:{RESET}")
        print(f"                {GREEN}NEL:{RESET} {headers.get('NEL', '(not present)')}") if 'NEL' in headers else None
        print(f"          {YELLOW}Report-To{RESET}: {headers.get('Report-To', '(not present)')}") if 'Report-To' in headers else None
        print(f"{GREEN}Reporting-Endpoints:{RESET} {headers.get('Reporting-Endpoints', '(not present)')}") if 'Reporting-Endpoints' in headers else None
        print()

    issues = check_all(headers, url)

    if issues:
        print(f"{RED}Found {len(issues)} issue(s):{RESET}")
        for key, message in issues.items():
            print(f"  {RED}[{key}]{RESET} {message}")
    else:
        print(f"{GREEN}NEL header looks valid — no issues found.{RESET}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <url>")
        print(f"Example: {sys.argv[0]} https://example.com/")
        sys.exit(1)
    main(sys.argv[1])
