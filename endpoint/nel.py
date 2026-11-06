import json
import re
import logging
import boto3
import ipaddress
import datetime
import uuid
import os
from urllib.parse import urlparse
from boto3.dynamodb.conditions import Attr

env_region = os.environ.get('AWS_REGION', 'us-east-1')
env_config = os.environ.get('NEL_CONFIG', 'NEL.Config')
env_reports = os.environ.get('NEL_REPORTS', 'NEL.Reports')
env_loglevel = os.environ.get('LOGLEVEL', 'INFO').upper()
env_maxbodykb = int(os.environ.get('MAX_BODY_KB', '100'))

# Map potential ENV strings to standard logging constants safely
LEVEL_MAP = {
    "DEBUG": logging.DEBUG,
    "INFO": logging.INFO,
    "WARNING": logging.WARNING,
    "ERROR": logging.ERROR,
    "CRITICAL": logging.CRITICAL
}
# Get the valid numeric level, default to logging.INFO if string is invalid
target_level = LEVEL_MAP.get(raw_level, logging.INFO)

logger = logging.getLogger()
logger.setLevel(target_level)

dynamodb = boto3.resource('dynamodb', region_name=env_region)
config_table = dynamodb.Table(env_config)
report_table = dynamodb.Table(env_reports)

# NEL reports are submitted as application/reports+json (RFC 8941 / W3C Reporting API)
NEL_CONTENT_TYPE = 'application/reports+json'
MAX_BODY_BYTES = 1024 * env_maxbodykb


def lambda_handler(event, context):
    logger.debug("Event: %s", event)

    # Validate Content-Type header
    if not _content_type_ok(event):
        logger.warning("Rejected: invalid or missing Content-Type header")
        return _response(415, "Unsupported Media Type", "Content-Type must be {}".format(NEL_CONTENT_TYPE))

    address = report_src_addr(event)
    if address is not False:
        if report_ip_banned(address):
            logger.warning("Rejected: banned IP %s", address)
            return _response(403, "rejected", "Your report was rejected from your IP address {}".format(address))
        if not report_ip_permitted(address):
            logger.warning("Rejected: IP %s not in permitted list", address)
            return _response(403, "rejected", "Your report was rejected from your IP address {}".format(address))

    if not report_hostname_permitted(event):
        return _response(403, "rejected", "Reports for subject not allowed")

    report_uuid = save_report(event, address)
    if not report_uuid:
        return _response(403, "rejected", None)

    logger.info("Accepted report %s from %s", report_uuid, address)
    return {
        'statusCode': 200,
        'body': json.dumps({"Status": "accepted", "ReportID": report_uuid})
    }


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def save_report(event, address):
    """Persist the raw report body to DynamoDB. Returns the report UUID or False."""
    report_uuid = uuid.uuid4().hex
    client_ip_str = str(address)
    logger.info("Saving report %s for IP %s", report_uuid, client_ip_str)
    response = report_table.put_item(
        Item={
            "ReportID": report_uuid,
            "Body": event['body'],
            "ReportTime": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "ClientIp": client_ip_str,
        }
    )
    if response['ResponseMetadata']['HTTPStatusCode'] == 200:
        return report_uuid
    logger.error("DynamoDB put_item returned HTTP %s for report %s",
                 response['ResponseMetadata']['HTTPStatusCode'], report_uuid)
    return False


# ---------------------------------------------------------------------------
# IP-based access control
# ---------------------------------------------------------------------------

def _get_config_networks(config_name):
    """Fetch ip_network objects from a NEL.Config item.

    Returns:
        list[ipaddress.IPv4Network | ipaddress.IPv6Network]  – may be empty
        None  – on configuration or parse error
    """
    response = config_table.scan(
        FilterExpression=Attr('ConfigName').eq(config_name)
    )
    items = response.get('Items', [])
    if not items:
        return []
    if len(items) != 1:
        logger.warning("Expected 1 item for %s, found %d", config_name, len(items))
        return None
    
    ip_list = []
    for ip in items[0].get('IPs', []):
        ip_list.append(ip)
    
    if not isinstance(ip_list, list):
        logger.error("IPs field for %s is not a list", config_name)
        return None
    networks = []
    for entry in ip_list:
        try:
            networks.append(ipaddress.ip_network(entry, strict=False))
        except ValueError as exc:
            logger.error("%s: invalid network %r: %s", config_name, entry, exc)
            return None
    return networks


def report_ip_banned(address):
    """Return True if *address* matches any network in the BannedIPs config."""
    networks = _get_config_networks("BannedIPs")
    if not networks:
        return False
    for network in networks:
        if address.version == network.version and address in network:
            logger.info("%s is banned (matched %s)", address, network)
            return True
    return False


def report_ip_permitted(address):
    """Return True if *address* is allowed. An empty PermittedIPs list means open access."""
    networks = _get_config_networks("PermittedIPs")
    if networks is None:
        # Config error – fail closed (deny)
        return False
    if not networks:
        # No restrictions configured
        return True
    for network in networks:
        if address.version == network.version and address in network:
            logger.info("Address %s is permitted (matched %s)", address, network)
            return True
    logger.warning("Address %s not in any permitted network", address)
    return False


# ---------------------------------------------------------------------------
# Hostname-based access control
# ---------------------------------------------------------------------------

def report_hostname_permitted(event):
    """Validate the request body and check each report URL against the banned hostname list."""
    if 'body' not in event:
        logger.warning("Rejected: no body in event")
        return False

    if event.get('httpMethod', '').lower() != 'post':
        logger.warning("Rejected: unexpected HTTP method %s", event.get('httpMethod'))
        return False

    if len(event['body']) > MAX_BODY_BYTES:
        logger.warning("Rejected: body too large (%d bytes)", len(event['body']))
        return False

    try:
        reports = json.loads(event['body'])
    except (json.JSONDecodeError, TypeError) as exc:
        logger.warning("Rejected: body JSON parse error: %s", exc)
        return False

    if not isinstance(reports, list):
        logger.warning("Rejected: body is not a JSON array")
        return False

    # Fetch the banned hostnames config once, outside the per-report loop
    response = config_table.scan(
        FilterExpression=Attr('ConfigName').eq("BannedServerHostnames")
    )
    banned_items = response.get('Items', [])

    for report in reports:
        if 'url' not in report:
            logger.warning("Rejected: report missing 'url' field")
            return False
        hostname = urlparse(report['url']).netloc
        for item in banned_items:
            for expression in item.get('Hostname', []):
                if re.search(expression + "$", hostname):
                    logger.warning("Rejected: %s matched banned pattern %r", hostname, expression)
                    return False

    return True


# ---------------------------------------------------------------------------
# Source address helpers
# ---------------------------------------------------------------------------

def report_src_addr(event):
    """Extract the caller's IP address from the API Gateway request context."""
    try:
        return ipaddress.ip_address(event['requestContext']['identity']['sourceIp'])
    except (KeyError, TypeError, ValueError) as exc:
        logger.warning("Could not parse source IP: %s", exc)
        return False


def parse_X_Forwarded_For(event):
    """Parse public IP addresses from the X-Forwarded-For header, skipping loopback/private."""
    xff = event.get('headers', {}).get('X-Forwarded-For')
    if not xff:
        return False
    addresses = []
    for part in xff.split(','):
        try:
            addr = ipaddress.ip_address(part.strip())
            if addr.is_loopback or addr.is_private:
                logger.debug("X-Forwarded-For %s is loopback/private – skipping", addr)
            else:
                addresses.append(addr)
        except ValueError as exc:
            logger.warning("X-Forwarded-For parse error for %r: %s", part.strip(), exc)
            return False
    return addresses


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _content_type_ok(event):
    """Return True if the request carries the expected Content-Type for NEL reports."""

    headers = event.get('headers') or {}
    # API Gateway normalises header names to lowercase in some configurations;
    # check both cases to be safe.
    ct = headers.get('content-type') or headers.get('Content-Type') or ''
    return ct.lower().startswith(NEL_CONTENT_TYPE)


def _response(status_code, status, message):
    body = {"Status": status}
    if message:
        body["Message"] = message
    return {
        'statusCode': status_code,
        'body': json.dumps(body),
    }