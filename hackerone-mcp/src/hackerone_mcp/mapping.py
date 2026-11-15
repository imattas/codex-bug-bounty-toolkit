"""Conservative web-asset membership and explicit primary-CWE mapping."""
import ipaddress
import re
from urllib.parse import urlsplit


def _host(value):
    if not isinstance(value, str) or not value or value.endswith('.'):
        return None
    value = value.lower()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        if len(value) <= 253 and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in value.split('.')):
            return value
    return None


def _url(value):
    if not isinstance(value, str) or any(char in value for char in ('\\', '\r', '\n', '\t')):
        return None
    try:
        parsed = urlsplit(value)
        host = _host(parsed.hostname)
        if parsed.scheme not in ('http', 'https') or not host or parsed.username is not None or parsed.password is not None or parsed.fragment or '%' in parsed.path or '//' in parsed.path or any(part in ('.', '..') for part in parsed.path.split('/')):
            return None
        return parsed.scheme, host, parsed.port or (443 if parsed.scheme == 'https' else 80), parsed.path or '/', parsed.query
    except (ValueError, TypeError):
        return None


def asset_matches(attributes, asset):
    """True/False for supported forms, None when membership is unknown."""
    target = _url(asset)
    identifier, kind = attributes.get('asset_identifier'), attributes.get('asset_type')
    if target is None or not isinstance(identifier, str): return None
    if kind == 'URL':
        scope = _url(identifier if '://' in identifier else 'https://' + identifier)
        if scope is None or scope[4]: return None
        prefix = scope[3].rstrip('/')
        return target[:3] == scope[:3] and (not prefix or target[3] == prefix or target[3].startswith(prefix + '/'))
    if kind == 'DOMAIN':
        host = _host(identifier)
        if host is None: return None
        return target[1] == host and target[2] == (443 if target[0] == 'https' else 80)
    if kind == 'WILDCARD':
        if not identifier.startswith('*.') or '*' in identifier[2:]: return None
        host = _host(identifier[2:])
        if host is None: return None
        return target[1].endswith('.' + host) and target[2] == (443 if target[0] == 'https' else 80)
    return None


def weakness_matches(display, attributes):
    if not isinstance(display, str): return False
    cwes = re.findall(r'\bCWE-([1-9][0-9]*)\b', display, flags=re.IGNORECASE)
    if cwes:
        primary = re.match(r'\s*CWE-([1-9][0-9]*)(?=\s|:|$)', display, flags=re.IGNORECASE)
        return len(cwes) == 1 and primary is not None and str(attributes.get('external_id', '')).lower() == 'cwe-' + primary.group(1)
    return display == attributes.get('name')
