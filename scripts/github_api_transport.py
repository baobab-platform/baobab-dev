"""Bounded, same-origin transport for GitHub API requests carrying credentials."""
from urllib.parse import urlsplit
import urllib.error
import urllib.request

API_HOST = "api.github.com"
MAX_RESPONSE_BYTES = 1_048_576


def _validate_api_url(url):
    parsed = urlsplit(url)
    if (parsed.scheme != "https" or parsed.hostname != API_HOST
            or parsed.port not in (None, 443)
            or parsed.username is not None or parsed.password is not None):
        raise ValueError("GitHub API request URL must use HTTPS on api.github.com")
    return parsed


class _SameHostRedirect(urllib.request.HTTPRedirectHandler):
    """Permit redirects only to the same canonical GitHub API origin."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        old = _validate_api_url(req.full_url)
        new = _validate_api_url(newurl)
        if (old.scheme, old.hostname, old.port or 443) != (
                new.scheme, new.hostname, new.port or 443):
            raise urllib.error.HTTPError(
                newurl, code, "cross-origin GitHub API redirect refused", headers, fp
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SameHostRedirect())


def open_github(request, timeout=30):
    """Open a request only after validating its destination and redirect policy."""
    _validate_api_url(request.full_url)
    return _OPENER.open(request, timeout=timeout)


def read_bounded(response):
    """Read at most one MiB plus one sentinel byte; reject oversized responses."""
    raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise ValueError("GitHub API response exceeded the 1 MiB safety limit")
    return raw
