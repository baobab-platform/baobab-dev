"""Bounded GitHub API transport for DEV-10 identity and custody evidence."""
import http.client
import json
import re
import urllib.error
import urllib.request
from urllib.parse import urlsplit

API_HOST = "api.github.com"
API_ROOT = f"https://{API_HOST}"
API_VERSION = "2022-11-28"
MAX_RESPONSE_BYTES = 1_048_576
_REQUEST_ID = re.compile(r"(?:[0-9A-Fa-f]{1,16}:){2,5}[0-9A-Fa-f]{1,16}")
_SAFE_MESSAGES = {
    message.casefold(): message for message in (
        "Resource not accessible by integration", "Bad credentials",
        "Requires authentication", "Not Found", "Validation Failed",
        "API rate limit exceeded", "Secondary rate limit", "Problems parsing JSON",
        "Unprocessable Entity", "Forbidden", "Unauthorized", "Internal Server Error",
    )
}


class GitHubAPIError(ValueError):
    """A bounded GitHub API failure safe to report to operators."""


def _validate_api_url(url):
    message = "GitHub API request URL must target api.github.com over HTTPS"
    try:
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or parsed.hostname != API_HOST
                or parsed.port not in (None, 443) or parsed.username is not None
                or parsed.password is not None or parsed.fragment
                or any(ord(char) <= 32 or char in "\\\x7f" for char in url)):
            raise GitHubAPIError(message)
    except ValueError:
        raise GitHubAPIError(message) from None
    return parsed


class _SameHostRedirect(urllib.request.HTTPRedirectHandler):
    """Permit same-origin read redirects. Never redirect a credentialed write."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            _validate_api_url(req.full_url)
            _validate_api_url(newurl)
            if req.get_method() not in ("GET", "HEAD"):
                raise GitHubAPIError("GitHub API write redirect refused")
        except GitHubAPIError:
            raise urllib.error.HTTPError(
                req.full_url, code, "GitHub API redirect refused", headers, fp
            ) from None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER = urllib.request.build_opener(_SameHostRedirect())


def open_github(request, timeout=30):
    """Open a request only after validating its destination and redirect policy."""
    _validate_api_url(request.full_url)
    return _OPENER.open(request, timeout=timeout)


def read_bounded(response):
    """Read at most one MiB plus one sentinel byte."""
    raw = response.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        raise GitHubAPIError("GitHub API response exceeded the 1 MiB safety limit")
    return raw


def safe_github_message(value):
    if isinstance(value, str):
        return _SAFE_MESSAGES.get(value.strip().casefold(), "unrecognized GitHub error")
    return "unrecognized GitHub error"


def _http_error_summary(error, context):
    """Report HTTP status, documented message labels and a validated request ID."""
    status = error.code
    parts = [f"{context} HTTP {status}"]
    if 300 <= status < 400:
        parts.append("GitHub API redirect refused")
    else:
        try:
            raw = read_bounded(error)
            payload = json.loads(raw) if raw else None
        except GitHubAPIError:
            parts.append("error response exceeded the 1 MiB safety limit")
        except (AttributeError, OSError, http.client.HTTPException, ValueError, RecursionError):
            payload = None
        else:
            if isinstance(payload, dict) and "message" in payload:
                parts.append(safe_github_message(payload["message"]))
    candidate = error.headers.get("x-github-request-id") if error.headers else None
    if (
        isinstance(candidate, str) and len(candidate) <= 80
        and _REQUEST_ID.fullmatch(candidate)
    ):
        parts.append(f"GitHub request ID {candidate}")
    return ": ".join(parts)


def request_json(request, *, context, allowed_status=()):
    """Return the HTTP status and decoded body, and suppress untrusted error details."""
    try:
        with open_github(request) as response:
            status = response.status
            raw = read_bounded(response)
    except urllib.error.HTTPError as error:
        with error:
            if error.code in allowed_status:
                return error.code, None
            message = _http_error_summary(error, context)
        raise GitHubAPIError(message) from None
    except TimeoutError:
        raise GitHubAPIError(f"{context} request timed out") from None
    except urllib.error.URLError as error:
        reason = "request timed out" if isinstance(error.reason, TimeoutError) else "transport failed"
        raise GitHubAPIError(f"{context} {reason}") from None
    except GitHubAPIError:
        raise
    except (OSError, http.client.HTTPException, ValueError):
        # http.client may put a rejected request header in a ValueError.
        raise GitHubAPIError(f"{context} transport failed") from None
    if status not in (200, 201, 204) and status not in allowed_status:
        raise GitHubAPIError(f"{context} returned HTTP {status}")
    if not raw:
        return status, None
    try:
        return status, json.loads(raw)
    except (ValueError, RecursionError):
        raise GitHubAPIError(f"{context} returned invalid JSON") from None


def rest_request(token, method, path, payload=None, allowed_status=()):
    """Make a bounded REST request to the canonical GitHub API."""
    if not isinstance(path, str):
        raise GitHubAPIError("GitHub API path must be text")
    if path.startswith("https://"):
        url = path
    elif path.startswith("/") and not path.startswith("//"):
        url = API_ROOT + path
    else:
        raise GitHubAPIError("GitHub API path must be a repository-relative API path")
    _validate_api_url(url)
    data = None if payload is None else json.dumps(payload, separators=(",", ":")).encode()
    request = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "Content-Type": "application/json",
        "X-GitHub-Api-Version": API_VERSION,
        "User-Agent": "baobab-dev-dev10",
    })
    return request_json(request, context=f"GitHub API {method}", allowed_status=allowed_status)
