"""
ProtectorNet API Client for Splunk

Handles all communication with the ProtectorNet REST API:
  - Submit URL/domain for analysis (POST /search/threatanalyse)
  - Poll scan status (GET /search/threatanalyse/webscanstatus/{id})
  - Poll threat hunt status (GET /search/threatanalyse/threathuntstatus/{id})
  - Fetch verdict (GET /search/threatverdict/{id})
  - Fetch full data (GET /search/webscan/fulldata/{id}/v2)

Security:
  - API key retrieved from Splunk's encrypted credential store (storage/passwords)
  - SSL verification enabled by default
  - Input validated before API calls
  - No credentials logged
"""

import json
import re
import time
import urllib.parse

# Splunk ships its own Python; use the bundled urllib for HTTP.
# We avoid third-party libraries so the app has zero external dependencies.
try:
    # Python 3 (Splunk 8.x+)
    import urllib.request
    import urllib.error
    import ssl
except ImportError:
    raise RuntimeError("TA-protectornet requires Python 3 (Splunk 8.2+)")


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

DEFAULT_BASE_URL = "https://app.protectornet.io"
DEFAULT_TIMEOUT = 30  # seconds per HTTP request
MAX_POLL_ATTEMPTS = 40  # 40 × 15s = 10 min max
POLL_INTERVAL = 15  # seconds between status polls

# Simple allow-list for URL validation (scheme + host required)
_URL_PATTERN = re.compile(
    r"^https?://[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)*"
    r"(:\d{1,5})?(/[^\s]*)?$"
)

# Domain validation
_DOMAIN_PATTERN = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?)+$"
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class ProtectorNetError(Exception):
    """Base exception for ProtectorNet API errors."""


class ProtectorNetAuthError(ProtectorNetError):
    """Raised on 401/403 responses."""


class ProtectorNetRateLimitError(ProtectorNetError):
    """Raised on 429 responses."""


class ProtectorNetValidationError(ProtectorNetError):
    """Raised for bad input before making an API call."""


# ---------------------------------------------------------------------------
# Input Validation
# ---------------------------------------------------------------------------

def validate_url(url):
    """Validate a URL string. Raises ProtectorNetValidationError on failure."""
    if not url or not isinstance(url, str):
        raise ProtectorNetValidationError("URL is required and must be a string")
    url = url.strip()
    if len(url) > 2048:
        raise ProtectorNetValidationError("URL exceeds maximum length of 2048 characters")
    if not _URL_PATTERN.match(url):
        raise ProtectorNetValidationError(
            "Invalid URL format. Must start with http:// or https://"
        )
    return url


def validate_domain(domain):
    """Validate a domain string. Raises ProtectorNetValidationError on failure."""
    if not domain or not isinstance(domain, str):
        raise ProtectorNetValidationError("Domain is required and must be a string")
    domain = domain.strip().lower()
    if len(domain) > 253:
        raise ProtectorNetValidationError("Domain exceeds maximum length of 253 characters")
    if not _DOMAIN_PATTERN.match(domain):
        raise ProtectorNetValidationError("Invalid domain format")
    return domain


def validate_submission_id(submission_id):
    """Validate a submission reference ID."""
    if not submission_id or not isinstance(submission_id, str):
        raise ProtectorNetValidationError("Submission ID is required")
    submission_id = submission_id.strip()
    # Allow alphanumeric + hyphens (UUID-style IDs)
    if not re.match(r"^[a-zA-Z0-9\-]{1,128}$", submission_id):
        raise ProtectorNetValidationError("Invalid submission ID format")
    return submission_id


def validate_services(services):
    """Validate and normalise service list."""
    allowed = {"webscan", "threathunt"}
    if not services:
        return ["webscan", "threathunt"]
    if isinstance(services, str):
        services = [s.strip().lower() for s in services.split(",")]
    result = []
    for s in services:
        s = s.strip().lower()
        if s in allowed:
            result.append(s)
    if not result:
        raise ProtectorNetValidationError(
            "At least one valid service required: webscan, threathunt"
        )
    return result


# ---------------------------------------------------------------------------
# Credential Helper
# ---------------------------------------------------------------------------

def get_api_key(session_key, base_url=None):
    """
    Retrieve the ProtectorNet API key from Splunk's encrypted credential store.

    The key is stored under:
      storage/passwords  →  realm=TA-protectornet, username=api_key

    Returns the clear-text API key string.
    Raises ProtectorNetAuthError if not found.
    """
    import splunklib.client as client  # noqa: available in Splunk runtime

    try:
        service = client.connect(token=session_key, app="TA-protectornet")
        for credential in service.storage_passwords:
            if (
                credential.content.get("realm") == "TA-protectornet"
                and credential.content.get("username") == "api_key"
            ):
                return credential.content.get("clear_password", "")
    except Exception as exc:
        raise ProtectorNetAuthError(
            "Failed to retrieve API key from Splunk credential store: {}".format(exc)
        )

    raise ProtectorNetAuthError(
        "ProtectorNet API key not configured. "
        "Go to ProtectorNet app → Setup to enter your API key."
    )


# ---------------------------------------------------------------------------
# HTTP Transport
# ---------------------------------------------------------------------------

def _build_ssl_context():
    """Create an SSL context with certificate verification enabled."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def _make_request(url, api_key, method="GET", data=None, timeout=DEFAULT_TIMEOUT):
    """
    Low-level HTTP request using urllib (no external deps).

    Returns parsed JSON dict.
    Raises ProtectorNetError subclass on failure.
    """
    headers = {
        "Authorization": "Bearer {}".format(api_key),
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "TA-protectornet/1.0.0 Splunk",
    }

    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    ctx = _build_ssl_context()

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            raw = resp.read().decode("utf-8")
            if not raw:
                return {}
            return json.loads(raw)
    except urllib.error.HTTPError as exc:
        status = exc.code
        detail = ""
        try:
            detail = exc.read().decode("utf-8")
        except Exception:
            pass

        if status == 401:
            raise ProtectorNetAuthError("Invalid API key (401 Unauthorized)")
        if status == 403:
            raise ProtectorNetAuthError(
                "API key does not have access to this resource (403 Forbidden)"
            )
        if status == 429:
            raise ProtectorNetRateLimitError(
                "Rate limit exceeded. Please wait before retrying. {}".format(detail)
            )
        raise ProtectorNetError(
            "ProtectorNet API returned HTTP {}: {}".format(status, detail)
        )
    except urllib.error.URLError as exc:
        raise ProtectorNetError(
            "Failed to connect to ProtectorNet API: {}".format(exc.reason)
        )


# ---------------------------------------------------------------------------
# API Methods
# ---------------------------------------------------------------------------

def submit_scan(api_key, url, services=None, base_url=DEFAULT_BASE_URL):
    """
    Submit a URL for analysis.

    POST {base_url}/search/threatanalyse
    Body: { "url": "<url>", "services": ["webscan","threathunt"] }

    Returns dict with keys: submissionreference, status, services
    """
    url = validate_url(url)
    services = validate_services(services)

    endpoint = "{}/search/threatanalyse".format(base_url.rstrip("/"))
    payload = {"url": url, "services": services}

    return _make_request(endpoint, api_key, method="POST", data=payload)


def get_webscan_status(api_key, submission_id, base_url=DEFAULT_BASE_URL):
    """
    Poll WebScan status.

    GET {base_url}/search/threatanalyse/webscanstatus/{id}

    Returns dict with key: status (Processing | Completed | Failed)
    """
    submission_id = validate_submission_id(submission_id)
    endpoint = "{}/search/threatanalyse/webscanstatus/{}".format(
        base_url.rstrip("/"), urllib.parse.quote(submission_id, safe="")
    )
    return _make_request(endpoint, api_key)


def get_threathunt_status(api_key, submission_id, base_url=DEFAULT_BASE_URL):
    """
    Poll ThreatHunt status.

    GET {base_url}/search/threatanalyse/threathuntstatus/{id}

    Returns dict with key: status (Processing | Completed | Failed)
    """
    submission_id = validate_submission_id(submission_id)
    endpoint = "{}/search/threatanalyse/threathuntstatus/{}".format(
        base_url.rstrip("/"), urllib.parse.quote(submission_id, safe="")
    )
    return _make_request(endpoint, api_key)


def get_verdict(api_key, submission_id, base_url=DEFAULT_BASE_URL):
    """
    Fetch the threat verdict.

    GET {base_url}/search/threatverdict/{id}

    Returns dict with keys: verdict (list), details, threat_score
    """
    submission_id = validate_submission_id(submission_id)
    endpoint = "{}/search/threatverdict/{}".format(
        base_url.rstrip("/"), urllib.parse.quote(submission_id, safe="")
    )
    return _make_request(endpoint, api_key)


def get_fulldata(api_key, submission_id, profile="dashboard_security",
                 base_url=DEFAULT_BASE_URL):
    """
    Fetch full scan data.

    GET {base_url}/search/webscan/fulldata/{id}/v2?profile={profile}
    """
    submission_id = validate_submission_id(submission_id)
    endpoint = "{}/search/webscan/fulldata/{}/v2?profile={}".format(
        base_url.rstrip("/"),
        urllib.parse.quote(submission_id, safe=""),
        urllib.parse.quote(profile, safe=""),
    )
    return _make_request(endpoint, api_key)


def get_phishing_domains(api_key, submission_id, base_url=DEFAULT_BASE_URL):
    """
    Fetch phishing domain results.

    GET {base_url}/search/webscan/phishingdomains/{id}
    """
    submission_id = validate_submission_id(submission_id)
    endpoint = "{}/search/webscan/phishingdomains/{}".format(
        base_url.rstrip("/"), urllib.parse.quote(submission_id, safe="")
    )
    return _make_request(endpoint, api_key)


# ---------------------------------------------------------------------------
# High-level: submit + poll + verdict (blocking)
# ---------------------------------------------------------------------------

def scan_and_wait(api_key, url, services=None, base_url=DEFAULT_BASE_URL,
                  logger=None):
    """
    Full end-to-end scan: submit → poll until complete → fetch verdict.

    Returns a flat dict suitable for Splunk output:
    {
      submission_id, url, final_verdict, confidence, threat_score,
      category, services_completed, ...
    }
    """
    # 1. Submit
    submission = submit_scan(api_key, url, services, base_url)
    ref = submission.get("submissionreference", "")
    if not ref:
        raise ProtectorNetError("No submission reference returned from API")

    active_services = submission.get("services", services or ["webscan"])

    if logger:
        logger.info("ProtectorNet: Submitted %s — ref=%s services=%s",
                     url, ref, active_services)

    # 2. Poll
    for attempt in range(1, MAX_POLL_ATTEMPTS + 1):
        all_done = True
        for svc in active_services:
            if svc == "webscan":
                status_resp = get_webscan_status(api_key, ref, base_url)
            elif svc == "threathunt":
                status_resp = get_threathunt_status(api_key, ref, base_url)
            else:
                continue

            status = status_resp.get("status", "")
            if status == "Failed":
                raise ProtectorNetError(
                    "Service '{}' failed for submission {}".format(svc, ref)
                )
            if status != "Completed":
                all_done = False

        if all_done:
            break

        if logger and attempt % 4 == 0:
            logger.info("ProtectorNet: Still polling %s (attempt %d/%d)",
                         ref, attempt, MAX_POLL_ATTEMPTS)

        time.sleep(POLL_INTERVAL)
    else:
        raise ProtectorNetError(
            "Scan timed out after {} attempts for {}".format(MAX_POLL_ATTEMPTS, ref)
        )

    # 3. Verdict
    verdict_resp = get_verdict(api_key, ref, base_url)

    # Flatten for Splunk output
    verdicts = verdict_resp.get("verdict", [])
    first = verdicts[0] if verdicts else {}

    return {
        "ptnet_submission_id": ref,
        "ptnet_url": url,
        "ptnet_final_verdict": first.get("final_verdict", "Unknown"),
        "ptnet_confidence": first.get("confidence", 0),
        "ptnet_category": first.get("category", ""),
        "ptnet_threat_score": verdict_resp.get("threat_score", 0),
        "ptnet_services": ",".join(active_services),
        "ptnet_status": "Completed",
        "ptnet_report_url": "{}/search?ref={}".format(base_url.rstrip("/"), ref),
    }
