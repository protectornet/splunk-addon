"""
SentrySurface API Client for Splunk

Handles all communication with the SentrySurface REST API using the
current asynchronous submit/poll/fetch workflow:
    - Submit URL for analysis  (POST /search/threatanalyse/)
    - Poll aggregated status   (GET  /search/threatanalyse/status/{submission_id})
    - Fetch WebScan summary    (GET  /search/webscan/summary/{submission_id})
    - Fetch WebScan full data  (GET  /search/webscan/fulldata/{submission_id}/v2)
    - Fetch ThreatData         (GET  /search/threatdata/{submission_id})

Key changes from v1:
    - Auth: x-api-key header (was Authorization: Bearer)
    - Submit body: "text" field (was "url")
    - Submit endpoint has trailing slash
    - Submission ID from submissions[0].submission_id (was submissionreference)
    - Status: unified /search/threatanalyse/status/{id} (was per-service endpoints)
    - Services: domainAnalysis / threatIntel (API frontend names)

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

DEFAULT_BASE_URL = "https://api.sentrysurface.io"
DEFAULT_TIMEOUT = 30  # seconds per HTTP request
MAX_POLL_ATTEMPTS = 40  # 40 × 15s = 10 min max
POLL_INTERVAL = 15  # seconds between status polls

# Map legacy service names → API frontend names accepted by /search/threatanalyse/
_SERVICE_ALIASES = {
    "webscan": "domainAnalysis",
    "threathunt": "threatIntel",
    "domainanalysis": "domainAnalysis",
    "threatintel": "threatIntel",
    "domainAnalysis": "domainAnalysis",
    "threatIntel": "threatIntel",
}

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
    """
    Validate and normalise service list.
    Accepts API frontend names (domainAnalysis, threatIntel) and legacy
    Splunk addon names (webscan, threathunt) as aliases.
    """
    if not services:
        return ["domainAnalysis", "threatIntel"]
    if isinstance(services, str):
        services = [s.strip() for s in services.split(",")]
    result = []
    for s in services:
        s = s.strip()
        normalized = _SERVICE_ALIASES.get(s) or _SERVICE_ALIASES.get(s.lower())
        if normalized and normalized not in result:
            result.append(normalized)
        elif not normalized:
            raise ProtectorNetValidationError(
                "Invalid service '{}'. Valid values: domainAnalysis, threatIntel".format(s)
            )
    if not result:
        raise ProtectorNetValidationError(
            "At least one valid service required: domainAnalysis, threatIntel"
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

    Uses x-api-key header for authentication.
    Returns parsed JSON dict.
    Raises ProtectorNetError subclass on failure.
    """
    headers = {
        "x-api-key": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "TA-protectornet/2.0.0 Splunk",
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

    POST {base_url}/search/threatanalyse/
    Body: { "text": "<url>", "services": ["domainAnalysis", "threatIntel"] }

    Returns the full submission response. Caller extracts:
      response["submissions"][0]["submission_id"]
    """
    url = validate_url(url)
    services = validate_services(services)

    endpoint = "{}/search/threatanalyse/".format(base_url.rstrip("/"))
    payload = {"text": url, "services": services}

    return _make_request(endpoint, api_key, method="POST", data=payload)


def get_submission_status(api_key, submission_id, base_url=DEFAULT_BASE_URL):
    """
    Poll aggregated submission status.

    GET {base_url}/search/threatanalyse/status/{submission_id}

    Returns dict with keys:
      overall_status  : "submitted" | "processing" | "completed" | "failed"
      webscan_status  : per-service status string
      threathunt_status: per-service status string
    """
    submission_id = validate_submission_id(submission_id)
    endpoint = "{}/search/threatanalyse/status/{}".format(
        base_url.rstrip("/"), urllib.parse.quote(submission_id, safe="")
    )
    return _make_request(endpoint, api_key)


def get_webscan_summary(api_key, submission_id, base_url=DEFAULT_BASE_URL):
    """
    Fetch the WebScan summary (verdict + metadata, optimised for dashboards).

    GET {base_url}/search/webscan/summary/{submission_id}

    Returns dict with keys: submissionId, metadata, verdict, screenshot, progress.
    verdict contains: threat, confidence, riskScore, recommendation, categories, isMalicious.
    """
    submission_id = validate_submission_id(submission_id)
    endpoint = "{}/search/webscan/summary/{}".format(
        base_url.rstrip("/"), urllib.parse.quote(submission_id, safe="")
    )
    return _make_request(endpoint, api_key)


def get_fulldata(api_key, submission_id, profile="full", base_url=DEFAULT_BASE_URL):
    """
    Fetch full scan data.

    GET {base_url}/search/webscan/fulldata/{id}/v2?profile={profile}

    Profiles: minimal (2KB), dashboard_basic (25KB), dashboard_security (50KB),
              api_threat_intel (35KB), full (200KB)
    """
    submission_id = validate_submission_id(submission_id)
    endpoint = "{}/search/webscan/fulldata/{}/v2?profile={}".format(
        base_url.rstrip("/"),
        urllib.parse.quote(submission_id, safe=""),
        urllib.parse.quote(profile, safe=""),
    )
    return _make_request(endpoint, api_key)


def get_threatdata(api_key, submission_id, base_url=DEFAULT_BASE_URL):
    """
    Fetch ThreatData (threat hunt results, IOCs, enrichment).

    GET {base_url}/search/threatdata/{submission_id}
    """
    submission_id = validate_submission_id(submission_id)
    endpoint = "{}/search/threatdata/{}".format(
        base_url.rstrip("/"), urllib.parse.quote(submission_id, safe="")
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
    Full end-to-end scan: submit → poll status → fetch WebScan summary.

    Returns a flat dict of Splunk output fields:
      ptnet_submission_id, ptnet_url, ptnet_overall_status,
      ptnet_webscan_status, ptnet_threathunt_status,
      ptnet_threat_level, ptnet_risk_score, ptnet_confidence,
      ptnet_recommendation, ptnet_categories, ptnet_is_malicious,
      ptnet_final_verdict (alias), ptnet_threat_score (alias),
      ptnet_status, ptnet_report_url
    """
    # 1. Submit
    submission_resp = submit_scan(api_key, url, services, base_url)
    submissions_list = submission_resp.get("submissions", [])
    if not submissions_list:
        raise ProtectorNetError(
            "No submissions in API response. Response status: {}".format(
                submission_resp.get("status", "unknown")
            )
        )
    ref = submissions_list[0].get("submission_id", "")
    if not ref:
        raise ProtectorNetError("submission_id missing from API response")

    if logger:
        logger.info("ProtectorNet: Submitted %s — submission_id=%s", url, ref)

    # 2. Poll
    last_status = {}
    for attempt in range(1, MAX_POLL_ATTEMPTS + 1):
        last_status = get_submission_status(api_key, ref, base_url)
        overall = last_status.get("overall_status", "processing")
        if overall == "completed":
            break
        if overall == "failed":
            raise ProtectorNetError(
                "Submission {} failed (overall_status=failed)".format(ref)
            )
        if logger and attempt % 4 == 0:
            logger.info(
                "ProtectorNet: Polling %s — attempt %d/%d, status=%s",
                ref, attempt, MAX_POLL_ATTEMPTS, overall,
            )
        time.sleep(POLL_INTERVAL)
    else:
        raise ProtectorNetError(
            "Scan timed out after {} attempts for {}".format(MAX_POLL_ATTEMPTS, ref)
        )

    # 3. Fetch WebScan summary for verdict fields
    verdict = {}
    try:
        summary = get_webscan_summary(api_key, ref, base_url)
        verdict = summary.get("verdict", {}) or {}
    except ProtectorNetError as exc:
        if logger:
            logger.warning(
                "ProtectorNet: Could not fetch summary for %s: %s", ref, exc
            )

    return {
        "ptnet_submission_id": ref,
        "ptnet_url": url,
        "ptnet_overall_status": last_status.get("overall_status", "completed"),
        "ptnet_webscan_status": last_status.get("webscan_status", ""),
        "ptnet_threathunt_status": last_status.get("threathunt_status", ""),
        "ptnet_threat_level": verdict.get("threat", "unknown"),
        "ptnet_risk_score": verdict.get("riskScore", 0),
        "ptnet_confidence": verdict.get("confidence", 0),
        "ptnet_recommendation": verdict.get("recommendation", ""),
        "ptnet_categories": ",".join(verdict.get("categories", [])),
        "ptnet_is_malicious": verdict.get("isMalicious", False),
        # Backward-compat field aliases used by existing SPL queries
        "ptnet_final_verdict": verdict.get("threat", "unknown"),
        "ptnet_threat_score": verdict.get("riskScore", 0),
        "ptnet_status": "Completed",
        "ptnet_report_url": "{}/search?ref={}".format(base_url.rstrip("/"), ref),
    }
