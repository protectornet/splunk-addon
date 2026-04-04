#!/usr/bin/env python
"""
protectornetscan — Custom Splunk Streaming Search Command

Usage (SPL):
    | protectornetscan url=<url> [services=domainAnalysis,threatIntel]
    index=proxy | protectornetscan field=url [services=domainAnalysis]

Submits a URL to ProtectorNet, polls until complete, and returns the verdict
as new fields (ptnet_final_verdict, ptnet_confidence, ptnet_threat_score, etc.)

Security:
  - API key is retrieved from Splunk's encrypted credential store
  - URL input is validated before submission
  - SSL verification is enabled
"""

import os
import sys
import logging

# Add the lib directory to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))

from lib.protectornet_client import (
    scan_and_wait,
    get_api_key,
    validate_url,
    ProtectorNetError,
    ProtectorNetValidationError,
    DEFAULT_BASE_URL,
)

# Splunk SDK
from splunklib.searchcommands import (
    dispatch,
    StreamingCommand,
    Configuration,
    Option,
    validators,
)


@Configuration()
class ProtectorNetScanCommand(StreamingCommand):
    """
    Streaming search command that enriches events with ProtectorNet threat verdicts.

    If 'url' option is given, scans that single URL for every event.
    If 'field' option is given, reads the URL from each event's field value.
    """

    url = Option(
        doc="A single URL to scan (alternative to field=)",
        require=False,
    )
    field = Option(
        doc="Event field name containing URLs to scan",
        require=False,
        default="url",
    )
    services = Option(
        doc="Comma-separated services: domainAnalysis, threatIntel",
        require=False,
        default="domainAnalysis,threatIntel",
    )

    def stream(self, records):
        logger = logging.getLogger("protectornetscan")

        # Get credentials
        try:
            session_key = self.metadata.searchinfo.session_key
            api_key = get_api_key(session_key)
        except Exception as exc:
            logger.error("ProtectorNet auth error: %s", exc)
            self.write_error("ProtectorNet: {}".format(exc))
            return

        # Read base URL from app config (default if not set)
        base_url = DEFAULT_BASE_URL
        try:
            from splunklib.client import connect

            service = connect(token=session_key, app="TA-protectornet")
            conf = service.confs["ta_protectornet_settings"]
            for stanza in conf:
                if stanza.name == "general":
                    base_url = stanza.content.get("base_url", DEFAULT_BASE_URL)
                    break
        except Exception:
            pass  # Fall back to default

        svc_list = [s.strip() for s in (self.services or "domainAnalysis,threatIntel").split(",")]

        # Cache to avoid re-scanning identical URLs in the same search
        cache = {}

        for record in records:
            target_url = self.url or record.get(self.field, "")
            if not target_url:
                # Pass through event unchanged
                yield record
                continue

            target_url = target_url.strip()

            # Check cache
            if target_url in cache:
                record.update(cache[target_url])
                yield record
                continue

            try:
                result = scan_and_wait(
                    api_key, target_url, services=svc_list,
                    base_url=base_url, logger=logger,
                )
                cache[target_url] = result
                record.update(result)
            except ProtectorNetValidationError as exc:
                logger.warning("Validation error for %s: %s", target_url, exc)
                record["ptnet_error"] = str(exc)
                record["ptnet_status"] = "ValidationError"
            except ProtectorNetError as exc:
                logger.error("API error for %s: %s", target_url, exc)
                record["ptnet_error"] = str(exc)
                record["ptnet_status"] = "Error"

            yield record


dispatch(ProtectorNetScanCommand, sys.argv, sys.stdin, sys.stdout, __name__)
