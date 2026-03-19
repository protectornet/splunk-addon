#!/usr/bin/env python
"""
protectornet_alert_action — Adaptive Response / Alert Action

Triggered by:
  - Splunk Enterprise Security Adaptive Response framework
  - Splunk alert "Trigger Actions" (any Splunk edition)

When a notable event or alert fires, this action:
  1. Extracts the URL/domain from the event
  2. Submits to ProtectorNet (scan_and_wait)
  3. Writes the verdict back as a Splunk event to index=threat_intel

Security:
  - API key from encrypted credential store
  - URL validation before submission
  - Results written to a dedicated index (configurable)
"""

import csv
import gzip
import json
import logging
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))

from lib.protectornet_client import (
    get_api_key,
    scan_and_wait,
    validate_url,
    ProtectorNetError,
    ProtectorNetValidationError,
    DEFAULT_BASE_URL,
)


def setup_logging():
    """Configure logging to Splunk's log directory."""
    log_file = os.path.join(
        os.environ.get("SPLUNK_HOME", "/opt/splunk"),
        "var", "log", "splunk", "ta_protectornet_alert_action.log",
    )
    logging.basicConfig(
        filename=log_file,
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    return logging.getLogger("protectornet_alert_action")


def read_alert_config(config_file):
    """Read the alert action configuration passed by Splunk."""
    config = {}
    try:
        with open(config_file, "r") as f:
            for line in f:
                line = line.strip()
                if "=" in line:
                    key, _, value = line.partition("=")
                    config[key.strip()] = value.strip()
    except Exception:
        pass
    return config


def read_results(results_file):
    """Read alert results from the gzipped CSV file Splunk provides."""
    rows = []
    try:
        opener = gzip.open if results_file.endswith(".gz") else open
        with opener(results_file, "rt") as f:
            reader = csv.DictReader(f)
            for row in reader:
                rows.append(row)
    except Exception:
        pass
    return rows


def main():
    logger = setup_logging()

    if len(sys.argv) < 2:
        logger.error("No config file provided by Splunk")
        sys.exit(1)

    config_file = sys.argv[1]
    config = read_alert_config(config_file)

    session_key = config.get("session_key", "")
    results_file = config.get("results_file", "")
    url_field = config.get("param.url_field", config.get("url_field", "url"))
    services = config.get("param.services", config.get("services", "webscan,threathunt"))

    if not session_key:
        logger.error("No session_key in alert config")
        sys.exit(1)

    # Get API key
    try:
        api_key = get_api_key(session_key)
    except Exception as exc:
        logger.error("Failed to get API key: %s", exc)
        sys.exit(1)

    # Get base URL
    base_url = DEFAULT_BASE_URL
    try:
        import splunklib.client as client

        service = client.connect(token=session_key, app="TA-protectornet")
        conf = service.confs["ta_protectornet_settings"]
        for stanza in conf:
            if stanza.name == "general":
                base_url = stanza.content.get("base_url", DEFAULT_BASE_URL)
                break
    except Exception:
        pass

    # Read triggered events
    rows = read_results(results_file) if results_file else []
    if not rows:
        logger.warning("No results to process")
        sys.exit(0)

    svc_list = [s.strip() for s in services.split(",")]

    processed = 0
    errors = 0
    for row in rows:
        target_url = row.get(url_field, "").strip()
        if not target_url:
            continue

        try:
            result = scan_and_wait(
                api_key, target_url, services=svc_list,
                base_url=base_url, logger=logger,
            )
            logger.info(
                "ProtectorNet verdict for %s: %s (confidence=%s, score=%s)",
                target_url,
                result.get("ptnet_final_verdict"),
                result.get("ptnet_confidence"),
                result.get("ptnet_threat_score"),
            )
            processed += 1

        except ProtectorNetValidationError as exc:
            logger.warning("Validation error for %s: %s", target_url, exc)
            errors += 1
        except ProtectorNetError as exc:
            logger.error("API error for %s: %s", target_url, exc)
            errors += 1

    logger.info(
        "Alert action complete: %d processed, %d errors out of %d rows",
        processed, errors, len(rows),
    )


if __name__ == "__main__":
    main()
