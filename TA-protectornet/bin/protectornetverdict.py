#!/usr/bin/env python
"""
protectornetverdict — Custom Splunk Generating Search Command

Usage (SPL):
    | protectornetverdict submission_id=<id>

Fetches full WebScan and ThreatData results for a completed ProtectorNet scan.
Calls:
    GET /search/webscan/fulldata/{id}/v2?profile=full  — full WebScan dataset
    GET /search/threatdata/{id}                        — threat hunt IOCs & enrichment
Returns raw JSON payloads as Splunk fields for downstream lookup or eval.
"""

import json
import os
import sys
import logging

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))

from lib.protectornet_client import (
    get_api_key,
    get_fulldata,
    get_threatdata,
    validate_submission_id,
    ProtectorNetError,
    DEFAULT_BASE_URL,
)

from splunklib.searchcommands import (
    dispatch,
    GeneratingCommand,
    Configuration,
    Option,
)


@Configuration()
class ProtectorNetVerdictCommand(GeneratingCommand):
    """
        Generating command that retrieves the full ProtectorNet WebScan and
        ThreatData payloads for a completed submission.

        Output fields:
            ptnet_submission_id  — submission UUID
            ptnet_webscan_data   — JSON string of the full WebScan dataset (profile=full)
            ptnet_threatdata     — JSON string of the ThreatData payload (empty if not available)
            ptnet_status         — "Completed" or "Error"
            ptnet_error          — error message if status is "Error"
    """

    submission_id = Option(
        doc="The submission reference ID",
        require=True,
    )

    def generate(self):
        logger = logging.getLogger("protectornetverdict")

        try:
            session_key = self.metadata.searchinfo.session_key
            api_key = get_api_key(session_key)
        except Exception as exc:
            logger.error("ProtectorNet auth error: %s", exc)
            yield {"_raw": "Error: {}".format(exc), "ptnet_error": str(exc)}
            return

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
            pass

        try:
            sid = validate_submission_id(self.submission_id)

            fulldata = get_fulldata(api_key, sid, profile="full", base_url=base_url)

            threatdata = {}
            try:
                threatdata = get_threatdata(api_key, sid, base_url=base_url)
            except ProtectorNetError as td_exc:
                logger.warning(
                    "ThreatData not available for %s (ThreatHunt may not have "
                    "been requested): %s", sid, td_exc
                )

            yield {
                "ptnet_submission_id": sid,
                "ptnet_webscan_data": json.dumps(fulldata),
                "ptnet_threatdata": json.dumps(threatdata),
                "ptnet_status": "Completed",
                "ptnet_report_url": "{}/search?ref={}".format(base_url.rstrip("/"), sid),
            }

        except ProtectorNetError as exc:
            logger.error("Verdict fetch failed: %s", exc)
            yield {
                "ptnet_submission_id": self.submission_id,
                "ptnet_error": str(exc),
                "ptnet_status": "Error",
            }


dispatch(ProtectorNetVerdictCommand, sys.argv, sys.stdin, sys.stdout, __name__)
