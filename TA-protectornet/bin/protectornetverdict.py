#!/usr/bin/env python
"""
protectornetverdict — Custom Splunk Generating Search Command

Usage (SPL):
    | protectornetverdict submission_id=<id>

Fetches the full threat verdict for a completed ProtectorNet scan.
Returns: submission_id, final_verdict, confidence, threat_score, category,
         report_url, and raw verdict JSON.
"""

import json
import os
import sys
import logging

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))

from lib.protectornet_client import (
    get_api_key,
    get_verdict,
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
    Generating command that retrieves the ProtectorNet threat verdict
    for a completed submission.
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
            resp = get_verdict(api_key, sid, base_url)

            verdicts = resp.get("verdict", [])
            first = verdicts[0] if verdicts else {}

            yield {
                "ptnet_submission_id": sid,
                "ptnet_final_verdict": first.get("final_verdict", "Unknown"),
                "ptnet_confidence": first.get("confidence", 0),
                "ptnet_category": first.get("category", ""),
                "ptnet_threat_score": resp.get("threat_score", 0),
                "ptnet_details": json.dumps(resp.get("details", {})),
                "ptnet_verdicts_raw": json.dumps(verdicts),
                "ptnet_report_url": "{}/search?ref={}".format(
                    base_url.rstrip("/"), sid
                ),
                "ptnet_status": "Completed",
            }

        except ProtectorNetError as exc:
            logger.error("Verdict fetch failed: %s", exc)
            yield {
                "ptnet_submission_id": self.submission_id,
                "ptnet_error": str(exc),
                "ptnet_status": "Error",
            }


dispatch(ProtectorNetVerdictCommand, sys.argv, sys.stdin, sys.stdout, __name__)
