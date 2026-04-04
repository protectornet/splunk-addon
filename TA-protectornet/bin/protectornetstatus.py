#!/usr/bin/env python
"""
protectornetstatus — Custom Splunk Generating Search Command

Usage (SPL):
    | protectornetstatus submission_id=<id>

Checks the aggregated status of a previously submitted ProtectorNet scan.
Returns: ptnet_submission_id, ptnet_overall_status,
         ptnet_webscan_status, ptnet_threathunt_status
"""

import os
import sys
import logging

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))

from lib.protectornet_client import (
    get_api_key,
    get_submission_status,
    validate_submission_id,
    ProtectorNetError,
    DEFAULT_BASE_URL,
)

from splunklib.searchcommands import (
    dispatch,
    GeneratingCommand,
    Configuration,
    Option,
    validators,
)


@Configuration()
class ProtectorNetStatusCommand(GeneratingCommand):
    """
    Generating command that checks the aggregated status of a ProtectorNet
    submission using the unified /search/threatanalyse/status/{id} endpoint.
    """

    submission_id = Option(
        doc="The submission reference ID from a previous scan",
        require=True,
    )

    def generate(self):
        logger = logging.getLogger("protectornetstatus")

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

            service_conn = connect(token=session_key, app="TA-protectornet")
            conf = service_conn.confs["ta_protectornet_settings"]
            for stanza in conf:
                if stanza.name == "general":
                    base_url = stanza.content.get("base_url", DEFAULT_BASE_URL)
                    break
        except Exception:
            pass

        try:
            sid = validate_submission_id(self.submission_id)

            resp = get_submission_status(api_key, sid, base_url)
            yield {
                "ptnet_submission_id": sid,
                "ptnet_overall_status": resp.get("overall_status", "unknown"),
                "ptnet_webscan_status": resp.get("webscan_status", ""),
                "ptnet_threathunt_status": resp.get("threathunt_status", ""),
            }

        except ProtectorNetError as exc:
            logger.error("Status check failed: %s", exc)
            yield {
                "ptnet_submission_id": self.submission_id,
                "ptnet_error": str(exc),
                "ptnet_overall_status": "Error",
            }


dispatch(ProtectorNetStatusCommand, sys.argv, sys.stdin, sys.stdout, __name__)
