#!/usr/bin/env python
"""
protectornet_setup_handler — REST handler for the setup page

Provides a custom REST endpoint that the setup dashboard calls to
securely store the ProtectorNet API key in Splunk's credential store
(storage/passwords) and the base URL in a custom conf file.

Endpoints:
  GET  /servicesNS/nobody/TA-protectornet/protectornet_setup
       → Returns current config (base_url, api_key_configured=true/false)

  POST /servicesNS/nobody/TA-protectornet/protectornet_setup
       → Saves base_url + api_key

Security:
  - API key is stored encrypted via Splunk storage/passwords
  - Only admin-level users can access this endpoint (enforced by capability)
  - API key is never returned in GET responses
"""

import json
import logging
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "lib"))

import splunk.admin as admin
import splunk.rest as rest
import splunklib.client as client


logger = logging.getLogger("protectornet_setup")

APP_NAME = "TA-protectornet"
REALM = "TA-protectornet"
CREDENTIAL_USER = "api_key"
CONF_FILE = "ta_protectornet_settings"


class ProtectorNetSetupHandler(admin.MConfigHandler):
    """
    Custom REST handler for ProtectorNet app configuration.
    """

    def setup(self):
        if self.requestedAction == admin.ACTION_EDIT:
            for arg in ["base_url", "api_key"]:
                self.supportedArgs.addOptArg(arg)

    def handleList(self, confInfo):
        """GET — Return current config (without the actual API key)."""
        conf_dict = self._read_conf()
        api_key_set = self._is_api_key_set()

        confInfo["general"]["base_url"] = conf_dict.get(
            "base_url", "https://api.protectornet.io"
        )
        confInfo["general"]["api_key_configured"] = "true" if api_key_set else "false"

    def handleEdit(self, confInfo):
        """POST — Save config and credentials."""
        base_url = self.callerArgs.data.get("base_url", [None])[0]
        api_key = self.callerArgs.data.get("api_key", [None])[0]

        # Save base_url to conf
        if base_url:
            base_url = base_url.strip().rstrip("/")
            if not base_url.startswith("https://"):
                raise admin.AdminManagerException(
                    admin.ARG_VALIDATION_ERROR,
                    "Base URL must start with https://",
                )
            self._save_conf({"base_url": base_url})
            logger.info("Base URL updated to %s", base_url)

        # Save API key to credential store
        if api_key:
            api_key = api_key.strip()
            if len(api_key) < 10:
                raise admin.AdminManagerException(
                    admin.ARG_VALIDATION_ERROR,
                    "API key appears too short. Please check and re-enter.",
                )
            self._save_api_key(api_key)
            logger.info("API key updated in credential store")

        # Mark app as configured
        self._mark_configured()

    def _read_conf(self):
        """Read the settings conf file."""
        try:
            service = client.connect(
                token=self.getSessionKey(), app=APP_NAME
            )
            conf = service.confs[CONF_FILE]
            for stanza in conf:
                if stanza.name == "general":
                    return dict(stanza.content)
        except Exception:
            pass
        return {}

    def _save_conf(self, settings):
        """Write settings to the conf file."""
        service = client.connect(token=self.getSessionKey(), app=APP_NAME)

        try:
            conf = service.confs[CONF_FILE]
        except KeyError:
            service.confs.create(CONF_FILE)
            conf = service.confs[CONF_FILE]

        try:
            stanza = conf["general"]
        except KeyError:
            conf.create("general")
            stanza = conf["general"]

        stanza.submit(settings)

    def _is_api_key_set(self):
        """Check if an API key exists in the credential store."""
        try:
            service = client.connect(
                token=self.getSessionKey(), app=APP_NAME
            )
            for cred in service.storage_passwords:
                if (
                    cred.content.get("realm") == REALM
                    and cred.content.get("username") == CREDENTIAL_USER
                ):
                    return True
        except Exception:
            pass
        return False

    def _save_api_key(self, api_key):
        """Store the API key in Splunk's encrypted credential store."""
        service = client.connect(token=self.getSessionKey(), app=APP_NAME)

        # Delete existing credential if present
        try:
            for cred in service.storage_passwords:
                if (
                    cred.content.get("realm") == REALM
                    and cred.content.get("username") == CREDENTIAL_USER
                ):
                    cred.delete()
                    break
        except Exception:
            pass

        # Create new credential
        service.storage_passwords.create(api_key, CREDENTIAL_USER, REALM)

    def _mark_configured(self):
        """Set is_configured = true in app.conf."""
        try:
            service = client.connect(
                token=self.getSessionKey(), app=APP_NAME
            )
            app_conf = service.confs["app"]
            install_stanza = app_conf["install"]
            install_stanza.submit({"is_configured": "true"})
        except Exception as exc:
            logger.warning("Could not mark app as configured: %s", exc)


admin.init(ProtectorNetSetupHandler, admin.CONTEXT_APP_ONLY)
