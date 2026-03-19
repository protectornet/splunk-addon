/**
 * setup.js — Client-side JavaScript for the ProtectorNet Setup dashboard
 *
 * Handles saving the base URL and API key via the custom REST endpoint.
 * The API key goes to Splunk's encrypted credential store.
 */

/* global require, window, document */
require([
    "jquery",
    "splunkjs/mvc",
    "splunkjs/mvc/simplexml/ready!"
], function ($, mvc) {
    "use strict";

    var service = mvc.createService();

    // Load existing config on page load
    service.get(
        "/servicesNS/nobody/TA-protectornet/protectornet_setup/general",
        {},
        function (err, response) {
            if (!err && response && response.data && response.data.entry) {
                var entry = response.data.entry[0];
                if (entry && entry.content) {
                    var content = entry.content;
                    if (content.base_url) {
                        $("#base_url").val(content.base_url);
                    }
                    if (content.api_key_configured === "true") {
                        $("#api_key").attr("placeholder", "••••••••  (configured — enter new value to change)");
                    }
                }
            }
        }
    );

    // Save handler
    window.saveConfig = function () {
        var baseUrl = $("#base_url").val().trim();
        var apiKey = $("#api_key").val().trim();
        var statusEl = $("#setup_status");

        if (!baseUrl) {
            statusEl
                .removeClass("success").addClass("error")
                .text("Base URL is required.")
                .show();
            return;
        }

        if (baseUrl.indexOf("https://") !== 0) {
            statusEl
                .removeClass("success").addClass("error")
                .text("Base URL must start with https://")
                .show();
            return;
        }

        var data = { base_url: baseUrl };
        if (apiKey) {
            data.api_key = apiKey;
        }

        $("#save_btn").prop("disabled", true).text("Saving...");

        service.post(
            "/servicesNS/nobody/TA-protectornet/protectornet_setup/general",
            data,
            function (err) {
                $("#save_btn").prop("disabled", false).text("Save Configuration");

                if (err) {
                    statusEl
                        .removeClass("success").addClass("error")
                        .text("Error: " + (err.data ? err.data.messages[0].text : err.message || "Unknown error"))
                        .show();
                } else {
                    statusEl
                        .removeClass("error").addClass("success")
                        .text("✓ Configuration saved successfully." + (apiKey ? " API key stored securely." : ""))
                        .show();
                    // Clear the API key field after save
                    $("#api_key").val("").attr("placeholder", "••••••••  (configured — enter new value to change)");
                }
            }
        );
    };
});
