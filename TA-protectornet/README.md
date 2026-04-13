# TA-protectornet — SentrySurface Technology Add-on for Splunk

**Version:** 1.0.0  
**Author:** SentrySurface  
**Compatibility:** Splunk Enterprise 8.2+, Splunk Cloud  
**Python:** 3.x (ships with Splunk 8.x+)

## Overview

Enrich Splunk events with SentrySurface threat intelligence. Submit URLs and domains for real-time threat analysis using SentrySurface's WebScan and ThreatHunt services, and get back verdicts (Safe / Suspicious / Malicious), confidence scores, and threat categories — all without leaving Splunk.

## Features

| Feature                  | Description                                                                 |
|--------------------------|-----------------------------------------------------------------------------|
| **Custom Search Commands** | `protectornetscan`, `protectornetstatus`, `protectornetverdict`            |
| **Workflow Actions**       | Right-click any URL or domain in Splunk events → "Scan with SentrySurface" |
| **Adaptive Response**      | Auto-enrich notable events in Splunk Enterprise Security                  |
| **Setup Dashboard**        | Securely configure your API key (encrypted in Splunk credential store)    |
| **Overview Dashboard**     | Submit ad-hoc scans, view verdict distribution, and scan history          |

## Installation

### From Splunkbase
1. In Splunk Web, go to **Apps → Find More Apps**
2. Search for "SentrySurface"
3. Click **Install**
4. Restart Splunk when prompted

### Manual Installation
1. Download `TA-protectornet.tar.gz`
2. Copy to `$SPLUNK_HOME/etc/apps/`
3. Extract: `tar -xzf TA-protectornet.tar.gz`
4. Restart Splunk: `$SPLUNK_HOME/bin/splunk restart`

## Setup

1. Open Splunk Web → **SentrySurface** app → **Setup**
2. Enter your **SentrySurface Base URL** (default: `https://api.sentrysurface.io`)
3. Enter your **API Key** (from SentrySurface → Profile → API Keys)
4. Click **Save Configuration**

> **Security:** Your API key is stored encrypted in Splunk's `storage/passwords` and is never written to plain-text configuration files.

## Usage

### Custom Search Commands

#### `protectornetscan` — Full Scan (Submit + Poll + Verdict)

```spl
# Scan a single URL
| protectornetscan url="https://suspicious-site.com"

# Scan URLs from events
index=proxy sourcetype=squid
| protectornetscan field=url services="webscan,threathunt"
| where ptnet_final_verdict="Malicious"

# Scan with WebScan only
index=email sourcetype=exchange
| protectornetscan field=src_url services="webscan"
| table _time src_url ptnet_final_verdict ptnet_confidence ptnet_threat_score
```

**Output fields:** `ptnet_submission_id`, `ptnet_url`, `ptnet_final_verdict`, `ptnet_confidence`, `ptnet_threat_score`, `ptnet_category`, `ptnet_services`, `ptnet_status`, `ptnet_report_url`, `ptnet_error`

#### `protectornetstatus` — Check Scan Status

```spl
| protectornetstatus submission_id="abc-123-def" service="webscan"
```

**Output fields:** `ptnet_submission_id`, `ptnet_service`, `ptnet_status`

#### `protectornetverdict` — Fetch Verdict

```spl
| protectornetverdict submission_id="abc-123-def"
```

**Output fields:** `ptnet_submission_id`, `ptnet_final_verdict`, `ptnet_confidence`, `ptnet_category`, `ptnet_threat_score`, `ptnet_details`, `ptnet_verdicts_raw`, `ptnet_report_url`, `ptnet_status`

### Workflow Actions

Right-click any event containing a `url`, `dest_url`, `domain`, or `dest_host` field:
- **Scan with SentrySurface** — opens the SentrySurface overview dashboard with the URL pre-filled
- **Scan Domain with SentrySurface** — same, but for domain fields

### Adaptive Response (Enterprise Security)

1. Go to **Enterprise Security → Configure → Content → Correlation Searches**
2. Edit a correlation search
3. Under **Adaptive Response Actions**, click **Add New Response Action**
4. Select **SentrySurface Threat Scan**
5. Configure:
   - **URL Field**: the field containing the URL (default: `url`)
   - **Services**: `webscan,threathunt`

## API Endpoints Used

| Endpoint                                         | Method | Purpose          |
|--------------------------------------------------|--------|------------------|
| `/search/threatanalyse`                          | POST   | Submit URL scan  |
| `/search/threatanalyse/webscanstatus/{id}`       | GET    | Poll WebScan     |
| `/search/threatanalyse/threathuntstatus/{id}`    | GET    | Poll ThreatHunt  |
| `/search/threatverdict/{id}`                     | GET    | Get verdict      |
| `/search/webscan/fulldata/{id}/v2?profile=...`   | GET    | Full scan data   |
| `/search/webscan/phishingdomains/{id}`           | GET    | Phishing domains |

## Security

- **Credential Storage:** API key stored in Splunk's `storage/passwords` (AES-256 encrypted)
- **SSL/TLS:** All API calls use HTTPS with certificate verification enabled
- **Input Validation:** URLs, domains, and submission IDs validated before API calls
- **Access Control:** Setup endpoint restricted to `admin` role via `default.meta`
- **No Logging of Secrets:** API key is never written to logs
- **Zero External Dependencies:** Uses only Python standard library + Splunk SDK

## Troubleshooting

| Issue                          | Solution                                                        |
|--------------------------------|-----------------------------------------------------------------|
| "API key not configured"       | Go to SentrySurface → Setup and enter your API key               |
| "Invalid API key (401)"        | Verify the key in SentrySurface → Profile → API Keys             |
| "Rate limit exceeded (429)"    | Wait 60 seconds, or upgrade your SentrySurface plan              |
| "Scan timed out"               | The scan exceeded 10 minutes. Check submission status manually  |
| Commands not found             | Restart Splunk after installation                               |

## File Structure

```
TA-protectornet/
├── app.manifest                          # Splunkbase manifest
├── README.md                             # This file
├── default/
│   ├── app.conf                          # App metadata
│   ├── commands.conf                     # Search command definitions
│   ├── alert_actions.conf                # Alert action / Adaptive Response
│   ├── restmap.conf                      # REST endpoint for setup
│   ├── web.conf                          # Web settings
│   ├── workflow_actions.conf             # Right-click workflow actions
│   ├── ta_protectornet_settings.conf     # App settings (base URL)
│   └── data/ui/
│       ├── nav/default.xml               # Navigation
│       └── views/
│           ├── protectornet_overview.xml  # Main dashboard
│           └── setup.xml                 # Setup page
├── metadata/
│   ├── default.meta                      # Permissions
│   └── local.meta                        # User overrides (empty)
├── bin/
│   ├── protectornetscan.py               # Full scan command
│   ├── protectornetstatus.py             # Status check command
│   ├── protectornetverdict.py            # Verdict fetch command
│   ├── protectornet_alert_action.py      # Alert action handler
│   ├── protectornet_setup_handler.py     # Setup REST handler
│   └── lib/
│       ├── __init__.py
│       └── protectornet_client.py        # Shared API client
├── appserver/static/
│   └── setup.js                          # Setup page JavaScript
└── README/
    ├── alert_actions.conf.spec           # Alert action parameter spec
    └── ta_protectornet_settings.conf.spec # Settings spec
```

## Support

- **Documentation:** https://docs.sentrysurface.io/integrations/splunk
- **Support Email:** support@sentrysurface.io
- **GitHub:** https://github.com/SentrySurface/splunk-addon

## License

Copyright © 2026 SentrySurface. All rights reserved.
See https://sentrysurface.io/terms for license terms.
