#
# alert_actions.conf.spec — Documentation for the ProtectorNet alert action parameters
#

[protectornet_scan]
param.url_field = <string>
  * The field name containing the URL to scan
  * Default: url

param.services = <string>
  * Comma-separated list of ProtectorNet services to invoke
  * Valid values: webscan, threathunt
  * Default: webscan,threathunt
