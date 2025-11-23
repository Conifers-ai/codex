## Storyline - Lateral Movement (Asset Authentication from Service Account)
Detect if the JSON shows a successful authentication from one asset to another, especially using a service account, indicative of lateral movement.

### Entities to extract
User/service account involved (account name, display name, domain, SID if present)
Source and destination assets (hostnames/FQDNs and IPs if available)
Authentication event details (timestamp, result, logon type, service, Windows event code)
Network details (src/dest IP, ports, protocol if available)
Timeframe (start + end)
Simple reasoning why this is lateral movement (new source for account, remote auth, etc.)

### Output Schema
{
  "story_detected": true,
  "story_type": "lateral_movement_asset_authentication",
  "summary": "summary or null",
  "mitre_attack_techniques": [...],
  "incidents": [
    {
      "entities": {
        "users": [{
          "entity_type": "user",
          "role": "user role or null",
          "username": "the user name or null",
          "actor_ids": ["the", "actor", "ids"],
          "display_name": "the display name or null",
          "upn": "user principal name or null",
          "account_name": "account name or null",
          "domain": "domain or null",
          "account_sid": "account SID or null"
        }],
        "assets": [
          {
            "entity_type": "asset",
            "name": "source asset fqdn or hostname or null",
            "ip_addr": "source ip or null",
            "type": "source_asset"
          },
          {
            "entity_type": "asset",
            "name": "destination asset fqdn or hostname or null",
            "ip_addr": "destination ip or null",
            "type": "destination_asset"
          }
        ],
        "network_events": [
          {
            "entity_type": "network_event",
            "timestamp": "event timestamp (epoch ms) or null",
            "raw_timestamp": "event timestamp (iso8601) or null",
            "src_asset_name": "source asset name or null",
            "dest_asset_name": "destination asset name or null",
            "src_ip": "source ip or null",
            "dest_ip": "destination ip or null",
            "src_port": "source port or null",
            "dest_port": "destination port or null",
            "transport_protocol": "protocol or null",
            "windows_event_code": "event id/code or null",
            "service": "authentication service (e.g., Kerberos, NTLM) or null",
            "logon_type": "logon type or null",
            "result": "SUCCESS/FAILURE or null",
            "destination_account": "account name or null",
            "destination_domain": "domain or null",
            "destination_account_sid": "SID or null"
          }
        ]
      }
    }
  ],
  "timeframe": {
    "start": "start timestamp or null",
    "end": "end timestamp or null"
  },
  "reasoning": "brief reasoning why this is lateral movement (e.g., remote authentication to a new destination asset by a service account) or null",
  "_notes": []
}
