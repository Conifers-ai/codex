## Storyline - Initial Access (Malicious File Detected on Host)
Detect if the JSON shows a malicious file that was detected - but not executed

### Entities to extract
Users involved
The asset involved
Timeframe (start + end)
File details
Timestamp for the event
File hash (any format)

### Output Schema
{
  "story_detected": true,
  "story_type": "malicious_file_detected",
  "summary": "summary or null",
  "mitre_attack_techniques": [...],
  "incidents": [
    {
      "entities": {
        "users": [
          {
            "entity_type": "user",
            "upn": "user principal name or null",
            "display_name": "display name or none",
            "account_name": "acount name or null"
          }
        ],
        "assets": [
          {
            "entity_type": "asset",
            "name": "device fqdn or null",
            "ip_addr": ["local interfaces including loopback, internal address, and its outward-facing IPs"],
            "device_id": "device id or null",
            "log_source": "log source or null",
            "nat_internal_ip": "internal ip if behind nat or null"
          }
        ],
        "files": [
          {
            "entity_type": "file",
            "asset": "asset hostname or null",
            "end_time": "end timestamp or null",
            "file_md5": "md5 hash or null",
            "device_id": "device id or null",
            "file_sha1": "sha1 hash or null",
            "start_time": "start timestamp or null",
            "file_sha256": "sha256 hash or null",
            "full_path": "full file path or null",
            "mitigation_status": "mitigation status or null",
            "agent_remediation_actions": "remediation actions or null"
          }
        ]
      }
    },
    ...
  ],
  "timeframe": {
    "start": "start timestamp or null",
    "end": "end timestamp or null"
  },
  "_notes": []
}


