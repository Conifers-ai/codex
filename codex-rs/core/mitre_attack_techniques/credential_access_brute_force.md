## Storyline - Brute Force (Distributed Password Guessing)
Detect if the JSON shows repeated failed sign-in attempts against an account, often from multiple IPs/providers, indicative of brute force.

### Entities to extract
User targeted (UPN/display name if available)
All source IPs involved (include ASN and country if available)
Timeframe (start + end)
Attempt counts (total/failed/successful)
Result codes/descriptions (e.g., AAD error codes)
Apps/clients targeted and user agent details (browser/OS) if present
User-to-IP associations (user_ip)

### Output Schema
{
  "story_detected": true,
  "story_type": "brute_force",
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
          "account_name": "acount name or null"
        }],
        "ips": [
          {
            "entity_type": "ip",
            "dst_ip": "destination ip or null",
            "ip_addr": "source ip or null",
            "asn_name": "the asn name or null",
            "asn_number": "the asn number or null",
            "log_source": "log source or null",
            "country_code": "2 letter country code or null",
            "country_name": "country name or null"
          }
        ],
        "user_ips": [
          {
            "entity_type": "user_ip",
            "username": "user principal name or null",
            "ip_addr": "ip address or null",
            "primary_value": "username_ip composite or null"
          }
        ]
      }
    },
    ...
  ],
  "attempts": {
    "total": "total attempts or null",
    "failed": "failed attempts or null",
    "successful": "successful attempts or null",
    "result_descriptions": ["result code/description strings"],
    "apps": ["app display names if available"],
    "browsers": ["browser strings if available"],
    "oses": ["os strings if available"]
  },
  "timeframe": {
    "start": "start timestamp or null",
    "end": "end timestamp or null"
  },
  "reasoning": "brief reasoning explaining why this is brute force (e.g., many failures from multiple IPs and no successes) or null",
  "_notes": []
}


