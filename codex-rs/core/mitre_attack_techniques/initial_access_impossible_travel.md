## Storyline - Impossible Travel
Detect if the JSON shows the same user logging in from geographically distant locations within an unrealistically short time.

### Entities to extract
User
All login events (location, IP, timestamp, device if available)
asn name and number if available
Simple reasoning explaining why the travel is impossible

### Output Schema
{
  "story_detected": true,
  "story_type": "impossible_travel",
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
        ]
      }
    },
    ...
  ],
  "reasoning": "reasoning or null",
  "_notes": []
}

