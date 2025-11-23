> See Entity Field Guidance: ./entities_reference.md

## Storyline - Lateral Movement (Administrator Impersonation)
Detect if the JSON shows an authentication where an administrator account appears to be impersonated or used to access another account/session on the same or another asset.

### Entities to extract
- Two or more users (subject/source and target/destination)
- Source and destination assets
- Authentication details (service, process)
- Whether local vs remote (loopback vs non-loopback)
- Timeframe
- Brief reasoning

### Output Schema
{
  "story_detected": true,
  "story_type": "lateral_movement_administrator_impersonation",
  "summary": "summary or null",
  "mitre_attack_techniques": [...],
  "incidents": [
    {
      "entities": {
        "users": [
          {
            "entity_type": "user",
            "username": "username",
            "display_name": "display name or null",
            "user_principal_name": "UPN or null",
            "account_sid": "SID or null",
            "actor_ids": ["ids..."],
            "role": "Subject|Member or list or null"
          }
        ],
        "assets": [
          { "entity_type": "asset", "name": "source asset hostname", "ip_addr": "source ip or null", "type": "source_asset" },
          { "entity_type": "asset", "name": "destination asset hostname", "ip_addr": "destination ip or null", "type": "destination_asset" }
        ],
        "active_directory_auths": [
          {
            "entity_type": "active_directory_auth",
            "source_asset": "source asset or null",
            "dest_asset": "destination asset or null",
            "target_account": "target account or null",
            "subject_account": "originating account or null",
            "service": "Kerberos/NTLM/etc. or null",
            "process": "process path/name or null",
            "is_local": "true if same asset, false if different, null if unknown"
          }
        ]
      }
    }
  ],
  "timeframe": { "start": "start timestamp or null", "end": "end timestamp or null" },
  "reasoning": "brief reasoning or null",
  "_notes": []
}
