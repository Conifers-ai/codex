> See Entity Field Guidance: ./entities_reference.md

## Storyline - Initial Access (Reported Suspicious Email)
Detect if the JSON shows an email reported as malware or phishing by a user or system, focusing on sender authentication, delivery, headers, and content indicators.

### Entities to extract
- Email metadata (from/to/subject/date/user agent/content type)
- Auth results (SPF, DKIM, DMARC)
- Body indicators (links, attachments, tracking pixels, patterns)
- Timeframe
- Brief reasoning

### Output Schema
{
  "story_detected": true,
  "story_type": "reported_suspicious_email",
  "summary": "summary or null",
  "mitre_attack_techniques": [...],
  "incidents": [
    {
      "entities": {
        "emails": [
          {
            "entity_type": "email",
            "title": "email title/subject or empty string",
            "primary_value": "sender email or null",
            "auth_valid": { "SPF": "true|false|null", "DKIM": "true|false|null", "DMARC": "true|false|null" },
            "spf": { "domain": "domain", "selector": "selector or null", "is_passed": "bool|null" },
            "dkim": { "domain": "domain", "selector": "selector or null", "is_passed": "bool|null" },
            "dmarc": { "domain": "domain", "selector": "selector or null", "is_passed": "bool|null" },
            "headers": {
              "from_address": { "email": "email", "username": "local", "display_name": "name or null", "domain": "domain", "ip": "ip or null", "role": "role or null", "selector": "selector or null" },
              "to": [{ "email": "email", "username": "local", "display_name": "name or null", "domain": "domain", "ip": "ip or null", "role": "role or null", "selector": "selector or null" }],
              "cc": [{ "email": "email", "display_name": "name or null", "domain": "domain" }],
              "subject": "subject or empty string",
              "date": "date string or null",
              "received": ["received chain entries or empty"],
              "message_id": "internet message id or null",
              "user_agent": "user agent or null",
              "content_type": "content type or null",
              "mime_version": "mime version or null",
              "list_unsubscribe": "list unsubscribe header or null"
            },
            "body": {
              "message_content": "extracted text content or null",
              "html_text": "html content or null",
              "links": ["urls if any"],
              "call_to_actions": ["cta phrases if any"],
              "tracking_pixels": ["tracking indicators if any"],
              "suspicious_scripts": ["scripts if any"],
              "suspicious_patterns": {}
            },
            "attachments": [],
            "is_phishing": "true|false|null",
            "analyst_tags": [],
            "x_spam_score": "score or null",
            "x_spam_status": "status or null",
            "swimlane_verdict": "verdict or null"
          }
        ]
      }
    }
  ],
  "timeframe": { "start": "start timestamp or null", "end": "end timestamp or null" },
  "reasoning": "brief reasoning or null",
  "_notes": []
}
