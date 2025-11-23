> See Entity Field Guidance: ./entities_reference.md

## Storyline - Suspicious External Communication to Exposed Service Port
Detect if the JSON shows communication between a public/malicious IP and an internal/private IP on an exposed service port, suggesting reconnaissance, unauthorized access attempts, or potential data exfiltration.

### Entities to extract
- Source and destination IPs (ASN/country if available)
- Network event details (src/dest IPs, ports, protocol)
- Timeframe
- Reasoning why suspicious

### Output Schema
{
  "story_detected": true,
  "story_type": "suspicious_external_service_port_communication",
  "summary": "summary or null",
  "mitre_attack_techniques": [...],
  "incidents": [
    {
      "entities": {
        "ips": [
          {
            "entity_type": "ip",
            "ip_addr": "ip address",
            "ip_type": "source_ip|destination_ip or null",
            "country_code": "2-letter code or null",
            "country_name": "country name or null",
            "asn_name": "asn name or null",
            "asn_number": "asn number or null",
            "log_source": "vendor/source or null",
            "dst_ip": "destination ip or null"
          }
        ],
        "network_events": [
          {
            "entity_type": "network_event",
            "raw_timestamp": "original time string or null",
            "timestamp": "epoch millis or null",
            "transport_protocol": "TCP|UDP|ICMP or null",
            "src_ip": "source ip or null",
            "src_port": "source port or null",
            "src_process": "source process or null",
            "dest_ip": "destination ip or null",
            "dest_port": "destination port or null",
            "dest_process": "destination process/service or null"
          }
        ]
      }
    }
  ],
  "timeframe": { "start": "start timestamp or null", "end": "end timestamp or null" },
  "reasoning": "brief reasoning or null",
  "_notes": []
}
