## Storyline - Malicious Process Execution
Detect if the JSON shows a malicious file or suspicious process was executed.

### Match Criteria
- Evidence includes a concrete process creation/execution with:
  - A process object (name/path, command line, pid) and a timestamp for creation/start.
  - One or more of:
    - Verdict/detection status is suspicious/malicious for the process.
    - Suspicious command-line flags (e.g., disabling sandboxing like `--service-sandbox-type=none` or `--no-sandbox`, injection, LOLBIN abuse, script host execution).
    - Parent/child chain anomalies or unexpected utility process behavior.
    - Unsigned or unknown publisher for the executed image (signed-but-abused LOLBINs can still qualify if flags/behavior are suspicious).
- If a suspicious URL/domain is also present, still choose this storyline when process evidence above is strong. Include the URL only as context.
- Deterministic tie-break for signed browsers: If the process (or its utility subprocess) includes sandbox‑disabling or abuse flags, choose this storyline even if the image is a signed browser and the alert was triggered by a network indicator.
- Do NOT choose this storyline when the only signal is a network indicator and the initiating process is a standard signed browser/OS process without suspicious flags; in that case a network communication storyline is more appropriate.

Concretely suspicious browser utility pattern (sufficient on its own when timestamped process evidence is present):
- `chrome.exe` (or another Chromium‑based browser) running a utility subprocess with `--type=utility --utility-sub-type=network.mojom.NetworkService` combined with sandbox disabling such as `--service-sandbox-type=none`, or a top‑level browser with `--no-sandbox`.

### Entities to extract
Users involved in the incident
The asset involved in the incident
Event Timeframe (start + end)
Timestamp for each process event
Exact command line used
File hash (any format), make sure you don't miss any file hashes

### Output Schema
{
  "story_detected": true,
  "story_type": "malicious_process_execution",
  "summary": "summary or null",
  "mitre_attack_techniques": [...],
  "incidents": [
    {
      "entities": {
        "users": [
          {
            "entity_type": "user",
            "username": "canonical login (UPN/email or account name)",
            "display_name": "display name or null",
            "user_email": "email address or null",
            "user_principal_name": "UPN or null",
            "actor_ids": "array of stable user identifiers (e.g., SID, AAD ID) or []",
            "account_sid": "Windows account SID or null",
            "role": "role label(s) such as 'Subject' (actor) or 'Member' (target) or null"
          }
        ],
        "assets": [
          {
            "entity_type": "asset",
            "type": "'source_asset' (initiator) or 'destination_asset' (target)",
            "name": "asset hostname or identifier (lowercase; prefer FQDN; no IPs)",
            "ip_addr": "comma-separated IPs (IPv4/IPv6). Include ALL known addresses for this asset: internal/private, external/public, loopbacks, and all network interfaces. No spaces; dedupe if repeated; order not important; null if unknown",
            "nat_internal_ip": "Set this to true when the asset’s network details imply it’s on a private/internal network or behind NAT (e.g., evidence of internal/private addressing and possibly a distinct external address), otherwise false.",
            "is_indexed": "true if asset exists in inventory/index; false if known not indexed; null if unknown",
            "logsource_id": "originating log source/system identifier (e.g., connector or sensor ID) or null",
            "multi_ip": "True when the asset’s ip_addr contains more than one address (comma‑separated); otherwise unset/False",
            "device_id": "stable device identifier from EDR/asset system (e.g., sensor/agent GUID) or null"
          }
        ],
        "files": [
          {
            "entity_type": "file",
            "file_hash": "Set file_hash = SHA‑1 if available; otherwise use SHA‑256; if neither, use MD5; never choose a less‑preferred hash when a preferred one exists; output only the chosen hash as a lowercase hex string.",
            "file_sha256": "SHA256 of the file or null",
            "file_sha1": "SHA1 of the file or null",
            "file_md5": "MD5 of the file or null",
            "file_access_info": {
              "file_path": "directory portion of the path (POSIX or Windows), or null",
              "file_name": "basename of the file (no directory), or null",
              "file_hash": "optional hash for this file reference (any format) or null",
              "full_path": "absolute/canonical full path or URI; if only one path-like value exists, put it here. If file_path and file_name provided, full_path may be derived as file_path + separator + file_name"
            },
            "asset": "asset hostname/FQDN associated with the file’s host (lowercase) or null",
            "threat_type": "threat category/type from the source (e.g., malware/ransomware) or null",
            "threat_name": "rule/signature/family name linked to the file or null",
            "threat_severity": "textual level indicating how serious the file-related detection is",
            "threat_occurred": "time the threat occurred (ISO-8601 UTC or epoch; normalize to UTC) or null",
            "remediation_status": "what action (if any) was taken to contain or neutralize a detected file, such as blocked, remediated, or partially remediated",
            "remediation_status_details": "free-text details for remediation (reason, errors, extra context) or null"
          }
        ],
        "processes": [
          {
            "entity_type": "process",
            "asset": "asset hostname/FQDN tied to this process or null",
            "device_id": "stable sensor/EDR device identifier (e.g., agent GUID) or null",
            "username": "username on a process identifies which account executed the process and is used to correlate activity to that user across analysis and features",
            "activity_description": "A short human-readable summary of what the process activity represents (typically the alert/signal title or description).",
            "threat_identifier": "A source-provided identifier for the process’s threat (hash, indicator string, or IP), carried for correlation and, when it’s a hash, used to help link the process to its corresponding file.",
            "file_md5": "MD5 of executable image or null",
            "file_sha1": "SHA1 of executable image or null",
            "file_sha256": "SHA256 of executable image or null",
            "start_time": "process start (ISO-8601 UTC preferred, or unix seconds) or null",
            "end_time": "process end (ISO-8601 UTC preferred, or unix seconds) or null",
            "event_creation_time": "The timestamp when the process event was created/emitted by the source system, used as the canonical event time for analyses.",
            "cmd_line": "full command line (include binary + args) or null",
            "parent_cmd_line": "parent process full command line or null",
            "grandparent_cmd_line": "grandparent process full command line or null",
            "parent_process_id": "parent PID as integer or null",
            "ioc_type": "indicator type (e.g., hash, domain, ip) or null",
            "ioc_value": "indicator value matching ioc_type or null",
            "mitigation_status": "array of status objects from EDR (e.g., actions/outcomes) or null",
            "indicators": "A list of raw indicators associated with the process (e.g., IOC objects) when provided by the source; otherwise omitted.",
            "threat_info": "structured threat metadata (e.g., severity, technique IDs) or null",
            "file_access_info": {
              "file_path": "directory portion of the executable/file path (POSIX or Windows), or null",
              "file_name": "basename of the executable/file (no directory), or null",
              "file_hash": "optional hash string when provided by source (any format, e.g., sha256), or null",
              "full_path": "absolute/canonical full path. If not supplied, derive as file_path + separator + file_name; if only a single path-like field exists (e.g., URI), place it here"
            },
            "network_access": [
              {
                "timestamp": "ISO-8601 UTC or unix seconds",
                "source_ip": "source IP",
                "source_port": "source port as string",
                "destination_ip": "destination IP",
                "destination_port": "destination port as string",
                "protocol": "network protocol (e.g., TCP/UDP/ICMP)",
                "direction": "traffic direction relative to host (e.g., outbound/inbound)"
              }
            ],
            "file_access": [
              {
                "timestamp": "ISO-8601 UTC or unix seconds or null",
                "file_path": "directory path of the file",
                "file_name": "file name without path",
                "full_path": "full absolute path; if omitted, derive as file_path + separator + file_name"
              }
            ],
            "executable_writes": [
              {
                "timestamp": "ISO-8601 UTC or unix seconds",
                "file_path": "directory path where executable/content was written",
                "file_name": "written file name"
              }
            ],
            "agent_remediation_actions": "object mapping remediation action names to booleans or detailed objects; keys are vendor-specific (e.g., kill_process, quarantine_file, isolate_host);"
          }
        ]
      }
    },
    ...
  ],
  "timeframe": {
    "start": "the story start timestamp or null",
    "end": "the story end timestamp or null"
  },
  "_notes": []
}


### Normalization rules (technique-specific)
- Multi-source merge:
  - Merge multiple source evidence for the same process using device ID, PID, host, image name/path, and close timestamps.
- Parent command line:
  - If the exact parent command line is available, set parent_cmd_line to that exact string.
  - If not available but the parent image name or path is known, set parent_cmd_line to just the image name (no explanatory text, no synthesized placeholders). Do not inject notes inside the field; put explanations in _notes.
- Hash preference:
  - Populate all available hash fields: set `file_sha256`, `file_sha1`, and `file_md5` when present in the source.
  - Set `file_hash` to the strongest available (prefer sha1, sha256; else md5).
- Timestamp normalization:
  - Normalize all timestamps to ISO-8601 UTC with up to 6 fractional digits (microseconds). If the source provides 7+ digits (e.g., 2025-11-14T02:12:19.2333333Z), truncate/round to 6 digits (2025-11-14T02:12:19.233333Z).
  - start_time: prefer the process’ creation/start timestamp (e.g., processCreationDateTime).
  - Keep timezone as Z (UTC).
