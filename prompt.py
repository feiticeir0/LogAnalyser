ANALYSIS_PROFILES = {
    "general": (
        "Prioritize service-impacting errors and security-relevant anomalies with balanced depth."
    ),
    "security": (
        "Prioritize threat hunting signals: auth abuse, brute force, privilege escalation, "
        "suspicious network/process behavior, and persistence indicators."
    ),
    "service_health": (
        "Prioritize availability, reliability, restart loops, failed jobs, resource pressure, "
        "and operational stability."
    ),
    "compliance": (
        "Prioritize auditable evidence, policy-relevant violations, access control events, and "
        "clear remediation steps."
    ),
}


def get_profile_instruction(profile: str) -> str:
    """Return the profile instruction text, defaulting to `general`."""
    return ANALYSIS_PROFILES.get(profile, ANALYSIS_PROFILES["general"])


def build_chunk_analysis_prompt(log_data: str, profile: str) -> str:
    """Build the prompt used for first-pass chunk analysis."""
    profile_instruction = get_profile_instruction(profile)
    return f"""
You are a senior Linux systems administrator with deep security experience.
Task focus: {profile_instruction}

Analyze the log chunk below and return ONLY valid JSON (no markdown, no code block).
The JSON format must be:
{{
  "chunk_summary": "short summary",
  "findings": [
    {{
      "severity": "critical|high|medium|low",
      "category": "security|service|performance|configuration|compliance|other",
      "service": "service/component name or unknown",
      "summary": "concise issue statement",
      "likely_cause": "likely cause based on evidence",
      "impact": "operational/security impact",
      "evidence": ["exact short log lines/snippets from this chunk"],
      "recommended_actions": ["practical next step 1", "practical next step 2"],
      "confidence": 0.0
    }}
  ],
  "suspicious_patterns": ["optional repeated pattern 1", "optional pattern 2"]
}}

Rules:
- Evidence entries must be directly grounded in this chunk. Keep them short and verbatim.
- If no meaningful issue exists, return an empty findings list and explain briefly in chunk_summary.
- Confidence must be from 0.0 to 1.0.
- Never invent hosts/IPs/processes that are not present.

Log chunk:
{log_data}
""".strip()


def build_reduce_prompt(chunk_findings_json: str, profile: str) -> str:
    """Build the prompt used for the second-pass global reducer."""
    profile_instruction = get_profile_instruction(profile)
    return f"""
You are a senior Linux systems administrator producing a final incident triage report.
Task focus: {profile_instruction}

You will receive first-pass chunk analyses in JSON.
Merge and deduplicate related findings across chunks.
Return ONLY valid JSON (no markdown, no code block) in this format:
{{
  "overall_summary": "high-level assessment",
  "global_patterns": ["cross-chunk repeated pattern 1", "pattern 2"],
  "findings": [
    {{
      "severity": "critical|high|medium|low",
      "category": "security|service|performance|configuration|compliance|other",
      "service": "service/component name or unknown",
      "summary": "deduplicated issue statement",
      "likely_cause": "likely cause",
      "impact": "impact",
      "evidence": ["short evidence snippets with chunk markers when available"],
      "recommended_actions": ["action 1", "action 2"],
      "confidence": 0.0,
      "sources": ["chunk-1", "chunk-2"]
    }}
  ]
}}

Rules:
- Deduplicate near-identical findings.
- Keep highest severity when duplicates conflict.
- Preserve evidence references.
- Sort findings by severity (critical->low), then confidence desc.

Input chunk analyses JSON:
{chunk_findings_json}
""".strip()
