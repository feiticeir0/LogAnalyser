import json
import re
from typing import Any

from langchain_text_splitters import RecursiveCharacterTextSplitter

from models import get_llm
from prompt import build_chunk_analysis_prompt, build_reduce_prompt

EVENT_START_PATTERNS = [
    # ISO-like timestamps: 2026-02-06 12:34:56 / 2026-02-06T12:34:56.123Z
    re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}"),
    # Syslog style: Feb  6 12:34:56
    re.compile(r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"),
    # Bracketed timestamps: [2026-02-06 12:34:56]
    re.compile(r"^\[\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}"),
]

LOGWATCH_SECTION_START_PATTERN = re.compile(
    r"^\s*-{2,}\s+.+\s+Begin\s*-{2,}\s*$"
)

SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _is_event_start(line: str) -> bool:
    """Return True when a line looks like the beginning of a new log event."""
    stripped = line.lstrip()
    return any(pattern.match(stripped) for pattern in EVENT_START_PATTERNS)


def _build_logwatch_events(lines: list[str]) -> list[str]:
    """
    Split Logwatch text into service-level event blocks.

    A new block starts when a line matches the `--- Service Begin ---` pattern.
    """
    events: list[str] = []
    current_event: list[str] = []

    for line in lines:
        if LOGWATCH_SECTION_START_PATTERN.match(line) and current_event:
            events.append("".join(current_event))
            current_event = [line]
        else:
            current_event.append(line)

    if current_event:
        events.append("".join(current_event))
    return events


def _build_timestamp_events(lines: list[str]) -> list[str]:
    """
    Split generic log text into events using timestamp-like line starts.

    Continuation lines (for example stack traces) stay attached to their event.
    """
    events: list[str] = []
    current_event: list[str] = []
    for line in lines:
        if _is_event_start(line) and current_event:
            events.append("".join(current_event))
            current_event = [line]
        else:
            current_event.append(line)
    if current_event:
        events.append("".join(current_event))
    return events


def _split_oversized_event(event_text: str, chunk_size: int) -> list[str]:
    """Split a very large single event into smaller overlapping chunks."""
    splitter = RecursiveCharacterTextSplitter(
        chunk_size=chunk_size,
        chunk_overlap=200,
        separators=["\n\n", "\n", " "],
        keep_separator=True,
    )
    return splitter.split_text(event_text)


def split_logs(log_text: str) -> list[str]:
    """
    Split raw log text into model-ready chunks while preserving event context.

    The function prefers Logwatch section boundaries when present, otherwise it
    falls back to timestamp-based event detection.

    Args:
        log_text (str): Full log text from the uploaded file.

    Returns:
        list[str]: Ordered log chunks to be analyzed independently.
    """
    if not log_text.strip():
        return []

    max_chunk_chars = 8000
    overlap_events = 1
    lines = log_text.splitlines(keepends=True)

    if any(LOGWATCH_SECTION_START_PATTERN.match(line) for line in lines):
        events = _build_logwatch_events(lines)
    else:
        # Generic fallback for non-Logwatch inputs.
        events = _build_timestamp_events(lines)

    chunks: list[str] = []
    current_chunk_events: list[str] = []
    current_chunk_len = 0

    for event in events:
        if len(event) > max_chunk_chars:
            if current_chunk_events:
                chunks.append("".join(current_chunk_events))
                current_chunk_events = []
                current_chunk_len = 0
            chunks.extend(_split_oversized_event(event, max_chunk_chars))
            continue

        if current_chunk_events and (current_chunk_len + len(event) > max_chunk_chars):
            chunks.append("".join(current_chunk_events))
            current_chunk_events = current_chunk_events[-overlap_events:]
            current_chunk_len = sum(len(e) for e in current_chunk_events)

        current_chunk_events.append(event)
        current_chunk_len += len(event)

    if current_chunk_events:
        chunks.append("".join(current_chunk_events))

    return chunks


def _extract_json_payload(text: str) -> dict[str, Any] | None:
    """Extract and parse the most likely JSON object from model output."""
    cleaned = text.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("`")
        cleaned = cleaned.replace("json\n", "", 1).strip()

    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start == -1 or end == -1 or end <= start:
        return None

    candidate = cleaned[start : end + 1]
    try:
        parsed = json.loads(candidate)
        return parsed if isinstance(parsed, dict) else None
    except json.JSONDecodeError:
        return None


def _normalize_severity(value: str) -> str:
    """Normalize arbitrary severity text into the expected enum."""
    lowered = str(value).strip().lower()
    if lowered in SEVERITY_RANK:
        return lowered
    return "medium"


def _normalize_confidence(value: Any) -> float:
    """Clamp confidence to the [0.0, 1.0] range."""
    try:
        conf = float(value)
    except (TypeError, ValueError):
        return 0.5
    return max(0.0, min(1.0, conf))


def _normalize_finding(finding: dict[str, Any], source: str) -> dict[str, Any]:
    """Normalize a finding to a stable schema used by the UI and reducer."""
    evidence = finding.get("evidence", [])
    actions = finding.get("recommended_actions", [])

    return {
        "severity": _normalize_severity(finding.get("severity", "medium")),
        "category": str(finding.get("category", "other")).strip().lower() or "other",
        "service": str(finding.get("service", "unknown")).strip() or "unknown",
        "summary": str(finding.get("summary", "Unspecified finding")).strip(),
        "likely_cause": str(finding.get("likely_cause", "Unknown")).strip(),
        "impact": str(finding.get("impact", "Unknown")).strip(),
        "evidence": [str(item).strip() for item in evidence if str(item).strip()],
        "recommended_actions": [
            str(item).strip() for item in actions if str(item).strip()
        ],
        "confidence": _normalize_confidence(finding.get("confidence", 0.5)),
        "sources": [source],
    }


def _fallback_chunk_payload(raw_text: str, source: str) -> dict[str, Any]:
    """Return a safe fallback payload when JSON parsing fails."""
    summary = raw_text.strip().splitlines()[0] if raw_text.strip() else "No output."
    return {
        "chunk_summary": summary[:240],
        "findings": [
            {
                "severity": "medium",
                "category": "other",
                "service": "unknown",
                "summary": summary[:300] or "Model returned unstructured output.",
                "likely_cause": "Model response was not valid JSON.",
                "impact": "Manual review needed for this chunk.",
                "evidence": [],
                "recommended_actions": [
                    "Review the raw chunk and rerun with a stricter prompt."
                ],
                "confidence": 0.3,
                "sources": [source],
            }
        ],
        "suspicious_patterns": [],
    }


def _analyze_chunk(
    llm: Any,
    chunk: str,
    chunk_index: int,
    profile: str,
) -> dict[str, Any]:
    """Run first-pass analysis for a single chunk and normalize output."""
    source = f"chunk-{chunk_index + 1}"
    response = llm.invoke(build_chunk_analysis_prompt(chunk, profile))
    content = str(response.content)
    parsed = _extract_json_payload(content)
    payload = parsed if parsed else _fallback_chunk_payload(content, source)

    normalized_findings = [
        _normalize_finding(finding, source) for finding in payload.get("findings", [])
    ]
    return {
        "source": source,
        "chunk_summary": str(payload.get("chunk_summary", "")).strip(),
        "findings": normalized_findings,
        "suspicious_patterns": [
            str(item).strip()
            for item in payload.get("suspicious_patterns", [])
            if str(item).strip()
        ],
    }


def _merge_sources(source_lists: list[list[str]]) -> list[str]:
    """Merge and sort unique chunk source labels."""
    merged: set[str] = set()
    for source_list in source_lists:
        for source in source_list:
            merged.add(source)
    return sorted(merged)


def _sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort findings by severity, then confidence descending, then service."""
    return sorted(
        findings,
        key=lambda item: (
            SEVERITY_RANK.get(item.get("severity", "medium"), 2),
            -float(item.get("confidence", 0.0)),
            str(item.get("service", "unknown")).lower(),
        ),
    )


def _local_reduce_fallback(chunk_results: list[dict[str, Any]]) -> dict[str, Any]:
    """Fallback reducer when the second-pass JSON response is unavailable."""
    dedup: dict[str, dict[str, Any]] = {}
    all_patterns: list[str] = []

    for chunk in chunk_results:
        all_patterns.extend(chunk.get("suspicious_patterns", []))
        for finding in chunk.get("findings", []):
            key = f"{finding['service'].lower()}::{finding['summary'].lower()}"
            current = dedup.get(key)
            if not current:
                dedup[key] = finding
                continue

            if SEVERITY_RANK[finding["severity"]] < SEVERITY_RANK[current["severity"]]:
                current["severity"] = finding["severity"]
            current["confidence"] = max(
                float(current.get("confidence", 0.0)),
                float(finding.get("confidence", 0.0)),
            )
            current["sources"] = _merge_sources(
                [current.get("sources", []), finding.get("sources", [])]
            )
            if not current.get("evidence") and finding.get("evidence"):
                current["evidence"] = finding["evidence"]
            if not current.get("recommended_actions") and finding.get(
                "recommended_actions"
            ):
                current["recommended_actions"] = finding["recommended_actions"]

    patterns = sorted({item for item in all_patterns if item})
    findings = _sort_findings(list(dedup.values()))
    overall = (
        "No major issues detected across analyzed chunks."
        if not findings
        else f"Detected {len(findings)} prioritized finding(s) across log chunks."
    )
    return {
        "overall_summary": overall,
        "global_patterns": patterns,
        "findings": findings,
    }


def _reduce_findings(
    llm: Any,
    chunk_results: list[dict[str, Any]],
    profile: str,
) -> dict[str, Any]:
    """Run second-pass global reduction and normalize the final payload."""
    compact_payload = [
        {
            "source": result["source"],
            "chunk_summary": result["chunk_summary"],
            "suspicious_patterns": result["suspicious_patterns"],
            "findings": result["findings"],
        }
        for result in chunk_results
    ]
    prompt = build_reduce_prompt(
        json.dumps(compact_payload, ensure_ascii=True, indent=2),
        profile,
    )
    response = llm.invoke(prompt)
    parsed = _extract_json_payload(str(response.content))
    if not parsed:
        return _local_reduce_fallback(chunk_results)

    findings: list[dict[str, Any]] = []
    for finding in parsed.get("findings", []):
        source_list = finding.get("sources", [])
        if not isinstance(source_list, list):
            source_list = []
        normalized = _normalize_finding(
            finding,
            source_list[0] if source_list else "chunk-unknown",
        )
        normalized["sources"] = _merge_sources(
            [source_list, normalized.get("sources", [])]
        )
        findings.append(normalized)

    return {
        "overall_summary": str(parsed.get("overall_summary", "")).strip(),
        "global_patterns": [
            str(item).strip()
            for item in parsed.get("global_patterns", [])
            if str(item).strip()
        ],
        "findings": _sort_findings(findings),
    }


def _build_markdown_report(final_payload: dict[str, Any], profile: str) -> str:
    """Build the narrative markdown report from the structured final payload."""
    lines: list[str] = []
    lines.append("# Log Analysis Report")
    lines.append(f"Profile: `{profile}`")
    lines.append("")
    lines.append("## Overall Summary")
    lines.append(final_payload.get("overall_summary", "No summary available."))
    lines.append("")

    patterns = final_payload.get("global_patterns", [])
    if patterns:
        lines.append("## Repeated / Suspicious Patterns")
        for pattern in patterns:
            lines.append(f"- {pattern}")
        lines.append("")

    findings = final_payload.get("findings", [])
    if not findings:
        lines.append("## Findings")
        lines.append("No significant findings were detected.")
        return "\n".join(lines)

    lines.append("## Findings")
    for index, finding in enumerate(findings, start=1):
        lines.append(
            f"### {index}. [{finding['severity'].upper()}] "
            f"{finding['summary']} ({finding['service']})"
        )
        lines.append(f"- Category: `{finding['category']}`")
        lines.append(f"- Likely Cause: {finding['likely_cause']}")
        lines.append(f"- Impact: {finding['impact']}")
        lines.append(f"- Confidence: {finding['confidence']:.2f}")
        lines.append(f"- Sources: {', '.join(finding.get('sources', []))}")
        if finding.get("evidence"):
            lines.append("- Evidence:")
            for snippet in finding["evidence"][:5]:
                lines.append(f"  - `{snippet}`")
        if finding.get("recommended_actions"):
            lines.append("- Recommended Actions:")
            for action in finding["recommended_actions"][:5]:
                lines.append(f"  - {action}")
        lines.append("")
    return "\n".join(lines)


def analyze_logs(log_data: str, profile: str = "general") -> dict[str, Any]:
    """
    Analyze logs with a two-pass pipeline and return structured + markdown output.

    Args:
        log_data (str): Raw log text content.
        profile (str): Analysis profile (`general`, `security`, `service_health`,
            `compliance`).

    Returns:
        dict[str, Any]: Structured findings payload and narrative markdown report.
    """
    chunks = split_logs(log_data)
    if not chunks:
        empty_payload = {
            "profile": profile,
            "chunk_count": 0,
            "overall_summary": "No log content was available for analysis.",
            "global_patterns": [],
            "findings": [],
        }
        empty_payload["markdown_report"] = _build_markdown_report(empty_payload, profile)
        return empty_payload

    llm = get_llm()

    chunk_results: list[dict[str, Any]] = []
    for index, chunk in enumerate(chunks):
        chunk_results.append(_analyze_chunk(llm, chunk, index, profile))

    final_payload = _reduce_findings(llm, chunk_results, profile)
    final_payload["profile"] = profile
    final_payload["chunk_count"] = len(chunks)
    final_payload["markdown_report"] = _build_markdown_report(final_payload, profile)
    return final_payload
