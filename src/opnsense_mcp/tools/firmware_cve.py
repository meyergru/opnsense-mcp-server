"""The native OPNsense security (VuXML / package-CVE) audit.

Unlike opn_security_audit, this queries the OPNsense firmware backend, not
local heuristic firewall configuration checks. The OPNsense backend exposes a
GLOBAL log rather than status-by-job-ID. Keep a site-local baseline to avoid
mistaking a stale completed log for the new scan.
"""

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass
from typing import Any
from weakref import WeakKeyDictionary

import httpx
from fastmcp import Context

from opnsense_mcp.api_client import OPNsenseAPI, OPNsenseAPIError
from opnsense_mcp.server import get_api, mcp

_AUDIT_MARKER = "***GOT REQUEST TO AUDIT SECURITY***"
_DONE_MARKER = "***DONE***"
_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
_VULN_PATTERN = re.compile(r"(?m)^\s*([^\s:]{2,120})\s+is vulnerable:\s*$")
_CLEAN_PATTERN = re.compile(r"(?i)\b0\s+problem\(s\)\s+in\s+0\s+installed\s+package\(s\)\s+found\b")
_URL_PATTERN = re.compile(r"(?m)^\s*WWW:\s*(https?://\S+)")
_FAILED_PATTERN = re.compile(
    r"(?im)^\s*(?:pkg:\s*)?(?:failed to|error:|fetch(?:ing)?\s+.*failed|"
    r"unable to|cannot (?:fetch|download|open))"
)
_SESSIONS: WeakKeyDictionary[OPNsenseAPI, _AuditSession] = WeakKeyDictionary()
_LOCKS: WeakKeyDictionary[OPNsenseAPI, asyncio.Lock] = WeakKeyDictionary()


@dataclass
class _AuditSession:
    job_id: str
    baseline_hash: str
    active: bool = True


def _hash_log(log: str) -> str:
    return hashlib.sha256(log.encode("utf-8")).hexdigest()


def _lock_for(api: OPNsenseAPI) -> asyncio.Lock:
    lock = _LOCKS.get(api)
    if lock is None:
        lock = asyncio.Lock()
        _LOCKS[api] = lock
    return lock


def _parse_audit_log(log: str) -> dict[str, Any]:
    """Return package/CVE evidence, never treat missing evidence as 'clean'."""
    # Truncate only the RESULT, never the source during parsing.
    packages: list[dict[str, Any]] = []
    headers = list(_VULN_PATTERN.finditer(log))
    for idx, m in enumerate(headers):
        block = log[m.end() : headers[idx + 1].start() if idx + 1 < len(headers) else len(log)]
        cves = sorted({v.upper() for v in _CVE_PATTERN.findall(block)})
        links = _URL_PATTERN.findall(block)
        detail_lines = [
            line.strip()
            for line in block.splitlines()
            if line.strip() and not line.strip().startswith(("CVE:", "WWW:", "***"))
        ]
        packages.append(
            {
                "package": m.group(1),
                "cves": cves,
                "references": links[:5],
                "description": " ".join(detail_lines)[:350],
            }
        )
    cves_all = sorted({cve for pkg in packages for cve in pkg["cves"]})
    if packages:
        assessment = "vulnerabilities_found"
    elif _CLEAN_PATTERN.search(log) and not _FAILED_PATTERN.search(log):
        assessment = "clean"
    else:
        assessment = "inconclusive"
    return {
        "assessment": assessment,
        "affected_package_count": len(packages),
        "packages": packages[:30],
        "packages_truncated": len(packages) > 30,
        "cves": cves_all[:100],
        "cves_truncated": len(cves_all) > 100,
        "report_excerpt": log[-650:],
        "note": "OPNsense VuXML findings: known database entries, not proof of exploitability or absence of other flaws",
    }


async def _poll(
    api: OPNsenseAPI, state: _AuditSession, max_checks: int, poll_interval_seconds: int
) -> dict[str, Any]:
    """Bounded sampling; errors do not silently become an empty CVE report."""
    last_state = "running"
    for i in range(max_checks):
        try:
            result = await asyncio.wait_for(api.get("firmware.upgradestatus"), timeout=6)
        except (OPNsenseAPIError, httpx.TransportError, TimeoutError) as exc:
            if isinstance(exc, OPNsenseAPIError) and exc.status_code not in (0, 502, 503, 504):
                raise
            return {
                "state": "temporarily_unreachable",
                "job_id": state.job_id,
                "note": "Retry opn_firmware_cve_audit_result; do not restart audit",
            }
        log = result.get("log")
        raw = log if isinstance(log, str) else ""
        last_state = str(result.get("status", "unknown"))
        # Progress log is global and NOT keyed by msg_uuid. Require new log
        # content, the security-audit marker, and a completion marker.
        is_new = _hash_log(raw) != state.baseline_hash
        is_audit = _AUDIT_MARKER in raw
        if is_new and is_audit and _DONE_MARKER in raw and last_state == "done":
            state.active = False
            return {
                "state": "complete",
                "job_id": state.job_id,
                "correlation": "changed global log with security-audit marker (no backend job-ID correlation)",
                **_parse_audit_log(raw),
            }
        if last_state == "reboot":
            return {
                "state": "inconclusive",
                "job_id": state.job_id,
                "note": "Unexpected reboot marker during security audit; manual inspection required",
            }
        if is_new and raw and not is_audit and last_state == "done":
            return {
                "state": "inconclusive",
                "job_id": state.job_id,
                "note": "A different firmware operation appears to have replaced the global log",
            }
        if i + 1 < max_checks:
            await asyncio.sleep(poll_interval_seconds)
    return {
        "state": "running" if last_state in ("running", "done", "error") else "inconclusive",
        "job_id": state.job_id,
        "checks": max_checks,
        "note": "No fresh completed security-audit log yet. Use opn_firmware_cve_audit_result with this job_id.",
    }


@mcp.tool()
async def opn_firmware_cve_audit(
    ctx: Context, site: str = "", max_checks: int = 2, poll_interval_seconds: int = 2
) -> dict[str, Any]:
    """Run OPNsense's ORIGINAL firmware Security Audit against VuXML CVEs.

    Uses POST /api/core/firmware/audit and bounded polling of the firmware
    backend. Allowed on read-only sites: this audits packages and creates
    diagnostic logs but installs no updates or reboots. Returns a structured
    package/CVE assessment if finished, otherwise a job_id to continue via
    opn_firmware_cve_audit_result. It never claims an old global log is a new
    result. A clean assessment requires explicit '0 problem(s)' evidence.
    This is NOT the local heuristic opn_security_audit configuration check.
    """
    if not 1 <= max_checks <= 3 or not 1 <= poll_interval_seconds <= 3:
        raise ValueError("max_checks and poll_interval_seconds must each be 1..3")
    api = get_api(ctx, site)
    async with _lock_for(api):
        existing = _SESSIONS.get(api)
        if existing is not None and existing.active:
            return {
                "state": "already_running",
                "job_id": existing.job_id,
                "note": "Continue with opn_firmware_cve_audit_result; do not start another scan",
            }
        running = await api.get("firmware.running")
        if running.get("status") == "busy":
            return {"state": "backend_busy", "note": "Another firmware operation is running; audit not started"}
        before = await api.get("firmware.upgradestatus")
        raw_before = before.get("log")
        baseline = _hash_log(raw_before if isinstance(raw_before, str) else "")
        started = await api.post("firmware.audit")
        job_id = started.get("msg_uuid")
        if started.get("status") != "ok" or not isinstance(job_id, str) or not job_id:
            return {"state": "start_failed", "backend_status": started.get("status")}
        state = _AuditSession(job_id=job_id, baseline_hash=baseline)
        _SESSIONS[api] = state
    return await _poll(api, state, max_checks, poll_interval_seconds)


@mcp.tool()
async def opn_firmware_cve_audit_result(
    ctx: Context, job_id: str, site: str = "", max_checks: int = 2, poll_interval_seconds: int = 2
) -> dict[str, Any]:
    """Collect a previously started OPNsense CVE scan, tolerating delays.

    Read-only. Requires a matching in-memory job ID and fresh audit log. A
    process/container restart discards session correlation: in that case
    results are intentionally 'unavailable' rather than an old, false clean
    report. Start a NEW audit only after verifying firmware is idle.
    """
    if not 1 <= max_checks <= 3 or not 1 <= poll_interval_seconds <= 3:
        raise ValueError("max_checks and poll_interval_seconds must each be 1..3")
    api = get_api(ctx, site)
    state = _SESSIONS.get(api)
    if state is None or state.job_id != job_id:
        return {"state": "no_matching_session", "note": "Cannot verify old logs after an MCP restart or wrong job ID"}
    return await _poll(api, state, max_checks, poll_interval_seconds)
