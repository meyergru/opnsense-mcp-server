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
from opnsense_mcp.tool_types import SiteName

_AUDIT_MARKER = "***GOT REQUEST TO AUDIT SECURITY***"
_HEALTH_MARKER = "***GOT REQUEST TO AUDIT HEALTH***"
_HEALTH_ISSUE = re.compile(
    r"(?i)(?:checksum mismatch|version mismatch|repository mismatch|"
    r"invalid .*\\.sig|missing files:\\s*[1-9]|"
    r"package not installed:|failed to|error [1-9]|"
    r"could not determine|cannot verify|incorrect, expected:|"
    r"no package manager|not known to package database|"
    r"has no upstream equivalent|unverified consistency check|"
    r"\\bis (?:not set|set) to (?:automatic|vital))"
)
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
    audit_kind: str = "security"


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
        "note": (
        "Native OPNsense/FreeBSD VuXML checks installed package/version matches against "
        "known advisories. A match is not proof that the vulnerable component, code "
        "path or configuration is used or remotely reachable; e.g. a MySQL client "
        "package does not imply a running MySQL server. Conversely, client libraries "
        "can be exploitable even without a local server. Check the exact CVE, "
        "installed component, service/feature use and exposure separately. "
        "No findings cannot exclude unknown vulnerabilities."
    ),
    }


def _parse_health_log(log: str) -> dict[str, Any]:
    """Report observed integrity/dependency anomalies; never claim overall health."""
    if _HEALTH_MARKER not in log or _DONE_MARKER not in log:
        return {"assessment": "inconclusive", "note": "No complete native health audit log"}
    findings = []
    for line in log.splitlines():
        line = line.strip()
        if not line or line.startswith((">>>", "***")) or line == "No problems detected.":
            continue
        if _HEALTH_ISSUE.search(line):
            findings.append(line[:300])
    sections = [line.strip()[4:][:140] for line in log.splitlines() if line.strip().startswith(">>> ")]
    has_integrity_checks = any("installed kernel version" in x for x in sections) and any(
        "missing or altered package files" in x for x in sections
    )
    if findings:
        assessment = "integrity_findings_reported"
    elif has_integrity_checks:
        assessment = "no_anomalies_detected_in_report"
    else:
        assessment = "inconclusive"
    return {
        "assessment": assessment, "checks": sections[:30],
        "findings": findings[:40], "findings_truncated": len(findings) > 40,
        "note": (
            "Native OPNsense firmware health checks compare local files, versions and "
            "package dependencies. No reported anomaly is NOT proof of a fully healthy "
            "system or absence of CVEs. Output is not an independently verified test "
            "of runtime network services, backups, or exploitability."
        ),
    }


async def _poll(api: OPNsenseAPI, state: _AuditSession, max_checks: int, poll_interval_seconds: int) -> dict[str, Any]:
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
        expected_marker = _AUDIT_MARKER if state.audit_kind == "security" else _HEALTH_MARKER
        is_audit = expected_marker in raw
        if is_new and is_audit and _DONE_MARKER in raw and last_state == "done":
            state.active = False
            return {
                "state": "complete",
                "job_id": state.job_id,
                "correlation": "changed global log with security-audit marker (no backend job-ID correlation)",
                **(_parse_audit_log(raw) if state.audit_kind == "security" else _parse_health_log(raw)),
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
    ctx: Context, site: SiteName = "", max_checks: int = 2, poll_interval_seconds: int = 2
) -> dict[str, Any]:
    """Run the NATIVE OPNsense firmware package/CVE audit (FreeBSD VuXML).

    OPNsense's backend matches known VuXML advisories to INSTALLED package
    names and versions. This is an upstream/package-level vulnerability flag,
    NOT proof of exploitability in this firewall's actual configuration.
    In particular distinguish CLIENT from SERVER components (e.g. mysql-client
    installed is not evidence of a running MySQL server), transitive dependencies,
    disabled/unused plugins or services, affected code paths, network exposure,
    and mitigations. Conversely a vulnerable client can still be exploitable
    without the corresponding server. Investigate each CVE and its affected
    component before claiming a concrete threat; the MCP server cannot infer
    that automatically. "clean" means no known VuXML package matches at scan
    time, NOT "no CVEs exist" or "system secure".

    Uses POST /api/core/firmware/audit and bounded polling. Allowed on
    read-only sites: writes diagnostic logs but installs no updates/reboots.
    Returns a package/CVE finding or job_id for
    opn_firmware_cve_audit_result. Global firmware logs are not job-specific;
    only fresh log evidence is accepted. A clean result requires explicit
    '0 problem(s)' evidence. This is NOT opn_security_audit, which performs
    heuristic configuration checks.
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
    ctx: Context, job_id: str, site: SiteName = "", max_checks: int = 2, poll_interval_seconds: int = 2
) -> dict[str, Any]:
    """Collect a started native OPNsense VuXML package/CVE audit.

    Output describes known advisory matches for installed package versions,
    NOT whether a vulnerable service/code path is enabled, used or reachable.
    Distinguish client vs server packages and confirm the actual CVE scope and
    configuration before judging exploitability. A "clean" VuXML scan does
    not establish the absence of all vulnerabilities.

    Read-only polling. Requires a matching in-memory job ID and fresh log.
    A process/container restart discards session correlation: old results
    are intentionally 'unavailable', never a false clean report. Start a
    new audit only after verifying firmware is idle.
    """
    if not 1 <= max_checks <= 3 or not 1 <= poll_interval_seconds <= 3:
        raise ValueError("max_checks and poll_interval_seconds must each be 1..3")
    api = get_api(ctx, site)
    state = _SESSIONS.get(api)
    if state is None or state.job_id != job_id or state.audit_kind != "security":
        return {"state": "no_matching_session", "note": "Cannot verify old logs after an MCP restart or wrong job ID"}
    return await _poll(api, state, max_checks, poll_interval_seconds)


@mcp.tool()
async def opn_firmware_health_audit(
    ctx: Context, site: SiteName = "", max_checks: int = 2, poll_interval_seconds: int = 2
) -> dict[str, Any]:
    """Run OPNsense's NATIVE firmware integrity/dependency health audit.

    This is NOT the heuristic configuration check opn_security_audit and NOT
    the VuXML CVE scan opn_firmware_cve_audit. The OPNsense firmware backend
    checks kernel/base versions and file integrity, repositories, plugins,
    installed package files and missing dependencies. Its 'no findings'
    result is NOT proof that services work, no CVEs exist or a system is safe.
    Backend verified against OPNsense health.sh: uses pkg check -dan/-sa,
    performs diagnostic checks and creates logs, but no upgrades/reboots.
    The native script may touch temporary verification files.

    Uses POST /api/core/firmware/health (reviewed diagnostic allowlist).
    Firmware backend progress log is GLOBAL and not keyed to the returned
    UUID. We compare against the prior log and require an explicit health
    marker and completion before parsing. If still running, use the job_id
    with opn_firmware_health_audit_result. Never initiate overlapping firmware
    operations. Anomalies require administrator review, not automatic repairs.
    """
    if not 1 <= max_checks <= 3 or not 1 <= poll_interval_seconds <= 3:
        raise ValueError("max_checks and poll_interval_seconds must each be 1..3")
    api = get_api(ctx, site)
    async with _lock_for(api):
        existing = _SESSIONS.get(api)
        if existing is not None and existing.active:
            return {
                "state": "already_running", "audit_kind": existing.audit_kind,
                "job_id": existing.job_id,
                "note": "Do not overlap firmware audits; collect the existing result first",
            }
        running = await api.get("firmware.running")
        if running.get("status") == "busy":
            return {"state": "backend_busy", "note": "Another firmware operation is running; health audit not started"}
        before = await api.get("firmware.upgradestatus")
        old_log = before.get("log")
        baseline = _hash_log(old_log if isinstance(old_log, str) else "")
        started = await api.post("firmware.health")
        job_id = started.get("msg_uuid")
        if started.get("status") != "ok" or not isinstance(job_id, str) or not job_id:
            return {"state": "start_failed", "backend_status": started.get("status")}
        state = _AuditSession(job_id=job_id, baseline_hash=baseline, audit_kind="health")
        _SESSIONS[api] = state
    return await _poll(api, state, max_checks, poll_interval_seconds)


@mcp.tool()
async def opn_firmware_health_audit_result(
    ctx: Context, job_id: str, site: SiteName = "",
    max_checks: int = 2, poll_interval_seconds: int = 2
) -> dict[str, Any]:
    """Collect a running native OPNsense firmware health audit by its MCP job ID.

    Polls the fixed global firmware log, requiring fresh content plus the
    HEALTH marker and completion marker. It refuses to reuse an old or
    unrelated audit log; sessions cannot survive MCP restarts. A completed
    integrity check is NOT a security, CVE or full operational health verdict.
    """
    if not 1 <= max_checks <= 3 or not 1 <= poll_interval_seconds <= 3:
        raise ValueError("max_checks and poll_interval_seconds must each be 1..3")
    api = get_api(ctx, site)
    state = _SESSIONS.get(api)
    if state is None or state.job_id != job_id or state.audit_kind != "health":
        return {"state": "no_matching_session", "note": "Cannot safely correlate old or unrelated firmware logs"}
    return await _poll(api, state, max_checks, poll_interval_seconds)
