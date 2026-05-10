"""Convert raw ScanResult into severity-tagged findings + a score.

Findings are the human-readable layer between the AST scanner (which
just collects function-call locations) and the markdown report (which
needs prose statements like "✅ No subprocess detected"). Each
finding has a severity — info / low / medium / high — and contributes
deterministically to the 0-10 score.

The score heuristic is deliberately simple and documented: an audit
score that depends on inscrutable weights is just gut-feel with extra
steps. See README's "Scoring methodology" section for the rationale
behind each deduction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from audit.ast_scan import ScanResult


Severity = Literal["info", "low", "medium", "high"]


@dataclass
class Finding:
    """One audit finding."""
    rule_id: str            # stable identifier e.g. "MCP001" — for suppression + changelogs
    dimension: str          # e.g. "Network", "Code execution", "Filesystem"
    severity: Severity      # info | low | medium | high
    title: str              # short one-line title
    detail: str = ""        # multi-line detail; locations, hostnames, etc.
    deduction: int = 0      # points subtracted from the score (always >= 0)


# ── Rule ID catalog ────────────────────────────────────────────────────────
#
# Stable identifiers for every finding type. These are part of the public
# contract: maintainers use them in suppression directives, CI scripts use
# them to gate, and changelogs reference them. Once published, never reuse
# a number — retire it and assign the next available if a check changes
# meaning materially.
#
# Numbering convention: sorted by rough severity tier. MCP001-MCP009 are
# code-execution / filesystem / network risks. MCP010+ are auxiliary.

class RuleID:
    SUBPROCESS              = "MCP001"  # subprocess.run / os.system / etc.
    DYNAMIC_EXEC            = "MCP002"  # eval / exec / compile / __import__
    TLS_DISABLED            = "MCP003"  # verify=False
    UNSAFE_DESERIALIZATION  = "MCP004"  # pickle / yaml.load(no SafeLoader) / etc.
    INBOUND_NETWORK         = "MCP005"  # socket.bind / HTTP servers
    FS_WRITE                = "MCP006"  # open(w/a/x), os.remove, shutil writes
    BROAD_CREDENTIAL_ENV    = "MCP007"  # AWS_SECRET_ACCESS_KEY etc.
    MULTIPLE_HOSTS          = "MCP008"  # > 1 distinct outbound host
    URL_CONSTRUCTION        = "MCP009"  # f-string / concat URL
    DYNAMIC_HTTP_DEST       = "MCP010"  # HTTP call but no resolved host
    LOOSE_DEP_PINS          = "MCP011"  # all deps without ==
    ZERO_WIDTH_UNICODE      = "MCP012"  # ZWSP, bidi-override in string literals
    INJECTION_PATTERN       = "MCP013"  # "ignore previous instructions" etc.
    UNKNOWN_ENV_KEY         = "MCP014"  # os.environ.get with non-literal key


@dataclass
class AuditReport:
    """Findings list + score + metadata, ready for rendering."""
    scan: ScanResult
    findings: list[Finding] = field(default_factory=list)
    score: int = 10
    total_deduction: int = 0  # uncapped sum of all deductions (vs. score which floors at 0)
    score_explanation: list[str] = field(default_factory=list)
    capabilities_yes: list[str] = field(default_factory=list)
    capabilities_no:  list[str] = field(default_factory=list)
    suppressions_applied: list[tuple[str, str, int]] = field(default_factory=list)  # (rule_id, file, line)


def _not_suppressed(call_sites: list, rule_id: str, report: AuditReport) -> list:
    """Filter out call sites that have an inline `# mcp-audit: ignore <rule_id>`
    suppression for the given rule. Records each applied suppression in the
    report so it appears in the rendered output (visible, not silent)."""
    kept = []
    for cs in call_sites:
        if hasattr(cs, "suppressed_rules") and rule_id in cs.suppressed_rules:
            report.suppressions_applied.append((rule_id, cs.file, cs.line))
        else:
            kept.append(cs)
    return kept


# ── Builder ─────────────────────────────────────────────────────────────────

def build_report(scan: ScanResult) -> AuditReport:
    rep = AuditReport(scan=scan)

    _check_network_egress(scan, rep)
    _check_code_execution(scan, rep)
    _check_filesystem(scan, rep)
    _check_env_vars(scan, rep)
    _check_stdio(scan, rep)
    _check_inbound_network(scan, rep)
    _check_url_safety(scan, rep)
    _check_dependencies(scan, rep)
    _check_string_content(scan, rep)
    _check_unsafe_deserialization(scan, rep)

    _compute_score(rep)
    return rep


# ── Per-dimension checks ────────────────────────────────────────────────────

def _check_network_egress(s: ScanResult, r: AuditReport) -> None:
    if not s.http_calls:
        r.capabilities_no.append("Makes no outbound HTTP requests")
        return

    # Hosts
    if s.hosts:
        host_list = ", ".join(sorted(s.hosts))
        r.capabilities_yes.append(f"Outbound HTTPS to: {host_list}")
        # Per the scoring methodology — anything beyond 1 host costs points
        # (an MCP wrapping a single API should hit ≤1 host)
        if len(s.hosts) > 1:
            extra = len(s.hosts) - 1
            r.findings.append(Finding(
                rule_id=RuleID.MULTIPLE_HOSTS,
                dimension="Network",
                severity="low" if extra <= 2 else "medium",
                title=f"{len(s.hosts)} distinct outbound hosts detected",
                detail=f"Single-purpose MCPs should hit ≤1 host. Detected: {host_list}",
                deduction=extra,
            ))
    else:
        # HTTP calls but no hosts could be resolved (no literal URL, no
        # env-default URL). Treat as medium-severity — reviewer should
        # trace the URL source manually.
        r.capabilities_yes.append("Makes outbound HTTP requests (host destination not literal in source)")
        r.findings.append(Finding(
            rule_id=RuleID.DYNAMIC_HTTP_DEST,
            dimension="Network",
            severity="medium",
            title="HTTP destination is dynamic (computed at runtime)",
            detail=(
                "URL construction uses variables/f-strings so the static analysis "
                "cannot enumerate which hosts this package contacts, AND no "
                "URL-shaped env-var default was found. Reviewer should trace "
                "the URL back to its source manually."
            ),
            deduction=1,
        ))

    # TLS posture
    tls_off = _not_suppressed(s.tls_disabled_calls, RuleID.TLS_DISABLED, r)
    if tls_off:
        sites = "; ".join(f"{c.file}:{c.line}" for c in tls_off)
        r.findings.append(Finding(
            rule_id=RuleID.TLS_DISABLED,
            dimension="Network",
            severity="high",
            title="TLS verification disabled (verify=False)",
            detail=f"Calls with TLS disabled: {sites}",
            deduction=2,
        ))
        r.capabilities_yes.append("TLS verification IS DISABLED on some calls (verify=False)")
    elif not s.tls_disabled_calls:
        r.capabilities_no.append("TLS verification on (no verify=False detected)")


def _check_code_execution(s: ScanResult, r: AuditReport) -> None:
    subp = _not_suppressed(s.subprocess_calls, RuleID.SUBPROCESS, r)
    if subp:
        any_shell = any("shell=True" in c.note for c in subp)
        sev: Severity = "high" if any_shell else "medium"
        deduct = 3 if any_shell else 2
        sites = "; ".join(f"{c.file}:{c.line} ({c.name})" for c in subp[:5])
        more = "" if len(subp) <= 5 else f" (+{len(subp) - 5} more)"
        r.findings.append(Finding(
            rule_id=RuleID.SUBPROCESS,
            dimension="Code execution",
            severity=sev,
            title=f"Subprocess / shell calls detected ({len(subp)})",
            detail=f"Call sites: {sites}{more}",
            deduction=deduct,
        ))
        r.capabilities_yes.append(f"Spawns subprocess / shell ({len(subp)} call sites)")
    elif not s.subprocess_calls:
        r.capabilities_no.append("No subprocess, shell, or os.system detected")

    dyn = _not_suppressed(s.dynamic_exec_calls, RuleID.DYNAMIC_EXEC, r)
    if dyn:
        sites = "; ".join(f"{c.file}:{c.line} ({c.name})" for c in dyn[:5])
        more = "" if len(dyn) <= 5 else f" (+{len(dyn) - 5} more)"
        r.findings.append(Finding(
            rule_id=RuleID.DYNAMIC_EXEC,
            dimension="Code execution",
            severity="high",
            title=f"Dynamic code execution ({len(dyn)}× eval/exec/compile/__import__)",
            detail=f"Call sites: {sites}{more}",
            deduction=3,
        ))
        r.capabilities_yes.append(f"Uses eval/exec/compile/__import__ ({len(dyn)} sites)")
    elif not s.dynamic_exec_calls:
        r.capabilities_no.append("No eval, exec, compile, or dynamic __import__ detected")


def _check_filesystem(s: ScanResult, r: AuditReport) -> None:
    fs_w = _not_suppressed(s.fs_write_calls, RuleID.FS_WRITE, r)
    if fs_w:
        sites = "; ".join(f"{c.file}:{c.line} ({c.name}{(' — ' + c.note) if c.note else ''})"
                          for c in fs_w[:5])
        more = "" if len(fs_w) <= 5 else f" (+{len(fs_w) - 5} more)"
        r.findings.append(Finding(
            rule_id=RuleID.FS_WRITE,
            dimension="Filesystem",
            severity="medium",
            title=f"Filesystem writes detected ({len(fs_w)})",
            detail=f"Sites: {sites}{more}",
            deduction=2,
        ))
        r.capabilities_yes.append(f"Writes to filesystem ({len(fs_w)} call sites)")
    elif not s.fs_write_calls:
        r.capabilities_no.append("No filesystem writes detected (no open(..., 'w'/'a'), no os.remove, no shutil writes, no Path.write_text)")

    if s.fs_read_calls:
        # Reads are info-only — most packages legitimately read config files
        r.capabilities_yes.append(f"Reads from filesystem ({len(s.fs_read_calls)} call sites)")
    else:
        r.capabilities_no.append("No filesystem reads detected")


def _check_env_vars(s: ScanResult, r: AuditReport) -> None:
    if not s.env_reads:
        r.capabilities_no.append("Reads no environment variables")
        return
    var_list = sorted(s.env_reads.keys())
    if "<unknown>" in var_list:
        var_list.remove("<unknown>")
        r.findings.append(Finding(
            rule_id=RuleID.UNKNOWN_ENV_KEY,
            dimension="Env vars",
            severity="low",
            title="Reads env var with non-literal name (computed key)",
            detail="At least one os.environ.get/getenv call uses a variable for the var name; reviewer should confirm what's being read",
            deduction=0,
        ))
    if var_list:
        r.capabilities_yes.append(f"Reads env vars: {', '.join(var_list)} ({len(var_list)} distinct)")

    # Suspicious env var names — credentials that suggest the package is
    # pulling AWS/GCP/secrets that don't belong to a focused MCP.
    suspicious = {
        "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "AWS_SESSION_TOKEN",
        "GOOGLE_APPLICATION_CREDENTIALS", "GCP_SERVICE_ACCOUNT_KEY",
        "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GITHUB_TOKEN",
        "SLACK_TOKEN", "STRIPE_API_KEY", "DATABASE_URL",
    }
    flagged = [v for v in var_list if v in suspicious]
    if flagged:
        r.findings.append(Finding(
            rule_id=RuleID.BROAD_CREDENTIAL_ENV,
            dimension="Env vars",
            severity="medium",
            title=f"Reads broad-credential env vars: {', '.join(flagged)}",
            detail=(
                "An MCP wrapping a single research API shouldn't need credentials "
                "this broad. Verify these reads are legitimate or have been "
                "intentionally over-scoped."
            ),
            deduction=1,
        ))


def _check_stdio(s: ScanResult, r: AuditReport) -> None:
    if s.stdin_calls:
        r.capabilities_yes.append(f"Reads from stdin ({len(s.stdin_calls)} sites — expected for stdio MCP)")
    if s.stdout_calls:
        r.capabilities_yes.append(f"Writes to stdout ({len(s.stdout_calls)} sites — expected for stdio MCP)")
    if s.stderr_calls:
        r.capabilities_yes.append(f"Writes to stderr ({len(s.stderr_calls)} sites — diagnostic logging, fine)")
    if not (s.stdin_calls or s.stdout_calls or s.stderr_calls):
        r.capabilities_no.append("No stdio I/O detected (unusual for an MCP server — verify entrypoint)")


def _check_inbound_network(s: ScanResult, r: AuditReport) -> None:
    inb = _not_suppressed(s.inbound_calls, RuleID.INBOUND_NETWORK, r)
    if inb:
        sites = "; ".join(f"{c.file}:{c.line} ({c.name})" for c in inb[:5])
        more = "" if len(inb) <= 5 else f" (+{len(inb) - 5} more)"
        r.findings.append(Finding(
            rule_id=RuleID.INBOUND_NETWORK,
            dimension="Inbound network",
            severity="medium",
            title=f"Inbound network listener detected ({len(inb)} sites)",
            detail=(
                f"MCP servers should be stdio-only — an inbound network listener is "
                f"unusual and worth verifying. Sites: {sites}{more}"
            ),
            deduction=2,
        ))
        r.capabilities_yes.append(f"Opens inbound network listener ({len(inb)} sites)")
    elif not s.inbound_calls:
        r.capabilities_no.append("No inbound network listener (stdio only)")


def _check_url_safety(s: ScanResult, r: AuditReport) -> None:
    if not s.url_construction_warnings:
        return
    sites = "; ".join(f"{c.file}:{c.line}" for c in s.url_construction_warnings[:5])
    more = "" if len(s.url_construction_warnings) <= 5 else f" (+{len(s.url_construction_warnings) - 5} more)"
    r.findings.append(Finding(
        rule_id=RuleID.URL_CONSTRUCTION,
        dimension="URL construction",
        severity="low",
        title=f"URL constructed via f-string or concatenation ({len(s.url_construction_warnings)} sites)",
        detail=(
            f"Reviewer should trace these back to verify any user-supplied data "
            f"is properly URL-encoded (typically via requests' params= kwarg, "
            f"not by inlining into the URL). Sites: {sites}{more}"
        ),
        deduction=1,
    ))


def _check_string_content(s: ScanResult, r: AuditReport) -> None:
    """Dimension 9 — flag zero-width unicode + prompt-injection patterns
    inside long string literals. Common targets are MCP tool descriptions,
    system prompts, or any string that ends up rendered as model context."""

    if s.zero_width_strings:
        bidi_count = sum(1 for c in s.zero_width_strings if "bidi-override" in c.note)
        sites = "; ".join(f"{c.file}:{c.line} ({c.note})" for c in s.zero_width_strings[:5])
        more = "" if len(s.zero_width_strings) <= 5 else f" (+{len(s.zero_width_strings) - 5} more)"
        # Bidi-override chars are higher severity — they can visually
        # reverse code, used in real CVEs (e.g., CVE-2021-42574 "Trojan
        # Source"). Plain zero-width chars are usually a hidden-content
        # attack vector but lower-severity than bidi inversion.
        sev: Severity = "high" if bidi_count > 0 else "high"
        deduct = 3 if bidi_count > 0 else 2
        r.findings.append(Finding(
            rule_id=RuleID.ZERO_WIDTH_UNICODE,
            dimension="String content",
            severity=sev,
            title=f"Zero-width / directional unicode in {len(s.zero_width_strings)} string literal(s)",
            detail=(
                f"These characters have no legitimate use in tool descriptions "
                f"or config strings — common vectors for hidden instructions or "
                f"Trojan Source-style code obfuscation. "
                f"Sites: {sites}{more}"
            ),
            deduction=deduct,
        ))

    if s.injection_pattern_strings:
        sites = "; ".join(f"{c.file}:{c.line}" for c in s.injection_pattern_strings[:3])
        more = "" if len(s.injection_pattern_strings) <= 3 else f" (+{len(s.injection_pattern_strings) - 3} more)"
        # Detail text deliberately avoids reproducing the regex-matchable
        # example phrases — otherwise Dimension 9 flags its own diagnostic
        # message when the audit tool is run on itself (the regex source
        # `_INJECTION_PATTERNS` list is in ast_scan.py and is the
        # canonical reference).
        r.findings.append(Finding(
            rule_id=RuleID.INJECTION_PATTERN,
            dimension="String content",
            severity="high",
            title=f"Prompt-injection pattern in {len(s.injection_pattern_strings)} string literal(s)",
            detail=(
                f"String literals contain phrases consistent with instruction-"
                f"override attempts. MCP tool descriptions become Claude's tool "
                f"context — text-injection here is a real vector. The pattern "
                f"set is defined in audit/ast_scan.py::_INJECTION_PATTERNS. "
                f"Reviewer should verify each match is legitimate (a docstring "
                f"that discusses the topic vs. an actual injection payload). "
                f"Sites: {sites}{more}"
            ),
            deduction=2,
        ))


def _check_unsafe_deserialization(s: ScanResult, r: AuditReport) -> None:
    """Dimension 10 — pickle.load / yaml.load (without SafeLoader) /
    marshal.loads / dill.loads / cloudpickle.loads / shelve.open.

    All of these execute arbitrary code when handed attacker-controlled
    bytes. Any MCP that round-trips data via these functions is a
    privilege-escalation hazard if the upstream source is ever
    compromised. yaml.load is the canonical example of "looks innocent,
    is actually ACE." We skip yaml.load when SafeLoader is explicitly
    passed."""
    deser = _not_suppressed(s.unsafe_deserialization_calls, RuleID.UNSAFE_DESERIALIZATION, r)
    if not deser:
        if not s.unsafe_deserialization_calls:
            r.capabilities_no.append(
                "No unsafe deserialization (no pickle.load, no yaml.load without "
                "SafeLoader, no marshal.loads, no dill/cloudpickle)"
            )
        return

    sites = "; ".join(f"{c.file}:{c.line} ({c.name})" for c in deser[:5])
    more = "" if len(deser) <= 5 else f" (+{len(deser) - 5} more)"
    r.findings.append(Finding(
        rule_id=RuleID.UNSAFE_DESERIALIZATION,
        dimension="Deserialization",
        severity="high",
        title=f"Unsafe deserialization sinks ({len(deser)})",
        detail=(
            "These functions execute arbitrary code when given attacker-"
            "controlled input. If the data ever crosses a trust boundary "
            "(network, IPC, untrusted file), this is remote code execution. "
            f"Sites: {sites}{more}"
        ),
        deduction=3,
    ))
    r.capabilities_yes.append(
        f"Unsafe deserialization ({len(deser)} call sites)"
    )


def _check_dependencies(s: ScanResult, r: AuditReport) -> None:
    if not s.dependencies:
        return
    # Loose / unpinned versions
    loose = []
    for d in s.dependencies:
        # very rough: anything without `==` is "loose"
        if "==" not in d:
            loose.append(d)
    if loose and len(loose) == len(s.dependencies):
        r.findings.append(Finding(
            rule_id=RuleID.LOOSE_DEP_PINS,
            dimension="Dependencies",
            severity="low",
            title=f"All {len(loose)} dep(s) use loose version pins",
            detail=(
                f"From {s.dep_source}: {', '.join(loose[:5])}"
                + ("..." if len(loose) > 5 else "")
                + ". For an audited release, consider exact pins (==) so a future "
                "transitive update can't change behavior under your release."
            ),
            deduction=0,
        ))


# ── Score computation ──────────────────────────────────────────────────────

def _compute_score(r: AuditReport) -> None:
    """Score starts at 10, deductions sum to floor of 0.

    Also populates `total_deduction` (uncapped) so CI consumers can
    distinguish "barely fails" (deduction = 11, score = 0) from
    "catastrophic" (deduction = 50, score = 0). Suggested by external
    auditor 2026-05-10."""
    r.score = 10
    r.total_deduction = 0
    explanations = []

    if not r.findings:
        explanations.append("Started at 10. No findings.")
    else:
        explanations.append("Started at 10.")
        for f in sorted(r.findings, key=_severity_rank, reverse=True):
            if f.deduction > 0:
                r.total_deduction += f.deduction
                r.score -= f.deduction
                explanations.append(
                    f"−{f.deduction} for [{f.severity}] [{f.rule_id}] {f.title}"
                )
        if r.score < 0:
            r.score = 0

    r.score_explanation = explanations


def _severity_rank(f: Finding) -> int:
    return {"high": 3, "medium": 2, "low": 1, "info": 0}.get(f.severity, 0)
