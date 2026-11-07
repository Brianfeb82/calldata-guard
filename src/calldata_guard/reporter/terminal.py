"""Terminal visual reporter for calldata-guard.
Renders human-readable decoded transaction intent with risk scoring.
Respects NO_COLOR. Zero Unicode emojis.
"""

from __future__ import annotations

import os
import sys
from typing import Any

from ..analyzer.rules import RiskFinding

_RESET = "\033[0m"
_BOLD = "\033[1m"
_RED = "\033[31m"
_YELLOW = "\033[33m"
_CYAN = "\033[36m"
_GRAY = "\033[90m"


def _use_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if not hasattr(sys.stdout, "isatty") or not sys.stdout.isatty():
        return False
    return True


def render_report(
    tx_meta: dict[str, Any],
    decoded_call: dict[str, Any],
    findings: list[RiskFinding],
    stream=sys.stdout,
) -> None:
    colorize = _use_color()

    def c(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if colorize else text

    print("-" * 65, file=stream)
    print(c(_BOLD, "calldata-guard: Offline Transaction Pre-Flight Audit"), file=stream)
    print("-" * 65, file=stream)

    # Transaction Meta
    tx_type = tx_meta.get("type", "direct_calldata")
    to_addr = tx_meta.get("to") or "Contract Deployment / Direct"
    val = tx_meta.get("value", 0)

    print(f"Transaction Envelope: {tx_type.upper()}", file=stream)
    print(f"Target Contract (To):  {to_addr}", file=stream)
    print(f"Native Value (ETH):    {val} Wei", file=stream)
    print(file=stream)

    # Decoded Calldata Intent
    func_name = decoded_call.get("name", "Unknown")
    selector = decoded_call.get("selector", "0x")
    standard = decoded_call.get("standard", "Custom")

    print(c(_BOLD, f"Decoded Function Call: {func_name}() [{standard}]"), file=stream)
    print(f"Selector:              {selector}", file=stream)

    params = decoded_call.get("params", {})
    if params:
        print("Parameters:", file=stream)
        for k, v in params.items():
            print(f"  - {k:<12} = {v}", file=stream)
    else:
        print("Parameters:            None / Raw Bytecode", file=stream)

    print(file=stream)

    # Risk Assessment Findings
    if findings:
        crit_count = sum(1 for f in findings if f.severity == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity == "HIGH")

        status_text = "FAILED: DANGEROUS TRANSACTION DETECTED"
        status_color = _RED if crit_count > 0 else _YELLOW
        print(c(_BOLD + status_color, status_text), file=stream)
        print("-" * 65, file=stream)

        for f in findings:
            tag_color = _RED if f.severity == "CRITICAL" else (_YELLOW if f.severity == "HIGH" else _CYAN)
            tag = c(_BOLD + tag_color, f"[{f.severity}]")
            print(f"{tag} {f.rule}", file=stream)
            print(f"    Impact:    {f.description}", file=stream)
            print(f"    Trigger:   {f.parameter} = {f.value}", file=stream)
    else:
        status_text = "PASSED: NO HIGH-RISK SIGNATURES DETECTED"
        print(c(_BOLD + _CYAN, status_text), file=stream)

    print("-" * 65, file=stream)
