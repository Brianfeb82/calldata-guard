"""CLI entry point for calldata-guard.
Audits raw transaction hex, raw calldata hex, or piped standard input offline.
POSIX Exit Codes:
  0: Clean / Passed audit
  1: High or Critical risk violation found (e.g. unlimited approval / drainer trap)
  2: Malformed or unparseable payload
"""

from __future__ import annotations

import argparse
import sys

from .analyzer.eip712 import audit_eip712_message, parse_eip712_json
from .analyzer.rules import analyze_transaction
from .decoder.abi import decode_abi_calldata
from .decoder.rlp import RLPDecodeError, parse_raw_transaction
from .reporter.terminal import render_report


def clean_hex_string(raw: str) -> bytes:
    cleaned = raw.strip()
    if cleaned.startswith(("0x", "0X")):
        cleaned = cleaned[2:]
    # Remove whitespace or newlines if any
    cleaned = "".join(cleaned.split())
    if len(cleaned) % 2 != 0:
        cleaned = "0" + cleaned
    return bytes.fromhex(cleaned)


def audit_payload(payload_bytes: bytes) -> int:
    try:
        # 1. Try to parse as a serialized transaction (RLP envelope)
        tx_meta = parse_raw_transaction(payload_bytes)
        calldata = tx_meta.get("data", b"")
    except (RLPDecodeError, ValueError):
        # 2. If not a full transaction, treat input as raw direct calldata
        tx_meta = {
            "type": "raw_calldata",
            "to": None,
            "value": 0,
            "data": payload_bytes,
        }
        calldata = payload_bytes

    # 3. Decode ABI Calldata
    decoded_call = decode_abi_calldata(calldata)

    # 4. Run Risk Rules
    findings = analyze_transaction(tx_meta, decoded_call)

    # 5. Render Report
    render_report(tx_meta, decoded_call, findings)

    # Determine exit code
    has_crit_or_high = any(f.severity in ("CRITICAL", "HIGH") for f in findings)
    if has_crit_or_high:
        return 1
    return 0


def audit_eip712_text(json_str: str) -> int:
    payload = parse_eip712_json(json_str)
    findings = audit_eip712_message(payload)

    tx_meta = {
        "type": "eip712",
        "domain": payload.domain,
    }
    decoded_call = {
        "name": payload.primary_type,
        "standard": "EIP-712",
        "params": payload.message,
    }

    render_report(tx_meta, decoded_call, findings)

    has_crit_or_high = any(f.severity in ("CRITICAL", "HIGH") for f in findings)
    if has_crit_or_high:
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="calldata-guard",
        description="Zero-dependency offline EVM calldata & transaction pre-flight auditor.",
    )
    parser.add_argument(
        "payload",
        nargs="?",
        help="Raw hex string or EIP-712 JSON string. Reads stdin if omitted.",
    )

    args = parser.parse_args(argv)

    raw_input = args.payload
    if not raw_input:
        if not sys.stdin.isatty():
            raw_input = sys.stdin.read().strip()
        else:
            parser.print_help()
            return 2

    if not raw_input:
        sys.stderr.write("Error: empty transaction payload\n")
        return 2

    # Check if input is JSON (EIP-712 structured data)
    stripped = raw_input.strip()
    if (stripped.startswith("{") and stripped.endswith("}")) or ("primaryType" in stripped and "domain" in stripped):
        try:
            return audit_eip712_text(stripped)
        except ValueError as e:
            sys.stderr.write(f"Error parsing EIP-712 JSON: {e}\n")
            return 2

    try:
        payload_bytes = clean_hex_string(raw_input)
    except ValueError as e:
        sys.stderr.write(f"Error: invalid hex format: {e}\n")
        return 2

    return audit_payload(payload_bytes)


if __name__ == "__main__":
    sys.exit(main())
