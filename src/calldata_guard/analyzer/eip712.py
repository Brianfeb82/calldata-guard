"""EIP-712 structured data parser & signature auditor.
Decodes typed messages (Uniswap Permit2, OpenSea Seaport, Blur orders, ERC-2612 typed data).
Detects off-chain signature traps without network access.
Zero dependencies.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from ..analyzer.rules import RiskFinding, MAX_UINT256, EXCESSIVE_APPROVAL_THRESHOLD


@dataclass
class EIP712Payload:
    domain: dict[str, Any]
    primary_type: str
    message: dict[str, Any]
    types: dict[str, list[dict[str, str]]]


def parse_eip712_json(raw_json_str: str) -> EIP712Payload:
    """Parses standard EIP-712 JSON string."""
    try:
        data = json.loads(raw_json_str)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON for EIP-712 payload: {e}") from e

    if not isinstance(data, dict):
        raise ValueError("EIP-712 payload must be a JSON object")

    domain = data.get("domain", {})
    message = data.get("message", {})
    primary_type = data.get("primaryType") or ""
    types = data.get("types", {})

    # Auto-detect primaryType if omitted
    if not primary_type:
        candidate_types = [t for t in types.keys() if t != "EIP712Domain"]
        primary_type = candidate_types[0] if candidate_types else "Unknown"

    return EIP712Payload(
        domain=domain,
        primary_type=primary_type,
        message=message,
        types=types,
    )


def audit_eip712_message(payload: EIP712Payload) -> list[RiskFinding]:
    """Audits EIP-712 typed signature payload against drainer and excessive permission rules."""
    findings: list[RiskFinding] = []

    p_type = payload.primary_type.lower()
    msg = payload.message
    domain = payload.domain

    # 1. Uniswap Permit2 / Token Permit Audits
    # Handles: PermitSingle, PermitBatch, PermitTransferFrom, Permit
    if "permit" in p_type:
        # PermitSingle: { details: { token, amount, expiration, nonce }, spender, sigDeadline }
        details = msg.get("details", {})
        if isinstance(details, dict):
            amount = details.get("amount")
            spender = msg.get("spender") or details.get("spender")
            token = details.get("token")
        else:
            amount = msg.get("amount") or msg.get("value")
            spender = msg.get("spender")
            token = msg.get("token")

        if amount is not None:
            try:
                num_amt = int(amount) if not isinstance(amount, int) else amount
            except (ValueError, TypeError):
                num_amt = None

            if num_amt == MAX_UINT256:
                findings.append(
                    RiskFinding(
                        severity="CRITICAL",
                        rule="EIP712_PERMIT2_UNLIMITED_DRAINER",
                        description=f"EIP-712 Permit2 authorizes infinite (2^256 - 1) token allowance to spender {spender} on token {token}. Off-chain signature can be replayed to empty balance.",
                        parameter="details.amount",
                        value="type(uint256).max",
                    )
                )
            elif num_amt is not None and num_amt >= EXCESSIVE_APPROVAL_THRESHOLD:
                findings.append(
                    RiskFinding(
                        severity="HIGH",
                        rule="EIP712_PERMIT2_EXCESSIVE_ALLOWANCE",
                        description=f"EIP-712 Permit authorizes high allowance ({num_amt}) to {spender}.",
                        parameter="amount",
                        value=str(num_amt),
                    )
                )

    # 2. Marketplace Zero-Price Sell / Gift Orders (OpenSea Seaport / LooksRare)
    # Attack vector: Tricking users into signing an order offering an NFT for 0 consideration (free transfer)
    if any(k in p_type for k in ("order", "offer", "listing")):
        consideration = msg.get("consideration")
        offer = msg.get("offer")

        # If offering items but consideration is empty / zero
        if isinstance(offer, list) and len(offer) > 0:
            if consideration is None or (isinstance(consideration, list) and len(consideration) == 0):
                findings.append(
                    RiskFinding(
                        severity="CRITICAL",
                        rule="EIP712_ZERO_CONSIDERATION_TRANSFER",
                        description="Marketplace order offers assets with 0 consideration (free gift/drain order). Signer receives nothing in exchange.",
                        parameter="consideration",
                        value="[]",
                    )
                )

    # 3. Target Domain / Chain Verification
    chain_id = domain.get("chainId")
    verifying_contract = domain.get("verifyingContract")

    if not verifying_contract or verifying_contract == "0x0000000000000000000000000000000000000000":
        findings.append(
            RiskFinding(
                severity="HIGH",
                rule="EIP712_MISSING_VERIFYING_CONTRACT",
                description="EIP-712 domain lacks a verifyingContract address. Signature could be phished across unrelated protocols.",
                parameter="domain.verifyingContract",
                value=str(verifying_contract),
            )
        )

    return findings
