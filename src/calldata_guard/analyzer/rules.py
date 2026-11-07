"""Security rules engine for EVM calldata & offline transaction validation.
Detects:
1. Unlimited / excessive ERC-20 token approvals (type(uint256).max / drained allowances).
2. Dangerous EIP-2612 Permit authorizations granting remote spend permissions.
3. ERC-721 setApprovalForAll vulnerabilities.
4. Value discrepancies (sending ETH alongside contract calls).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

# Maximum uint256 threshold: 2**256 - 1
MAX_UINT256 = (1 << 256) - 1

# Dangerous allowance threshold: e.g. 10 billion tokens (10**28 with 18 decimals)
EXCESSIVE_APPROVAL_THRESHOLD = 10**32


@dataclass
class RiskFinding:
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "INFO"
    rule: str
    description: str
    parameter: str
    value: Any


def analyze_transaction(
    tx_meta: dict[str, Any],
    decoded_call: dict[str, Any],
) -> list[RiskFinding]:
    """
    Evaluates decoded transaction and calldata against deterministic security invariants.
    """
    findings: list[RiskFinding] = []

    func_name = decoded_call.get("name", "")
    params = decoded_call.get("params", {})
    value = tx_meta.get("value", 0)

    # 1. Unrecognized Calldata / Blind Execution
    if decoded_call.get("unrecognized", False):
        findings.append(
            RiskFinding(
                severity="HIGH",
                rule="UNKNOWN_FUNCTION_SELECTOR",
                description="Transaction executes an unverified 4-byte selector. Hardware wallet cannot decode intent.",
                parameter="selector",
                value=decoded_call.get("selector"),
            )
        )

    # 2. Unlimited / Excessive ERC-20 Approvals
    if func_name == "approve":
        amount = params.get("amount", 0)
        spender = params.get("spender", "unknown")

        if amount == MAX_UINT256:
            findings.append(
                RiskFinding(
                    severity="CRITICAL",
                    rule="UNLIMITED_TOKEN_APPROVAL",
                    description=f"Transaction grants infinite (2^256 - 1) token allowance to spender {spender}. The spender can drain your entire token balance at any time.",
                    parameter="amount",
                    value="type(uint256).max",
                )
            )
        elif isinstance(amount, int) and amount >= EXCESSIVE_APPROVAL_THRESHOLD:
            findings.append(
                RiskFinding(
                    severity="HIGH",
                    rule="EXCESSIVE_TOKEN_APPROVAL",
                    description=f"Transaction approves an excessively large token amount ({amount}) to {spender}.",
                    parameter="amount",
                    value=str(amount),
                )
            )

    # 3. NFT Blanket Approvals (setApprovalForAll)
    if func_name == "setApprovalForAll":
        operator = params.get("operator", "unknown")
        approved = params.get("approved", False)

        if approved:
            findings.append(
                RiskFinding(
                    severity="CRITICAL",
                    rule="NFT_BLANKET_APPROVAL",
                    description=f"Transaction sets approval for ALL NFTs in this contract to operator {operator}. Operator can transfer all your collection tokens.",
                    parameter="approved",
                    value="true",
                )
            )

    # 4. Gasless Permit Signatures (EIP-2612)
    if func_name == "permit":
        value_param = params.get("value", 0)
        spender = params.get("spender", "unknown")
        deadline = params.get("deadline", 0)

        if value_param == MAX_UINT256 or (isinstance(value_param, int) and value_param >= EXCESSIVE_APPROVAL_THRESHOLD):
            findings.append(
                RiskFinding(
                    severity="CRITICAL",
                    rule="UNLIMITED_PERMIT_ALLOWANCE",
                    description=f"EIP-2612 Permit grants unlimited token spending rights to {spender} without requiring a separate on-chain approval transaction.",
                    parameter="value",
                    value="type(uint256).max" if value_param == MAX_UINT256 else str(value_param),
                )
            )

    # 5. ETH Value sent alongside standard Token calls
    if func_name in ("transfer", "approve", "transferFrom") and value > 0:
        findings.append(
            RiskFinding(
                severity="HIGH",
                rule="VALUE_MISMATCH_ON_ERC20",
                description=f"Transaction invokes standard ERC-20 {func_name} but simultaneously transmits {value} Wei native ETH.",
                parameter="value",
                value=f"{value} Wei",
            )
        )

    # 6. Batched Multicall Inspection
    if func_name == "multicall":
        findings.append(
            RiskFinding(
                severity="MEDIUM",
                rule="NESTED_MULTICALL_EXECUTION",
                description="Transaction packages multiple nested sub-calls. Ensure all sub-calls are explicitly verified.",
                parameter="data",
                value=params.get("data"),
            )
        )

    return findings
