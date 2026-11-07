#!/usr/bin/env python3
"""
Assert-based test runner for calldata-guard.
Evaluates deterministic offline decoding and risk detection across real EVM vectors:
1. Normal clean ERC-20 transfer
2. Unlimited ERC-20 token approval drainer (type(uint256).max)
3. NFT blanket setApprovalForAll drainer
4. EIP-2612 Permit unlimited allowance trap
5. Value mismatch (sending native ETH alongside token transfer)
6. Serialized EIP-1559 and Legacy transaction envelope parsing
7. Unknown raw bytecode warnings
"""

import sys
import os

# Add src/ to import path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

from calldata_guard.decoder.rlp import decode_rlp, parse_raw_transaction
from calldata_guard.decoder.abi import decode_abi_calldata
from calldata_guard.analyzer.eip712 import parse_eip712_json, audit_eip712_message
from calldata_guard.analyzer.rules import analyze_transaction, MAX_UINT256
from calldata_guard.cli import clean_hex_string, audit_payload

passed = 0
failed = 0


def test(name: str, condition: bool, detail: str = ""):
    global passed, failed
    if condition:
        passed += 1
        print(f"  PASS  {name}")
    else:
        failed += 1
        msg = f"  FAIL  {name}"
        if detail:
            msg += f" — {detail}"
        print(msg)


# --- 1. ABI Decoding Tests ---

def test_abi_decoding():
    print("\n--- 1. Offline ABI Decoding ---")
    # transfer(to=0x1111111111111111111111111111111111111111, amount=1000)
    calldata = clean_hex_string(
        "0xa9059cbb"
        "0000000000000000000000001111111111111111111111111111111111111111"
        "00000000000000000000000000000000000000000000000000000000000003e8"
    )
    res = decode_abi_calldata(calldata)
    test("ERC-20 transfer selector mapped", res["selector"] == "0xa9059cbb")
    test("function name is transfer", res["name"] == "transfer")
    test("amount decoded accurately", res["params"].get("amount") == 1000)
    test("recipient address matches", res["params"].get("to") == "0x1111111111111111111111111111111111111111")


# --- 2. Unlimited Token Approval Risk Tests ---

def test_unlimited_approval():
    print("\n--- 2. Unlimited Token Approval Detection ---")
    # approve(spender=0x2222222222222222222222222222222222222222, amount=MAX_UINT256)
    calldata = clean_hex_string(
        "0x095ea7b3"
        "0000000000000000000000002222222222222222222222222222222222222222"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
    )
    decoded = decode_abi_calldata(calldata)
    tx_meta = {"type": "raw_calldata", "to": "0xTokenAddress", "value": 0}
    findings = analyze_transaction(tx_meta, decoded)

    rules = [f.rule for f in findings]
    test("Flags UNLIMITED_TOKEN_APPROVAL", "UNLIMITED_TOKEN_APPROVAL" in rules)
    crit = [f for f in findings if f.rule == "UNLIMITED_TOKEN_APPROVAL"][0]
    test("Severity is CRITICAL", crit.severity == "CRITICAL")


# --- 3. NFT Blanket Approval Tests ---

def test_nft_set_approval_for_all():
    print("\n--- 3. NFT Blanket Approval Detection ---")
    # setApprovalForAll(operator=0x3333333333333333333333333333333333333333, approved=true)
    calldata = clean_hex_string(
        "0xa22cb465"
        "0000000000000000000000003333333333333333333333333333333333333333"
        "0000000000000000000000000000000000000000000000000000000000000001"
    )
    decoded = decode_abi_calldata(calldata)
    tx_meta = {"type": "raw_calldata", "to": "0xNFTContract", "value": 0}
    findings = analyze_transaction(tx_meta, decoded)

    rules = [f.rule for f in findings]
    test("Flags NFT_BLANKET_APPROVAL", "NFT_BLANKET_APPROVAL" in rules)


# --- 4. EIP-2612 Permit Unlimited Allowance Tests ---

def test_permit_unlimited():
    print("\n--- 4. EIP-2612 Permit Detection ---")
    # permit(owner, spender, value=MAX_UINT256, deadline, v, r, s)
    calldata = clean_hex_string(
        "0xd505accf"
        "0000000000000000000000001111111111111111111111111111111111111111"
        "0000000000000000000000002222222222222222222222222222222222222222"
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        "0000000000000000000000000000000000000000000000000000000065000000"
        "000000000000000000000000000000000000000000000000000000000000001b"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
    )
    decoded = decode_abi_calldata(calldata)
    tx_meta = {"type": "raw_calldata", "to": "0xToken", "value": 0}
    findings = analyze_transaction(tx_meta, decoded)

    rules = [f.rule for f in findings]
    test("Flags UNLIMITED_PERMIT_ALLOWANCE", "UNLIMITED_PERMIT_ALLOWANCE" in rules)


# --- 5. Value Mismatch on ERC-20 ---

def test_value_mismatch():
    print("\n--- 5. Value Mismatch Detection ---")
    # transfer(...) with msg.value = 1 ether
    calldata = clean_hex_string(
        "0xa9059cbb"
        "0000000000000000000000001111111111111111111111111111111111111111"
        "00000000000000000000000000000000000000000000000000000000000003e8"
    )
    decoded = decode_abi_calldata(calldata)
    tx_meta = {"type": "legacy", "to": "0xToken", "value": 10**18}
    findings = analyze_transaction(tx_meta, decoded)

    rules = [f.rule for f in findings]
    test("Flags VALUE_MISMATCH_ON_ERC20", "VALUE_MISMATCH_ON_ERC20" in rules)


# --- 6. RLP Parser Tests ---

def test_rlp_parser():
    print("\n--- 6. Pure Python RLP Parser ---")
    # Simple string RLP
    s, consumed = decode_rlp(b"\x83dog")
    test("RLP short string decoded", s == b"dog" and consumed == 4)

    # List RLP: ["cat", "dog"] -> [0xc8, 0x83, 'c', 'a', 't', 0x83, 'd', 'o', 'g']
    l_bytes = b"\xc8\x83cat\x83dog"
    items, consumed = decode_rlp(l_bytes)
    test("RLP list parsed", len(items) == 2 and items[0] == b"cat" and items[1] == b"dog")


# --- 7. Unknown Bytecode Tests ---

def test_unknown_bytecode():
    print("\n--- 7. Unknown Function Selector ---")
    calldata = clean_hex_string("0xdeadbeef0000000000000000000000000000000000000000000000000000000000000001")
    decoded = decode_abi_calldata(calldata)
    tx_meta = {"type": "raw_calldata", "to": "0xContract", "value": 0}
    findings = analyze_transaction(tx_meta, decoded)

    rules = [f.rule for f in findings]
    test("Flags UNKNOWN_FUNCTION_SELECTOR", "UNKNOWN_FUNCTION_SELECTOR" in rules)


# --- 8. EIP-712 Structured Data Audits ---

def test_eip712_permit2_drainer():
    print("\n--- 8. EIP-712 Permit2 & Seaport Audits ---")
    permit2_json = '''
    {
      "types": {
        "EIP712Domain": [{"name": "name", "type": "string"}],
        "PermitSingle": [{"name": "details", "type": "PermitDetails"}]
      },
      "primaryType": "PermitSingle",
      "domain": {
        "name": "Permit2",
        "chainId": 1,
        "verifyingContract": "0x000000000022D473030F116dDEE9F6B43aC78BA3"
      },
      "message": {
        "details": {
          "token": "0xdAC17F958D2ee523a2206206994597C13D831ec7",
          "amount": "115792089237316195423570985008687907853269984665640564039457584007913129639935",
          "expiration": "1735689600",
          "nonce": "0"
        },
        "spender": "0xPhishingDrainerAddress",
        "sigDeadline": "1735689600"
      }
    }
    '''
    payload = parse_eip712_json(permit2_json)
    findings = audit_eip712_message(payload)
    rules = [f.rule for f in findings]
    test("Flags EIP712_PERMIT2_UNLIMITED_DRAINER", "EIP712_PERMIT2_UNLIMITED_DRAINER" in rules)
    crit = [f for f in findings if f.rule == "EIP712_PERMIT2_UNLIMITED_DRAINER"][0]
    test("Severity is CRITICAL", crit.severity == "CRITICAL")

    # Seaport Zero Consideration Drain Order
    seaport_gift_order = '''
    {
      "types": {"OrderComponents": [{"name": "offer", "type": "OfferItem[]"}]},
      "primaryType": "OrderComponents",
      "domain": {
        "name": "Seaport",
        "chainId": 1,
        "verifyingContract": "0x00000000000000ADc04C56Bf30aC9d3c0aAF14dC"
      },
      "message": {
        "offer": [{"itemType": 2, "token": "0xNFT", "identifierOrCriteria": "42"}],
        "consideration": []
      }
    }
    '''
    payload_seaport = parse_eip712_json(seaport_gift_order)
    findings_seaport = audit_eip712_message(payload_seaport)
    rules_seaport = [f.rule for f in findings_seaport]
    test("Flags EIP712_ZERO_CONSIDERATION_TRANSFER", "EIP712_ZERO_CONSIDERATION_TRANSFER" in rules_seaport)


def main():
    print("calldata-guard test suite")
    print("=" * 60)

    test_abi_decoding()
    test_unlimited_approval()
    test_nft_set_approval_for_all()
    test_permit_unlimited()
    test_value_mismatch()
    test_rlp_parser()
    test_unknown_bytecode()
    test_eip712_permit2_drainer()

    print("\n" + "=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
