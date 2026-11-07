# calldata-guard

Zero-dependency offline EVM calldata & transaction pre-flight auditor.

> Blind-signing raw hexadecimal calldata causes nine-figure treasury and wallet drains. calldata-guard decodes, humanizes, and audits raw EVM payloads offline before hardware wallets or multisig participants sign them.

---

## The Real-World Problem

Hardware wallet screens and cold-signing terminals frequently display unverified hexadecimal blobs:
```text
Data: 0x095ea7b3000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
```

Because signers cannot decode the binary ABI parameters offline, they approve transactions blindly:
- **Unlimited Approvals:** Phishing sites trick users into calling `approve(spender, 2^256 - 1)`, granting malicious contracts permanent rights to sweep all their USDT/USDC tokens.
- **Gasless Permit Hijacks (EIP-2612):** Signers authorize off-chain permit signatures without realizing they are bypassing standard token balance checks.
- **NFT Blanket Approvals:** Contracts invoke `setApprovalForAll(operator, true)`, allowing an external address to drain entire NFT collections.
- **Value Mismatches:** Attackers trick users into sending native ETH to an address while claiming to execute an ERC-20 transfer.

`calldata-guard` acts as an offline pre-flight security gate: it unpacks raw RLP transaction envelopes, parses function selectors and parameters, evaluates deterministic risk invariants, and blocks dangerous payloads with POSIX exit codes.

---

## Features

- **100% Offline & Zero Dependencies:** Written exclusively in Python 3.12+ standard library (`struct`, `argparse`, `dataclasses`). Zero `pip` packages, zero external RPC calls, and zero risk of supply-chain key compromises.
- **Full Envelope Support:** Decodes both raw calldata payloads and serialized transaction envelopes (Legacy, EIP-1559, and EIP-2930) via a custom RLP parser.
- **Offline ABI Registry:** Bundles selectors for top DeFi and token standards (`ERC-20`, `ERC-721`, `EIP-2612 Permit`, `Uniswap Router`, `Gnosis Safe`, `Multicall`).
- **Deterministic Risk Rules:**
  - `[CRITICAL] UNLIMITED_TOKEN_APPROVAL`: Flags approvals where amount equals `type(uint256).max` or exceeds safety thresholds.
  - `[CRITICAL] NFT_BLANKET_APPROVAL`: Flags active `setApprovalForAll` operations.
  - `[CRITICAL] UNLIMITED_PERMIT_ALLOWANCE`: Detects hidden permit draining authorizations.
  - `[HIGH] VALUE_MISMATCH_ON_ERC20`: Detects native ETH transmitted alongside token contract calls.
  - `[HIGH] UNKNOWN_FUNCTION_SELECTOR`: Warns on unverified bytecode selectors.

---

## Installation

```bash
git clone https://github.com/Brianfeb82/calldata-guard.git
cd calldata-guard
```

No package manager or virtual environment is required.

---

## Usage

### 1. Audit Raw Calldata
```bash
python3 -m calldata_guard.cli 0x095ea7b30000000000000000000000002222222222222222222222222222222222222222ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
```

Output:
```text
-----------------------------------------------------------------
calldata-guard: Offline Transaction Pre-Flight Audit
-----------------------------------------------------------------
Transaction Envelope: RAW_CALLDATA
Target Contract (To):  Contract Deployment / Direct
Native Value (ETH):    0 Wei

Decoded Function Call: approve() [ERC-20]
Selector:              0x095ea7b3
Parameters:
  - spender      = 0x2222222222222222222222222222222222222222
  - amount       = 115792089237316195423570985008687907853269984665640564039457584007913129639935

FAILED: DANGEROUS TRANSACTION DETECTED
-----------------------------------------------------------------
[CRITICAL] UNLIMITED_TOKEN_APPROVAL
    Impact:    Transaction grants infinite (2^256 - 1) token allowance to spender 0x2222222222222222222222222222222222222222. The spender can drain your entire token balance at any time.
    Trigger:   amount = type(uint256).max
-----------------------------------------------------------------
```

### 2. Standard Input Pipe (Air-Gapped Workflows)
```bash
echo "0xa9059cbb000000000000000000000000111111111111111111111111111111111111111100000000000000000000000000000000000000000000000000000000000003e8" | python3 -m calldata_guard.cli
```

### 3. Audit EIP-712 Typed Signatures (Uniswap Permit2 & Seaport Orders)
```bash
python3 -m calldata_guard.cli '{
  "types": {
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
      "amount": "115792089237316195423570985008687907853269984665640564039457584007913129639935"
    },
    "spender": "0xPhishingDrainerAddress"
  }
}'
```

Output:
```text
-----------------------------------------------------------------
calldata-guard: Offline Transaction Pre-Flight Audit
-----------------------------------------------------------------
Signature Standard:    EIP-712 Typed Structured Message
Domain Name:           Permit2
Verifying Contract:    0x000000000022D473030F116dDEE9F6B43aC78BA3
Chain ID:              1

Primary Type:          PermitSingle
Message Fields:
  - details          = {'token': '0xdAC17F958D2ee523a2206206994597C13D831ec7', 'amount': '115792089237316195423570985008687907853269984665640564039457584007913129639935'}
  - spender          = 0xPhishingDrainerAddress

FAILED: DANGEROUS TRANSACTION DETECTED
-----------------------------------------------------------------
[CRITICAL] EIP712_PERMIT2_UNLIMITED_DRAINER
    Impact:    EIP-712 Permit2 authorizes infinite (2^256 - 1) token allowance to spender 0xPhishingDrainerAddress on token 0xdAC17F958D2ee523a2206206994597C13D831ec7. Off-chain signature can be replayed to empty balance.
    Trigger:   details.amount = type(uint256).max
-----------------------------------------------------------------
```

### 4. POSIX Exit Codes

- `0`: Clean transaction (e.g. standard fixed token transfer).
- `1`: High or Critical risk violation found (unlimited approvals, permit traps).
- `2`: Invalid hex or malformed payload.

Environment Variables:
- `NO_COLOR`: Suppresses ANSI color output.

---

## Verification

Run the test suite:
```bash
python3 test_runner.py
```
Evaluates 12 deterministic test cases covering ABI parameter decoding, RLP list parsing, and vulnerability detection.

---

## License

MIT License. Copyright (c) 2026 Brian Febrian.
