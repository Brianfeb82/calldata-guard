"""Standard 4-byte selector registry and EVM ABI parameter unpacker.
Offline directory of critical ERC-20, ERC-721, Uniswap, Gnosis Safe, and Permit interfaces.
Zero dependencies.
"""

from __future__ import annotations

import struct
from typing import Any

# Top critical function signatures mapped by 4-byte selector hex
SIGNATURE_REGISTRY: dict[str, dict[str, Any]] = {
    # ERC-20 / ERC-721 / ERC-1155
    "a9059cbb": {
        "name": "transfer",
        "inputs": [("to", "address"), ("amount", "uint256")],
        "standard": "ERC-20",
    },
    "095ea7b3": {
        "name": "approve",
        "inputs": [("spender", "address"), ("amount", "uint256")],
        "standard": "ERC-20",
    },
    "23b87266": {
        "name": "transferFrom",
        "inputs": [("from", "address"), ("to", "address"), ("amount", "uint256")],
        "standard": "ERC-20 / ERC-721",
    },
    "42842e0e": {
        "name": "safeTransferFrom",
        "inputs": [("from", "address"), ("to", "address"), ("tokenId", "uint256")],
        "standard": "ERC-721",
    },
    "a22cb465": {
        "name": "setApprovalForAll",
        "inputs": [("operator", "address"), ("approved", "bool")],
        "standard": "ERC-721 / ERC-1155",
    },
    # EIP-2612 Permit
    "d505accf": {
        "name": "permit",
        "inputs": [
            ("owner", "address"),
            ("spender", "address"),
            ("value", "uint256"),
            ("deadline", "uint256"),
            ("v", "uint8"),
            ("r", "bytes32"),
            ("s", "bytes32"),
        ],
        "standard": "EIP-2612",
    },
    # Uniswap V2 / V3 / Routers
    "38ed1739": {
        "name": "swapExactTokensForTokens",
        "inputs": [
            ("amountIn", "uint256"),
            ("amountOutMin", "uint256"),
            ("path", "address[]"),
            ("to", "address"),
            ("deadline", "uint256"),
        ],
        "standard": "UniswapV2Router",
    },
    "7ff36ab5": {
        "name": "swapExactETHForTokens",
        "inputs": [
            ("amountOutMin", "uint256"),
            ("path", "address[]"),
            ("to", "address"),
            ("deadline", "uint256"),
        ],
        "standard": "UniswapV2Router",
    },
    "ac9650d8": {
        "name": "multicall",
        "inputs": [("data", "bytes[]")],
        "standard": "Multicall / UniswapV3",
    },
    # Gnosis Safe / Governance
    "6a761202": {
        "name": "execTransaction",
        "inputs": [
            ("to", "address"),
            ("value", "uint256"),
            ("data", "bytes"),
            ("operation", "uint8"),
            ("safeTxGas", "uint256"),
            ("baseGas", "uint256"),
            ("gasPrice", "uint256"),
            ("gasToken", "address"),
            ("refundReceiver", "address"),
            ("signatures", "bytes"),
        ],
        "standard": "GnosisSafe",
    },
}


def decode_abi_calldata(calldata: bytes) -> dict[str, Any]:
    """
    Decodes raw calldata using offline selector directory.
    Extracts function name, types, and parameter values.
    """
    if len(calldata) < 4:
        return {
            "selector": "0x",
            "name": "raw_eth_transfer" if len(calldata) == 0 else "unknown_short_payload",
            "params": {},
            "raw_hex": calldata.hex(),
        }

    selector = calldata[:4].hex().lower()
    payload = calldata[4:]

    if selector not in SIGNATURE_REGISTRY:
        return {
            "selector": f"0x{selector}",
            "name": f"unknown_function_0x{selector}",
            "params": {},
            "raw_hex": calldata.hex(),
            "unrecognized": True,
        }

    spec = SIGNATURE_REGISTRY[selector]
    decoded_params = {}

    # Basic 32-byte word parsing for static types
    try:
        inputs = spec["inputs"]
        word_offset = 0

        for name, type_name in inputs:
            if type_name == "address":
                if word_offset + 32 <= len(payload):
                    word = payload[word_offset : word_offset + 32]
                    addr = f"0x{word[12:].hex()}"
                    decoded_params[name] = addr
                    word_offset += 32
            elif type_name.startswith("uint"):
                if word_offset + 32 <= len(payload):
                    word = payload[word_offset : word_offset + 32]
                    val = int.from_bytes(word, "big")
                    decoded_params[name] = val
                    word_offset += 32
            elif type_name == "bool":
                if word_offset + 32 <= len(payload):
                    word = payload[word_offset : word_offset + 32]
                    decoded_params[name] = bool(int.from_bytes(word, "big"))
                    word_offset += 32
            elif type_name == "bytes32":
                if word_offset + 32 <= len(payload):
                    decoded_params[name] = f"0x{payload[word_offset : word_offset + 32].hex()}"
                    word_offset += 32
            elif type_name == "bytes[]":
                # Dynamic array of bytes (e.g. multicall)
                # First word is offset to array
                if word_offset + 32 <= len(payload):
                    arr_offset = int.from_bytes(payload[word_offset : word_offset + 32], "big")
                    if arr_offset + 32 <= len(payload):
                        arr_len = int.from_bytes(payload[arr_offset : arr_offset + 32], "big")
                        decoded_params[name] = f"[{arr_len} sub-calls encoded]"
                    else:
                        decoded_params[name] = "[dynamic bytes array]"
                    word_offset += 32
            else:
                decoded_params[name] = "<dynamic_type>"
                word_offset += 32
    except Exception as e:
        decoded_params["_decode_error"] = str(e)

    return {
        "selector": f"0x{selector}",
        "name": spec["name"],
        "standard": spec.get("standard", "Custom"),
        "params": decoded_params,
        "raw_hex": calldata.hex(),
        "unrecognized": False,
    }
