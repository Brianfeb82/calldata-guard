"""RLP (Recursive Length Prefix) decoder in pure Python standard library.
Supports legacy Ethereum transactions, EIP-2718 typed transaction envelopes (EIP-1559, EIP-2930).
Zero dependencies.
"""

from __future__ import annotations


class RLPDecodeError(ValueError):
    pass


def decode_rlp(data: bytes) -> tuple[bytes | list, int]:
    """
    Decodes an RLP item from bytes.
    Returns (decoded_item, bytes_consumed).
    """
    if not data:
        raise RLPDecodeError("Empty input for RLP decoding")

    prefix = data[0]

    # 1. Single byte in [0x00, 0x7f]
    if prefix <= 0x7F:
        return bytes([prefix]), 1

    # 2. Short string: 0-55 bytes long (prefix 0x80 - 0xb7)
    if prefix <= 0xB7:
        length = prefix - 0x80
        total_len = 1 + length
        if len(data) < total_len:
            raise RLPDecodeError("Unexpected EOF in RLP short string")
        return data[1:total_len], total_len

    # 3. Long string: >55 bytes long (prefix 0xb8 - 0xbf)
    if prefix <= 0xBF:
        len_of_len = prefix - 0xB7
        if len(data) < 1 + len_of_len:
            raise RLPDecodeError("Unexpected EOF in RLP long string length")
        length = int.from_bytes(data[1 : 1 + len_of_len], "big")
        total_len = 1 + len_of_len + length
        if len(data) < total_len:
            raise RLPDecodeError("Unexpected EOF in RLP long string payload")
        return data[1 + len_of_len : total_len], total_len

    # 4. Short list: 0-55 bytes payload (prefix 0xc0 - 0xf7)
    if prefix <= 0xF7:
        length = prefix - 0xC0
        total_len = 1 + length
        if len(data) < total_len:
            raise RLPDecodeError("Unexpected EOF in RLP short list")
        sub_data = data[1:total_len]
        items = []
        offset = 0
        while offset < len(sub_data):
            item, consumed = decode_rlp(sub_data[offset:])
            items.append(item)
            offset += consumed
        return items, total_len

    # 5. Long list: >55 bytes payload (prefix 0xf8 - 0xff)
    len_of_len = prefix - 0xF7
    if len(data) < 1 + len_of_len:
        raise RLPDecodeError("Unexpected EOF in RLP long list length")
    length = int.from_bytes(data[1 : 1 + len_of_len], "big")
    total_len = 1 + len_of_len + length
    if len(data) < total_len:
        raise RLPDecodeError("Unexpected EOF in RLP long list payload")
    sub_data = data[1 + len_of_len : total_len]
    items = []
    offset = 0
    while offset < len(sub_data):
        item, consumed = decode_rlp(sub_data[offset:])
        items.append(item)
        offset += consumed
    return items, total_len


def parse_raw_transaction(raw_bytes: bytes) -> dict:
    """
    Parses raw signed or unsigned transaction bytes into structured fields:
    {
        'type': 'legacy' | 'eip2930' | 'eip1559',
        'to': '0x...' | None,
        'value': int,
        'data': bytes,
        'nonce': int,
        ...
    }
    """
    if not raw_bytes:
        raise RLPDecodeError("Empty transaction bytes")

    first_byte = raw_bytes[0]

    # EIP-2718 typed transaction envelope
    if first_byte in (0x01, 0x02):
        tx_type = "eip2930" if first_byte == 0x01 else "eip1559"
        rlp_payload = raw_bytes[1:]
        decoded, _ = decode_rlp(rlp_payload)
        if not isinstance(decoded, list):
            raise RLPDecodeError("Envelope payload must be an RLP list")

        if tx_type == "eip1559":
            # EIP-1559 structure:
            # [chainId, nonce, maxPriorityFeePerGas, maxFeePerGas, gasLimit, to, value, data, accessList, v, r, s]
            if len(decoded) < 8:
                raise RLPDecodeError(f"Insufficient fields for EIP-1559 transaction: {len(decoded)}")
            to_raw = decoded[5]
            val_raw = decoded[6]
            data_raw = decoded[7]
            return {
                "type": "eip1559",
                "chain_id": int.from_bytes(decoded[0], "big") if decoded[0] else 0,
                "nonce": int.from_bytes(decoded[1], "big") if decoded[1] else 0,
                "to": f"0x{to_raw.hex()}" if to_raw else None,
                "value": int.from_bytes(val_raw, "big") if val_raw else 0,
                "data": data_raw,
            }
        else:
            # EIP-2930 structure:
            # [chainId, nonce, gasPrice, gasLimit, to, value, data, accessList, v, r, s]
            if len(decoded) < 7:
                raise RLPDecodeError(f"Insufficient fields for EIP-2930 transaction: {len(decoded)}")
            to_raw = decoded[4]
            val_raw = decoded[5]
            data_raw = decoded[6]
            return {
                "type": "eip2930",
                "chain_id": int.from_bytes(decoded[0], "big") if decoded[0] else 0,
                "nonce": int.from_bytes(decoded[1], "big") if decoded[1] else 0,
                "to": f"0x{to_raw.hex()}" if to_raw else None,
                "value": int.from_bytes(val_raw, "big") if val_raw else 0,
                "data": data_raw,
            }

    # Legacy transaction: raw RLP list [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
    decoded, _ = decode_rlp(raw_bytes)
    if not isinstance(decoded, list) or len(decoded) < 6:
        raise RLPDecodeError("Malformed legacy transaction list")

    to_raw = decoded[3]
    val_raw = decoded[4]
    data_raw = decoded[5]

    return {
        "type": "legacy",
        "nonce": int.from_bytes(decoded[0], "big") if decoded[0] else 0,
        "to": f"0x{to_raw.hex()}" if to_raw else None,
        "value": int.from_bytes(val_raw, "big") if val_raw else 0,
        "data": data_raw,
    }
