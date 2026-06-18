# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-FileCopyrightText: Portions Copyright (c) 2016 qntm (base65536, MIT)
# SPDX-FileCopyrightText: Portions Copyright (c) 2021 ferno (hexagram-encode, MIT)
# SPDX-License-Identifier: Apache-2.0

"""Encoding functions

Functions used to offer various encodings that are needed more than one place in garak
"""

import base64
import binascii
import random


def leetspeak(input: str, transmute_chance: float = 0.6) -> str:
    src_chars = "ieaost"
    dst_chars = "134057"
    processed = input.translate(
        str.maketrans(src_chars.lower() + src_chars.upper(), dst_chars + dst_chars)
    )
    # mix it up
    output = "".join(
        [processed[i] if random.random() > 0.5 else input[i] for i in range(len(input))]
    )
    return output


# ---------------------------------------------------------------------------
# Base65536 — a binary-to-text encoding that packs 2 bytes per character using
# "safe" Unicode code points. Used by probes.encoding to test whether a model
# will decode obscure encodings of an unsafe payload.
#
# Ported to Python from the reference implementation qntm/base65536, which is
# distributed under the MIT License:
#
#   Copyright (c) 2016 qntm (https://github.com/qntm/base65536)
#   Permission is hereby granted, free of charge, to any person obtaining a
#   copy of this software and associated documentation files, to deal in the
#   Software without restriction, including the rights to use, copy, modify,
#   merge, publish, distribute, sublicense, and/or sell copies of the Software.
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
# ---------------------------------------------------------------------------

_BASE65536_BITS_PER_CHAR = 16
_BASE65536_BITS_PER_BYTE = 8

# Compressed inclusive ranges of code points used by Base65536, taken verbatim
# from the qntm reference implementation. The first string holds the 256 blocks
# for full 16-bit values; the second holds the block for a trailing 8-bit value.
_BASE65536_PAIR_STRINGS = [
    "㐀䳿一黿ꄀꏿꔀꗿ𐘀𐛿𒀀𒋿𓀀𓏿𔐀𔗿𖠀𖧿𠀀𨗿",
    "ᔀᗿ",
]


def _build_base65536_tables():
    """Build the Base65536 encode/decode lookup tables from the compressed ranges."""
    encode = {}  # {num_z_bits: {z: char}}
    decode = {}  # {char: (num_z_bits, z)}
    for r, pair_string in enumerate(_BASE65536_PAIR_STRINGS):
        num_z_bits = _BASE65536_BITS_PER_CHAR - _BASE65536_BITS_PER_BYTE * r
        encode[num_z_bits] = {}
        code_points = [ord(c) for c in pair_string]
        z2 = 0
        for first, last in zip(code_points[0::2], code_points[1::2]):
            for code_point in range(first, last + 1):
                # Full 16-bit blocks flip the byte order (the encoding was
                # originally constructed taking the bytes in the wrong order);
                # 8-bit blocks do not.
                if num_z_bits == _BASE65536_BITS_PER_CHAR:
                    z = 256 * (z2 % 256) + (z2 >> 8)
                else:
                    z = z2
                encode[num_z_bits][z] = chr(code_point)
                decode[chr(code_point)] = (num_z_bits, z)
                z2 += 1
    return encode, decode


_BASE65536_ENCODE, _BASE65536_DECODE = _build_base65536_tables()


def base65536_encode(payload: bytes) -> str:
    """Encode bytes as a Base65536 string (2 bytes per character)."""
    out = []
    z = 0
    num_z_bits = 0
    for byte in payload:
        for j in range(_BASE65536_BITS_PER_BYTE - 1, -1, -1):
            z = (z << 1) + ((byte >> j) & 1)
            num_z_bits += 1
            if num_z_bits == _BASE65536_BITS_PER_CHAR:
                out.append(_BASE65536_ENCODE[num_z_bits][z])
                z = 0
                num_z_bits = 0
    if num_z_bits != 0:
        # A trailing byte leaves 8 bits; Base65536 needs no padding because 8
        # divides 16, so the remaining bits map straight onto an 8-bit block.
        out.append(_BASE65536_ENCODE[num_z_bits][z])
    return "".join(out)


def base65536_decode(text: str) -> bytes:
    """Decode a Base65536 string back to the original bytes."""
    out = bytearray()
    byte = 0
    num_byte_bits = 0
    for chr_ in text:
        if chr_ not in _BASE65536_DECODE:
            raise ValueError(f"Unrecognised Base65536 character: {chr_!r}")
        num_z_bits, z = _BASE65536_DECODE[chr_]
        for j in range(num_z_bits - 1, -1, -1):
            byte = (byte << 1) + ((z >> j) & 1)
            num_byte_bits += 1
            if num_byte_bits == _BASE65536_BITS_PER_BYTE:
                out.append(byte)
                byte = 0
                num_byte_bits = 0
    return bytes(out)


# ---------------------------------------------------------------------------
# Hexagram encoding — Base64 with each character (including the padding symbol)
# replaced by an I Ching hexagram, making the underlying bits visible as broken
# and unbroken lines. Used by probes.encoding.
#
# Ported to Python from the reference implementation ferno/hexagram-encode,
# which is distributed under the MIT License:
#
#   Copyright (c) 2021 ferno (https://github.com/ferno/hexagram-encode)
#   Permission is hereby granted, free of charge, to any person obtaining a
#   copy of this software and associated documentation files, to deal in the
#   Software without restriction, including the rights to use, copy, modify,
#   merge, publish, distribute, sublicense, and/or sell copies of the Software.
#   THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
# ---------------------------------------------------------------------------

# 64 Base64 characters in order; the 65th is the padding symbol. Mapped onto the
# 64 I Ching hexagrams (binary order, most significant bit at the top) plus the
# yin/yang symbol for padding, taken verbatim from the reference implementation.
_HEXAGRAM_BASE64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
_HEXAGRAM_GLYPHS = (
    "䷁䷗䷆䷒䷎䷣䷭䷊䷏䷲䷧䷵䷽䷶䷟䷡䷇䷂䷜䷻䷦䷾䷯䷄䷬䷐䷮䷹䷞䷰䷛䷪"
    "䷖䷚䷃䷨䷳䷕䷑䷙䷢䷔䷿䷥䷷䷝䷱䷍䷓䷩䷺䷼䷴䷤䷸䷈䷋䷘䷅䷉䷠䷌䷫䷀☯"
)
_B64_TO_HEXAGRAM = str.maketrans(_HEXAGRAM_BASE64, _HEXAGRAM_GLYPHS)
_HEXAGRAM_TO_B64 = str.maketrans(_HEXAGRAM_GLYPHS, _HEXAGRAM_BASE64)


def hexagram_encode(payload: bytes) -> str:
    """Encode bytes as a string of I Ching hexagrams (Base64 over the hexagrams)."""
    return base64.b64encode(payload).decode("ascii").translate(_B64_TO_HEXAGRAM)


def hexagram_decode(text: str) -> bytes:
    """Decode a hexagram-encoded string back to the original bytes."""
    try:
        return base64.b64decode(text.translate(_HEXAGRAM_TO_B64), validate=True)
    except binascii.Error as exc:
        raise ValueError(f"Invalid hexagram-encoded string: {exc}") from exc
