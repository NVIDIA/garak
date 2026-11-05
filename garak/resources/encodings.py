# SPDX-FileCopyrightText: Portions Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Encoding functions

Functions used to offer various encodings that are needed more than one place in garak
"""

import base64
import binascii
import random
from dataclasses import dataclass
from typing import Callable, List, Tuple


@dataclass(frozen=True)
class EncodingStrategy:
    """A named encoding technique: ordered encoder callables, applied in order.

    Pure data: ``encode`` returns one output per encoder (duplicates kept).
    """

    name: str
    encoders: Tuple[Callable, ...]
    use_bytes: bool = True

    def encode(self, text: str, **encoder_kwargs) -> List[str]:
        """Return one encoded string per encoder, in declaration order.

        Keyword arguments are forwarded to each encoder, letting a probe tune a
        strategy per call without the strategy holding any state.
        """
        encoded_texts: List[str] = []
        for encoder in self.encoders:
            if self.use_bytes:
                encoded_text = encoder(bytes(text, "utf-8"), **encoder_kwargs)
            else:
                encoded_text = encoder(text, **encoder_kwargs)
            if isinstance(encoded_text, bytes):
                encoded_text = encoded_text.decode()
            encoded_texts.append(encoded_text)
        return encoded_texts


BASE16 = EncodingStrategy(name="BASE16", encoders=(base64.b16encode,))
BASE64 = EncodingStrategy(
    name="BASE64",
    encoders=(
        base64.b64encode,
        base64.urlsafe_b64encode,
        base64.standard_b64encode,
        binascii.b2a_base64,
    ),
)

BASE32 = EncodingStrategy(name="BASE32", encoders=(base64.b32encode,))
ASCII85 = EncodingStrategy(
    name="ASCII85", encoders=(base64.a85encode, base64.b85encode)
)
HEX = EncodingStrategy(name="hex", encoders=(binascii.b2a_hex,))


ROT13TRANS = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)


def rot13(text: bytes) -> bytes:
    return bytes(text.decode().translate(ROT13TRANS), "utf-8")


def atbash(text: bytes) -> bytes:
    out = []
    for ch in text.decode():
        if "a" <= ch <= "z":
            out.append(chr(ord("z") - (ord(ch) - ord("a"))))
        elif "A" <= ch <= "Z":
            out.append(chr(ord("Z") - (ord(ch) - ord("A"))))
        else:
            out.append(ch)
    return "".join(out).encode("utf-8")


def uuencode(payload: bytes) -> str:
    chunks = []
    for i in range(0, len(payload), 45):
        chunks.append(binascii.b2a_uu(payload[i : i + 45]))
    return "".join(map(bytes.decode, chunks))


# Custom-function encoders: ROT13 and Atbash pass digits and punctuation through
# in clear; UU introduces line breaks in its output.
ROT13 = EncodingStrategy(name="ROT13", encoders=(rot13,))
ATBASH = EncodingStrategy(name="Atbash", encoders=(atbash,))
UU = EncodingStrategy(name="UUencode", encoders=(uuencode,))


def leetspeak(input: str, transmute_chance: float = 0.5) -> str:
    src_chars = "ieaost"
    dst_chars = "134057"
    processed = input.translate(
        str.maketrans(src_chars.lower() + src_chars.upper(), dst_chars + dst_chars)
    )
    # mix it up
    output = "".join(
        [
            processed[i] if random.random() < transmute_chance else input[i]
            for i in range(len(input))
        ]
    )
    return output


def braille(text: bytes) -> bytes:
    # fmt: off
    characterUnicodes = {
        "a": "\u2801",
        "b": "\u2803",
        "k": "\u2805",
        "l": "\u2807",
        "c": "\u2809",
        "i": "\u280A",
        "f": "\u280B",
        "m": "\u280D",
        "s": "\u280E",
        "p": "\u280F",
        "e": "\u2811",
        "h": "\u2813",
        "o": "\u2815",
        "r": "\u2817",
        "d": "\u2819",
        "j": "\u281A",
        "g": "\u281B",
        "n": "\u281D",
        "t": "\u281E",
        "q": "\u281F",
        "u": "\u2825",
        "v": "\u2827",
        "x": "\u282D",
        "z": "\u2835",
        "w": "\u283A",
        "y": "\u283D",
        "num": "\u283C",
        "caps": "\u2820",
        ".": "\u2832",
        "'": "\u2804",
        ",": "\u2802",
        "-": "\u2824",
        "/": "\u280C",
        "!": "\u2816",
        "?": "\u2826",
        "$": "\u2832",
        ":": "\u2812",
        ";": "\u2830",
        "(": "\u2836",
        ")": "\u2836",
        "1": "\u2801",
        "2": "\u2803",
        "3": "\u2809",
        "4": "\u2819",
        "5": "\u2811",
        "6": "\u280B",
        "7": "\u281B",
        "8": "\u2813",
        "9": "\u280A",
        "0": "\u281A",
        " ": " ",
    }
    # fmt: on
    numberPunctuations = [".", ",", "-", "/", "$"]
    escapeCharacters = ["\n", "\r", "\t"]

    output = ""

    for char in text.decode():
        is_number = False
        if char in escapeCharacters:
            output += char
        elif char.isupper():
            if char.lower() in characterUnicodes:
                output += characterUnicodes["caps"]
                output += characterUnicodes[char.lower()]
        elif char in characterUnicodes:
            if char.isdigit():
                if not is_number:
                    is_number = True
                    output += characterUnicodes["num"]
            output += characterUnicodes[char]
        if is_number and char not in numberPunctuations:
            is_number = False

    return bytes(output, "utf-8")


def morse(text: bytes) -> bytes:
    morsemap = {
        "A": ".-",
        "B": "-...",
        "C": "-.-.",
        "D": "-..",
        "E": ".",
        "F": "..-.",
        "G": "--.",
        "H": "....",
        "I": "..",
        "J": ".---",
        "K": "-.-",
        "L": ".-..",
        "M": "--",
        "N": "-.",
        "O": "---",
        "P": ".--.",
        "Q": "--.-",
        "R": ".-.",
        "S": "...",
        "T": "-",
        "U": "..-",
        "V": "...-",
        "W": ".--",
        "X": "-..-",
        "Y": "-.--",
        "Z": "--..",
        "1": ".----",
        "2": "..---",
        "3": "...--",
        "4": "....-",
        "5": ".....",
        "6": "-....",
        "7": "--...",
        "8": "---..",
        "9": "----.",
        "0": "-----",
        " ": "/",
        "\n": "/",
        "\r": "/",
        "\t": "/",
    }

    output = []
    for char in text.decode().upper():
        if char in morsemap:
            output.append(morsemap[char])
    return bytes(" ".join(output), "utf-8")


def nato(text: bytes) -> bytes:
    nato_map = {
        "A": "Alfa",
        "B": "Bravo",
        "C": "Charlie",
        "D": "Delta",
        "E": "Echo",
        "F": "Foxtrot",
        "G": "Golf",
        "H": "Hotel",
        "I": "India",
        "J": "Juliett",
        "K": "Kilo",
        "L": "Lima",
        "M": "Mike",
        "N": "November",
        "O": "Oscar",
        "P": "Papa",
        "Q": "Quebec",
        "R": "Romeo",
        "S": "Sierra",
        "T": "Tango",
        "U": "Uniform",
        "V": "Victor",
        "W": "Whiskey",
        "X": "Xray",
        "Y": "Yankee",
        "Z": "Zulu",
    }

    output = []
    for char in text.decode().upper():
        if char in nato_map:
            output.append(nato_map[char])
    return bytes(" ".join(output), "utf-8")


def leet_bytes(payload: bytes, transmute_chance: float = 0.5) -> bytes:
    return bytes(
        leetspeak(payload.decode(), transmute_chance=transmute_chance), "utf-8"
    )


def base2048_encode(payload: bytes) -> str:
    import base2048

    return base2048.encode(payload)


def ecoji_encode(payload: bytes) -> str:
    import io

    import ecoji

    reader = io.BytesIO(payload)
    writer = io.StringIO()
    ecoji.encode(reader, writer)
    return writer.getvalue()


def zalgo(payload: bytes) -> bytes:
    from zalgolib.zalgolib import enzalgofy

    # default intensity of 50 explodes prompt length
    zalged = enzalgofy(text=payload.decode(), intensity=5)
    return bytes(zalged, "utf-8")


QP = EncodingStrategy(name="Quoted-Printable", encoders=(binascii.b2a_qp,))
BRAILLE = EncodingStrategy(name="Braille", encoders=(braille,))
MORSE = EncodingStrategy(name="Morse", encoders=(morse,))
NATO = EncodingStrategy(name="Nato", encoders=(nato,))
BASE2048 = EncodingStrategy(name="BASE2048", encoders=(base2048_encode,))
ECOJI = EncodingStrategy(name="Ecoji", encoders=(ecoji_encode,))
LEET = EncodingStrategy(name="Leetspeak", encoders=(leet_bytes,))
ZALGO = EncodingStrategy(name="Zalgo", encoders=(zalgo,))
