# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Read a JSON object from model output that strict ``json.loads`` rejects.

Models asked for a large JSON object often write one that is almost valid: an
unescaped quote inside a string, an invalid escape such as ``\\d``, a trailing
comma, a list closed with ``}``, a code-like expression such as ``"a" * 5000``
in place of a value, or output cut off at the token limit. Strict parsing then
discards the whole reply. :func:`repair_json_object` recovers what the model
meant, and keeps everything that was complete when output was cut off.

Use it only after strict parsing has failed, and only where a partial or
approximately repaired object is better than none.
"""

import json
import re

_WHITESPACE = " \t\r\n"
_LITERAL = re.compile(r"-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null")
_UNICODE_ESCAPE = re.compile(r"[0-9a-fA-F]{4}")
_ESCAPES = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "b": "\b",
    "f": "\f",
    "n": "\n",
    "r": "\r",
    "t": "\t",
}
_VALUE_START = '"{[-0123456789tfn'


class _Truncated(Exception):
    """The text ended inside a string."""


class _NotAValue(Exception):
    """No JSON value starts at the current position."""


class _RepairingParser:
    """Recursive-descent JSON parser that repairs common model mistakes.

    A quote inside a string is taken as the end of the string only when what
    follows it can continue the JSON (a ``,`` and another value, the enclosing
    bracket, or a ``:`` after a key); otherwise it is kept as text. A string
    that then runs into a raw newline is ended at the last such quote.
    Unparseable tokens between values are skipped, a bracket of the wrong kind
    still closes the open container, and a value cut off by the end of the text
    is dropped while the complete values before it are kept.
    """

    def __init__(self, text: str):
        self.text = text
        self.end = len(text)
        self.pos = 0

    def _skip_whitespace(self, pos: int) -> int:
        while pos < self.end and self.text[pos] in _WHITESPACE:
            pos += 1
        return pos

    def _peek(self) -> str:
        self.pos = self._skip_whitespace(self.pos)
        return self.text[self.pos] if self.pos < self.end else ""

    def _opens_container_after_colon(self, pos: int) -> bool:
        """Whether ``pos`` holds a ``:`` followed by ``[`` or ``{``."""
        if pos >= self.end or self.text[pos] != ":":
            return False
        after = self._skip_whitespace(pos + 1)
        return after < self.end and self.text[after] in "[{"

    def _skip_junk(self) -> None:
        """Skip a stray token up to the next ``,``, ``]`` or ``}``."""
        while self.pos < self.end and self.text[self.pos] not in ",]}":
            if self.text[self.pos] == '"':
                close = self.text.find('"', self.pos + 1)
                self.pos = self.end if close == -1 else close + 1
            else:
                self.pos += 1

    def _quote_ends_string(self, pos: int, closer: str, is_key: bool) -> bool:
        """Whether a quote ends its string, judged by the text from ``pos`` on."""
        pos = self._skip_whitespace(pos)
        if pos >= self.end:
            return True
        following = self.text[pos]
        if is_key:
            return following == ":"
        if following == closer:
            return True
        if closer == "]" and self._opens_container_after_colon(pos):
            return True  # a key inside a list: the list was never closed
        if following == ",":
            pos = self._skip_whitespace(pos + 1)
            if pos >= self.end:
                return True
            allowed = '"}' if closer == "}" else _VALUE_START + "]"
            return self.text[pos] in allowed
        return False

    def _string(self, closer: str, is_key: bool) -> str:
        text, pos = self.text, self.pos + 1
        chars: list = []
        # (length of ``chars``, text position) of each quote kept as text
        kept_quotes: list = []
        while pos < self.end:
            char = text[pos]
            if char == "\\" and pos + 1 < self.end:
                escaped = text[pos + 1]
                if escaped in _ESCAPES:
                    chars.append(_ESCAPES[escaped])
                    pos += 2
                elif escaped == "u" and _UNICODE_ESCAPE.fullmatch(
                    text, pos + 2, pos + 6
                ):
                    chars.append(chr(int(text[pos + 2 : pos + 6], 16)))
                    pos += 6
                else:  # an invalid escape such as \d: keep it as written
                    chars.append(escaped if escaped == "'" else "\\" + escaped)
                    pos += 2
                continue
            if char == '"':
                if self._quote_ends_string(pos + 1, closer, is_key):
                    self.pos = pos + 1
                    return "".join(chars)
                kept_quotes.append((len(chars), pos))
                chars.append(char)
                pos += 1
                continue
            if char == "\n" and kept_quotes:
                # the string ran on past its real end: the last kept quote closed it
                length, quote_pos = kept_quotes[-1]
                self.pos = quote_pos + 1
                return "".join(chars[:length])
            chars.append(char)
            pos += 1
        self.pos = self.end
        raise _Truncated

    def _backslash_quoted(self) -> str:
        """A string delimited with escaped quotes, as in ``\\"text\\",``."""
        search_from = self.pos + 2
        while True:
            close = self.text.find('\\"', search_from)
            if close == -1:
                self.pos = self.end
                raise _Truncated
            after = self._skip_whitespace(close + 2)
            if after >= self.end or self.text[after] in ",]}":
                value = self.text[self.pos + 2 : close].replace('\\"', '"')
                self.pos = close + 2
                return value
            search_from = close + 2

    def _value(self, closer: str):
        char = self._peek()
        if char == "{":
            return self._container("}")
        if char == "[":
            return self._container("]")
        if char == '"':
            return self._string(closer, is_key=False)
        if self.text.startswith('\\"', self.pos):
            return self._backslash_quoted()
        literal = _LITERAL.match(self.text, self.pos)
        if literal:
            self.pos = literal.end()
            return json.loads(literal.group())
        raise _NotAValue

    def _container(self, closer: str):
        self.pos += 1
        is_object = closer == "}"
        container: dict | list = {} if is_object else []
        while True:
            char = self._peek()
            if not char:
                return container  # text ended: keep what is complete
            if char in "]}":
                self.pos += 1  # a bracket of the wrong kind still closes
                return container
            if char == ",":
                self.pos += 1
                continue
            try:
                if is_object:
                    if char != '"':
                        self._skip_junk()
                        continue
                    key = self._string(closer, is_key=True)
                    if self._peek() != ":":
                        self._skip_junk()
                        continue
                    self.pos += 1
                    if not self._peek():
                        return container
                    value = self._value(closer)
                    if key in container:
                        raise json.JSONDecodeError(
                            f"duplicate JSON field: {key}", self.text, self.pos
                        )
                    container[key] = value
                else:
                    start = self.pos
                    item = self._value(closer)
                    if isinstance(item, str) and self._opens_container_after_colon(
                        self._skip_whitespace(self.pos)
                    ):
                        # a key inside a list: hand it back to the enclosing object
                        self.pos = start
                        return container
                    container.append(item)
            except _Truncated:
                return container  # drop the value the end of the text cut off
            except _NotAValue:
                self._skip_junk()
                continue
            # anything but a delimiter here is junk; a quote is a missing comma
            if self._peek() not in (",", "]", "}", "", '"'):
                self._skip_junk()


def repair_json_object(text: str) -> dict:
    """Parse the first JSON object in ``text``, repairing common model mistakes.

    Valid JSON parses exactly as ``json.loads`` would. Objects that repeat a
    field name are rejected rather than resolved, since either value may be the
    one the model meant.

    :param text: model output containing a JSON object, possibly malformed or
        cut off
    :return: the recovered object; when the text was cut off, the values that
        were complete before the cut
    :raises json.JSONDecodeError: when ``text`` has no ``{``, nests too deeply,
        or an object repeats a field name
    """
    if not isinstance(text, str):
        raise json.JSONDecodeError("Model output must be text", "", 0)
    start = text.find("{")
    if start == -1:
        raise json.JSONDecodeError("No JSON object found", text, 0)
    parser = _RepairingParser(text)
    parser.pos = start
    try:
        return parser._container("}")
    except RecursionError as error:
        raise json.JSONDecodeError("JSON nesting is too deep", text, start) from error
