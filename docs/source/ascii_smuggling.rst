Ascii Smuggling
===============

Garak features probes that use `ASCII smuggling <https://embracethered.com/blog/posts/2024/hiding-and-finding-text-with-unicode-tags/>`_.
ASCII smuggling is a technique that abuses the fact that LLM tokenizers will handle non-printable or zero-width characters like unicode tags and variant selectors.
This makes it useful for bypassing LLM guardrails, which often are not trained on these evasions, and for circumventing human-in-the-loop controls, as the characters will not be visible on the screen when viewed by users.
Some LLMs will happily decode the relevant text and handle it gracefully. Others will not. This is expected.

Tag Smuggling
-------------
Unicode Tags are used as part of the support for emojis, and the tags must be appended to an emoji, per `the Unicode spec <https://unicode.org/reports/tr51/>`_.
Although tags are intended to be used to select a particular variant of an emoji, such as the Flag emoji, there is no limit to the number of tags that can be appended.
This allows us to append arbitrary ASCII text to an emoji, hidden in the tags.

.. code-block:: python

    def tag_char_smuggling(payload: str, desired_emoji: str = "😈"):
    """
    Use Unicode tags to smuggle ASCII characters.
    For tag char smuggling to work, it must be appended to an emoji, per the Unicode spec.
    https://unicode.org/reports/tr51/

    Args:
        payload (str): The payload we wish to hide.
        desired_emoji (str): Must be an emoji per unicode spec. Defaults to 😈

    Returns:
        desired_emoji + encoded payload (str): Payload encoded in unicode tags attached to the emoji.
    """

    encoded_payload = "".join(chr(0xE0000 + ord(ch)) for ch in payload)
    return desired_emoji + encoded_payload

Variant Smuggling
-----------------
Variation or `Variant Selectors <https://en.wikipedia.org/wiki/Variation_Selectors_Supplement>`_ is a Unicode block that allows for the specification of a glyph variant for the preceding character.
Since there are 256 of them, this means we can also convert arbitrary bytes -- like ASCII text -- to a Variant Selector.
Like tags, the `Unicode spec <https://www.unicode.org/versions/Unicode16.0.0/>`_ has no limit on the number of selectors that can be concatenated together.
Unlike tags, these do not need to be appended to an emoji and can simply exist wherever we please.

.. code-block:: python

    def variant_smuggling(payload: str):
        """
        Use Unicode variant selectors and supplement to smuggle ASCII characters.
        Unlike tag chars, variant selectors do not need to be appended to an emoji and there is no limit to the number of
        variant selectors that can be concatenated together, according to the unicode spec.
        https://www.unicode.org/versions/Unicode16.0.0/

        Args:
            payload (str): Payload to be encoded

        Returns:
            encoded_payload (str): The payload encoded in variant selectors.
        """
        encoded_payload = "".join(chr(0xE0100 + ord(ch)) for ch in payload)
        return encoded_payload

Sneaky Bits
-----------
Sneaky bits, a technique described by Johann Rehberger in `a blog post <https://embracethered.com/blog/posts/2025/sneaky-bits-and-ascii-smuggler/>`_ encodes ASCII characters to binary, then uses the invisible times (``U+2062``) and invisible plus (``U+2064``) Unicode characters to encode 0 and 1, relying on the ability of the LLM to interpret the binary back into text.
In our variation, we replace literal space characters with the zero-width space (``U+200B``), since it seems to perform a bit better than encoding the ASCII space to binary.

.. code-block:: python

    def sneaky_bits_smuggling(payload: str):
    """
    Use Sneaky Bits as described by Johann Rehberger in
    https://embracethered.com/blog/posts/2025/sneaky-bits-and-ascii-smuggler/ to encode
    ASCII characters using invisible times (U+2062) and invisible plus (U+2064) to encode 0 and 1.

    We replace spaces with zero-width space (U+200B).

    Args:
        payload (str): Payload to be encoded

    Returns:
        encoded_payload (str): Payload encoded as binary, joined by zero-width spaces.
    """
    char_map = {"0": chr(0x2062), "1": chr(0x2064)}
    encoded_payload = list()
    for ch in payload:
        if ord(ch) == 0x20:
            encoded_payload.append(chr(0x200B))
        else:
            for rep in bin(ord(ch)).removeprefix("0b"):
                encoded_payload.append(char_map[rep])
    return "".join(encoded_payload)
