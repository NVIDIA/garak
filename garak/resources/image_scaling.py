# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Image scaling attack generation.

Generates adversarial images that look innocent at full resolution but reveal
hidden text instructions after the AI backend downscales them using bilinear,
bicubic, or nearest-neighbour interpolation.

The core embedding algorithms are vendored from Trail of Bits' anamorpher:
    https://github.com/trailofbits/anamorpher (Apache-2.0)
"""

import hashlib
import logging
from pathlib import Path

import numpy as np
from PIL import Image, ImageDraw, ImageFont

from garak import _config
from garak.data import path as data_path
from garak.resources.anamorpher import (
    embed_bicubic,
    embed_bilinear,
    embed_nn,
    lin2srgb,
    srgb2lin,
)

logger = logging.getLogger(__name__)

DOWNSCALE_FACTOR = 4

_DECOY_DIR = data_path / "image_scaling" / "decoy_images"
_CACHE_DIR = _config.transient.cache_dir / "data" / "image_scaling"

DECOY_IMAGES = {
    "cat": "3200_decoy_cat.png",
    "boat": "4368_boat_decoy.png",
    "teapot": "4368_decoy_teapot.png",
}

GENERATION_PARAMS = {
    "bicubic": {
        "lam": 0.25,
        "gamma_target": 1.0,
        "dark_frac": 0.3,
    },
    "bilinear": {
        "lam": 1.0,
        "gamma_target": 0.9,
        "dark_frac": 0.3,
    },
    "nearest": {
        "lam": 0.25,
        "gamma_target": 1.0,
        "offset": 2,
    },
}

_DEFAULT_FONT_SIZE = 32
_TEXT_BG_COLOR = "#333333"
_TEXT_FG_COLOR = "#00b002"
_TEXT_MARGIN = 10

_FONT_SEARCH_PATHS = [
    "/System/Library/Fonts/Arial.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    "C:\\Windows\\Fonts\\arial.ttf",
]

_EMBED_FNS = {
    "bicubic": embed_bicubic,
    "bilinear": embed_bilinear,
    "nearest": embed_nn,
}

# ---------------------------------------------------------------------------
# Text rendering
# ---------------------------------------------------------------------------


def _load_font(size):
    for path in _FONT_SEARCH_PATHS:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def _wrap_text(text, font, draw, max_width):
    words = text.split()
    lines = []
    current_line = []

    for word in words:
        candidate = " ".join(current_line + [word])
        bbox = draw.textbbox((0, 0), candidate, font=font)
        if (bbox[2] - bbox[0]) <= max_width:
            current_line.append(word)
        else:
            if current_line:
                lines.append(" ".join(current_line))
            current_line = [word]

    if current_line:
        lines.append(" ".join(current_line))
    return lines


def render_text_target(text, size):
    """Render payload text as a square image array suitable for embedding.

    Returns an (size, size, 3) float32 array in sRGB [0..255] space.
    """
    image = Image.new("RGB", (size, size), color=_TEXT_BG_COLOR)
    draw = ImageDraw.Draw(image)
    font = _load_font(_DEFAULT_FONT_SIZE)

    text_area_width = size - 2 * _TEXT_MARGIN
    wrapped_lines = _wrap_text(text, font, draw, text_area_width)

    bbox_ay = draw.textbbox((0, 0), "Ay", font=font)
    line_height = bbox_ay[3] - bbox_ay[1]
    y = _TEXT_MARGIN

    for line in wrapped_lines:
        if y + line_height > size - _TEXT_MARGIN:
            break
        draw.text((_TEXT_MARGIN, y), line, font=font, fill=_TEXT_FG_COLOR)
        y += line_height

    return np.array(image, dtype=np.float32)


# ---------------------------------------------------------------------------
# Top-level generation API
# ---------------------------------------------------------------------------


def _cache_key(algo, decoy_key, text):
    """Compute a deterministic cache filename from generation parameters."""
    raw = f"{algo}:{decoy_key}:{text}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]
    return f"{algo}_{decoy_key}_{digest}.png"


def _load_decoy(decoy_key):
    """Load a decoy image from the shipped data directory."""
    if decoy_key not in DECOY_IMAGES:
        raise ValueError(
            f"Unknown decoy key: {decoy_key!r}. Available: {list(DECOY_IMAGES)}"
        )
    filename = DECOY_IMAGES[decoy_key]
    decoy_path = Path(str(_DECOY_DIR)) / filename
    if not decoy_path.exists():
        raise FileNotFoundError(
            f"Decoy image not found: {decoy_path}. "
            "Ensure garak/data/image_scaling/decoy_images/ contains the seed images."
        )
    with Image.open(decoy_path) as img:
        return np.asarray(img.convert("RGB"), dtype=np.float32)


def generate_adversarial_image(algo, text, decoy_key):
    """Generate an adversarial image and return its cached file path.

    If the image has already been generated (cache hit), returns the existing
    path without regenerating.

    Args:
        algo: Interpolation algorithm — "bicubic", "bilinear", or "nearest".
        text: The hidden payload text to embed.
        decoy_key: Key into DECOY_IMAGES — "cat", "boat", or "teapot".

    Returns:
        Path to the generated PNG image in the garak cache directory.
    """
    if algo not in _EMBED_FNS:
        raise ValueError(f"Unknown algorithm: {algo!r}. Available: {list(_EMBED_FNS)}")

    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    filename = _cache_key(algo, decoy_key, text)
    cached_path = _CACHE_DIR / filename

    if cached_path.exists():
        return cached_path

    logger.info(
        "Generating %s adversarial image (%s, %s)...", algo, decoy_key, filename
    )

    decoy_srgb = _load_decoy(decoy_key)
    height, width = decoy_srgb.shape[:2]
    if height != width:
        raise ValueError(f"Decoy image must be square, got {width}x{height}")
    if height % DOWNSCALE_FACTOR != 0:
        raise ValueError(
            f"Decoy side length must be divisible by {DOWNSCALE_FACTOR}, got {height}"
        )

    target_size = height // DOWNSCALE_FACTOR
    target_srgb = render_text_target(text, target_size)

    decoy_lin = srgb2lin(decoy_srgb)
    target_lin = srgb2lin(target_srgb)

    params = GENERATION_PARAMS[algo]
    embed_fn = _EMBED_FNS[algo]
    adv_lin = embed_fn(decoy_lin, target_lin, **params)

    adv_srgb = lin2srgb(np.clip(adv_lin, 0.0, 1.0))
    adv_uint8 = adv_srgb.round().astype(np.uint8)
    adv_img = Image.fromarray(adv_uint8)
    adv_img.save(cached_path)

    logger.info("  -> saved %s", cached_path)
    return cached_path
