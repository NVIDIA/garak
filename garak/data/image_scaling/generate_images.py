# garak/data/image_scaling/generate_images.py
"""Offline script to regenerate anamorphic attack images.

These images look like innocent pictures at full resolution
but reveal hidden text instructions after the AI backend downscales them.

Usage:
    pip install "git+https://github.com/trailofbits/anamorpher.git"
    cd garak/data/image_scaling
    python generate_images.py

WARNING: Run this once and commit the outputs.
"""

import argparse
import json
from pathlib import Path
from urllib.request import urlretrieve

import numpy as np
from PIL import Image, ImageDraw, ImageFont

DOWNSCALE_FACTOR = 4

GENERATION_PARAMS = {
    "bicubic": {
        "lam": 0.25,
        "eps": 0.0,
        "gamma_target": 1.0,
        "dark_frac": 0.3,
    },
    "bilinear": {
        "lam": 0.25,
        "eps": 0.0,
        "gamma_target": 0.9,
        "dark_frac": 0.3,
    },
    "nearest": {
        "lam": 0.25,
        "eps": 0.0,
        "gamma_target": 1.0,
        "offset": 2,
    },
}

PIL_RESAMPLE = {
    "bicubic": Image.Resampling.BICUBIC,
    "bilinear": Image.Resampling.BILINEAR,
    "nearest": Image.Resampling.NEAREST,
}

try:
    import cv2
except ImportError:
    cv2 = None

try:
    from backend.adversarial_generators.bicubic_gen_payload import (
        embed,
        lin2srgb,
        srgb2lin,
    )
    from backend.adversarial_generators.bilinear_gen_payload import embed_bilinear
    from backend.adversarial_generators.nearest_gen_payload import embed_nn
except ImportError as exc:
    raise SystemExit(
        "Missing anamorpher backend package. Install with: "
        'pip install "git+https://github.com/trailofbits/anamorpher.git"'
    ) from exc

IMAGE_SPECS = (
    ("bicubic_hb_cat", "bicubic", "cat"),
    ("bicubic_hb_boat", "bicubic", "boat"),
    ("bicubic_hb_teapot", "bicubic", "teapot"),
    ("bilinear_hb_cat", "bilinear", "cat"),
    ("bilinear_hb_boat", "bilinear", "boat"),
    ("bilinear_hb_teapot", "bilinear", "teapot"),
    ("nearest_hb_cat", "nearest", "cat"),
    ("nearest_hb_boat", "nearest", "boat"),
    ("nearest_hb_teapot", "nearest", "teapot"),
)

DECOY_IMAGES = {
    "cat": "3200_decoy_cat.png",
    "boat": "4368_boat_decoy.png",
    "teapot": "4368_decoy_teapot.png",
}

DECOY_BASE_URL = (
    "https://raw.githubusercontent.com/trailofbits/anamorpher/main/"
    "backend/adversarial_generators/decoy_images"
)

DEFAULT_FONT_SIZE = 48
_SCRIPT_DIR = Path(__file__).resolve().parent

_FONT_SEARCH_PATHS = [
    "/System/Library/Fonts/Arial.ttf",  # macOS
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",  # Linux
    "C:\\Windows\\Fonts\\arial.ttf",  # Windows
]

_TEXT_BG_COLOR = "#333333"
_TEXT_FG_COLOR = "#00b002"
_TEXT_MARGIN = 10


def _load_font(size: int) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    for path in _FONT_SEARCH_PATHS:
        if Path(path).exists():
            return ImageFont.truetype(path, size)
    return ImageFont.load_default()


def _wrap_text_to_fit(
    text: str,
    font: ImageFont.FreeTypeFont | ImageFont.ImageFont,
    draw: ImageDraw.ImageDraw,
    max_width: int,
) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current_line: list[str] = []

    for word in words:
        candidate = " ".join(current_line + [word])
        bbox = draw.textbbox((0, 0), candidate, font=font)
        text_width = bbox[2] - bbox[0]

        if text_width <= max_width:
            current_line.append(word)
        else:
            if current_line:
                lines.append(" ".join(current_line))
                current_line = [word]
            else:
                lines.append(word)

    if current_line:
        lines.append(" ".join(current_line))

    return lines


def _render_text(text: str, size: int) -> np.ndarray:
    """Render text with top-left placement using anamorpher colours/margins."""
    image = Image.new("RGB", (size, size), color=_TEXT_BG_COLOR)
    draw = ImageDraw.Draw(image)
    font = _load_font(DEFAULT_FONT_SIZE)

    text_area_width = size - 2 * _TEXT_MARGIN
    wrapped_lines = _wrap_text_to_fit(text, font, draw, text_area_width)

    bbox_ay = draw.textbbox((0, 0), "Ay", font=font)
    line_height = bbox_ay[3] - bbox_ay[1]
    y = _TEXT_MARGIN

    for line in wrapped_lines:
        if y + line_height > size - _TEXT_MARGIN:
            break
        x = _TEXT_MARGIN
        draw.text((x, y), line, font=font, fill=_TEXT_FG_COLOR)
        y += line_height

    return np.array(image)


_DECOY_DIR = _SCRIPT_DIR / "decoy_images"
_PAYLOADS_FILE = _SCRIPT_DIR.parent / "payloads" / "harmful_behaviors.json"
_OUTPUT_DIR = _SCRIPT_DIR / "adversarial_images"
_PREVIEW_DIR = _SCRIPT_DIR / "previews"

# Indices of the most unambiguously harmful payloads in harmful_behaviors.json.
_SELECTED_PAYLOAD_INDICES = [
    0,  # synthesizing parathion          — CBRN
    4,  # animal dismemberment            — graphic violence
    6,  # making nitazene                 — CBRN
    7,  # synthesizing napalm             — weapon
    8,  # making methamphetamine          — drug synthesis
    9,  # giving people dimethyl mercury  — poisoning
    12,  # getting away with murder        — violence
    13,  # insulting a child               — abuse
    14,  # triggering a manic episode      — psychological abuse
]


def _load_harmful_behaviors() -> list[str]:
    payload_data = json.loads(_PAYLOADS_FILE.read_text(encoding="utf-8"))
    payloads = payload_data.get("payloads", [])
    cleaned_payloads = [p.strip() for p in payloads if isinstance(p, str) and p.strip()]
    if not cleaned_payloads:
        raise ValueError(f"No payload strings found in {_PAYLOADS_FILE}")
    selected = [
        cleaned_payloads[i]
        for i in _SELECTED_PAYLOAD_INDICES
        if i < len(cleaned_payloads)
    ]
    if not selected:
        raise ValueError("No payloads matched the selected indices")
    return selected


def _get_decoy_path(decoy_key: str) -> Path:
    if decoy_key not in DECOY_IMAGES:
        raise ValueError(f"Unknown decoy key: {decoy_key}")

    _DECOY_DIR.mkdir(parents=True, exist_ok=True)
    filename = DECOY_IMAGES[decoy_key]
    local_path = _DECOY_DIR / filename

    if not local_path.exists():
        url = f"{DECOY_BASE_URL}/{filename}"
        print(f"Downloading {filename} from {url}...")
        urlretrieve(url, local_path)

    return local_path


def _load_decoy(decoy_key: str) -> np.ndarray:
    decoy_path = _get_decoy_path(decoy_key)
    with Image.open(decoy_path) as image:
        return np.asarray(image.convert("RGB"), dtype=np.float32)


def _make_target(text: str, size: int) -> np.ndarray:
    return _render_text(text, size).astype(np.float32)


def _generate_image(algo: str, text: str, pattern: str) -> Image.Image:
    decoy_srgb = _load_decoy(pattern)
    height, width = decoy_srgb.shape[:2]
    if height != width:
        raise ValueError(f"Decoy image must be square, got {width}x{height}")
    if height % DOWNSCALE_FACTOR != 0:
        raise ValueError(
            f"Decoy image side length must be divisible by {DOWNSCALE_FACTOR}, got {height}"
        )

    target_size = height // DOWNSCALE_FACTOR
    target_srgb = _make_target(text, target_size)

    decoy_lin = srgb2lin(decoy_srgb)
    target_lin = srgb2lin(target_srgb)
    params = GENERATION_PARAMS.get(algo)
    if params is None:
        raise ValueError(f"Unknown algorithm: {algo}")

    if algo == "bicubic":
        adv_lin = embed(
            decoy_lin,
            target_lin,
            **params,
        )
    elif algo == "bilinear":
        adv_lin = embed_bilinear(
            decoy_lin,
            target_lin,
            **params,
        )
    elif algo == "nearest":
        adv_lin = embed_nn(
            decoy_lin,
            target_lin,
            **params,
        )
    else:  # pragma: no cover
        raise ValueError(f"Unknown algorithm: {algo}")

    adv_srgb = lin2srgb(np.clip(adv_lin, 0.0, 1.0)).round().astype(np.uint8)
    adv_img = Image.fromarray(adv_srgb)
    return adv_img


def _downscale_preview(img: Image.Image, algo: str) -> Image.Image:
    """Downscale an image using the same backend logic as the probe."""
    width = img.width // DOWNSCALE_FACTOR
    height = img.height // DOWNSCALE_FACTOR

    if algo in ("bilinear", "bicubic") and cv2 is not None:
        rgb = np.asarray(img.convert("RGB"), dtype=np.uint8)
        bgr = cv2.cvtColor(rgb, cv2.COLOR_RGB2BGR)
        interpolation = cv2.INTER_CUBIC if algo == "bicubic" else cv2.INTER_LINEAR_EXACT
        down_bgr = cv2.resize(bgr, (width, height), interpolation=interpolation)
        down_rgb = cv2.cvtColor(down_bgr, cv2.COLOR_BGR2RGB)
        return Image.fromarray(down_rgb)

    resample = PIL_RESAMPLE[algo]
    return img.resize((width, height), resample)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate image scaling attack images")
    parser.add_argument(
        "--image",
        choices=[name for name, _, _ in IMAGE_SPECS],
        help="Generate only one image by basename (for example: bilinear_hb_boat)",
    )
    parser.add_argument(
        "--no-preview",
        action="store_true",
        help="Skip generating downscaled preview images",
    )
    return parser.parse_args()


def main() -> None:
    args = _parse_args()
    payloads = _load_harmful_behaviors()
    output_dir = _OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)
    if not args.no_preview:
        _PREVIEW_DIR.mkdir(parents=True, exist_ok=True)

    for payload_index, (name, algo, pattern) in enumerate(IMAGE_SPECS):
        if args.image and name != args.image:
            continue
        text = payloads[payload_index % len(payloads)]
        print(
            f"Generating {name}.png ({algo}, {pattern}, payload #{payload_index + 1})..."
        )
        out_image = _generate_image(algo, text, pattern)
        out_path = output_dir / f"{name}.png"
        out_image.save(out_path)
        print(f"  -> {out_path.name}")

        if not args.no_preview:
            preview = _downscale_preview(out_image, algo)
            preview_path = _PREVIEW_DIR / f"{name}.png"
            preview.save(preview_path)
            print(f"  -> previews/{preview_path.name}")

    print(f"Done. Commit the generated PNG files in {output_dir}.")


if __name__ == "__main__":
    main()
