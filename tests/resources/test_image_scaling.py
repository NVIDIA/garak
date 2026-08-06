# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import numpy as np
import pytest
from PIL import Image

from garak.resources.anamorpher import (
    embed_bicubic,
    embed_bilinear,
    lin2srgb,
    srgb2lin,
)
from garak.resources.anamorpher import (
    embed_nn as embed_nearest,
)
from garak.resources.anamorpher import (
    weight_vector_bicubic as _weight_vector_bicubic,
)
from garak.resources.anamorpher import (
    weight_vector_bilinear as _weight_vector_bilinear,
)
from garak.resources.image_scaling import (
    DECOY_IMAGES,
    DOWNSCALE_FACTOR,
    _cache_key,
    _load_decoy,
    generate_adversarial_image,
    render_text_target,
)


class TestGammaConversion:
    def test_roundtrip(self):
        original = np.random.uniform(0, 255, (10, 10, 3)).astype(np.float32)
        linear = srgb2lin(original)
        recovered = lin2srgb(linear)
        np.testing.assert_allclose(recovered, original, atol=0.6)

    def test_black_stays_black(self):
        black = np.zeros((2, 2, 3), dtype=np.float32)
        assert srgb2lin(black).max() == 0.0
        assert lin2srgb(np.zeros((2, 2, 3))).max() == 0.0

    def test_white_stays_white(self):
        white = np.full((2, 2, 3), 255.0, dtype=np.float32)
        linear = srgb2lin(white)
        np.testing.assert_allclose(linear, 1.0, atol=1e-5)

    def test_output_range(self):
        values = (
            np.linspace(0, 255, 256)
            .reshape(16, 16, 1)
            .repeat(3, axis=2)
            .astype(np.float32)
        )
        linear = srgb2lin(values)
        assert linear.min() >= 0.0
        assert linear.max() <= 1.0


class TestWeightVectors:
    def test_bicubic_sums_to_one(self):
        w = _weight_vector_bicubic(4)
        assert w.shape == (16,)
        np.testing.assert_allclose(w.sum(), 1.0, atol=1e-6)

    def test_bilinear_sums_to_one(self):
        w = _weight_vector_bilinear(4)
        assert w.shape == (16,)
        np.testing.assert_allclose(w.sum(), 1.0, atol=1e-6)

    def test_bilinear_centre_weighted(self):
        w = _weight_vector_bilinear(4)
        # Centre 4 pixels should have the highest weights
        w2d = w.reshape(4, 4)
        centre_sum = w2d[1:3, 1:3].sum()
        assert centre_sum > 0.5


class TestEmbedNearest:
    def test_sampled_pixel_matches_target(self):
        s = DOWNSCALE_FACTOR
        offset = 2
        # Single block: 4x4 decoy, 1x1 target
        decoy = np.random.uniform(0, 1, (s, s, 3)).astype(np.float32)
        target = np.array([[[0.5, 0.7, 0.3]]], dtype=np.float32)

        result = embed_nearest(decoy, target, lam=0.0, gamma_target=1.0, offset=offset)
        # The sampled pixel should exactly equal the target
        np.testing.assert_allclose(
            result[offset, offset, :], target[0, 0, :], atol=1e-5
        )

    def test_with_lam_preserves_target(self):
        s = DOWNSCALE_FACTOR
        offset = 2
        decoy = np.random.uniform(0, 1, (s, s, 3)).astype(np.float32)
        target = np.array([[[0.4, 0.6, 0.2]]], dtype=np.float32)

        result = embed_nearest(decoy, target, lam=0.25, gamma_target=1.0, offset=offset)
        np.testing.assert_allclose(
            result[offset, offset, :], target[0, 0, :], atol=1e-5
        )


class TestEmbedBicubic:
    def test_weighted_sum_approaches_target(self):
        s = DOWNSCALE_FACTOR
        w = _weight_vector_bicubic(s)
        decoy = np.full((s, s, 3), 0.2, dtype=np.float32)
        target = np.array([[[0.8, 0.8, 0.8]]], dtype=np.float32)

        result = embed_bicubic(decoy, target, lam=0.25, gamma_target=1.0, dark_frac=1.0)

        # Anamorpher's solver is approximate; tolerance is loose here.
        # See TestPILRoundtrip for the definitive end-to-end correctness check.
        for c in range(3):
            weighted_sum = np.dot(w, result[:, :, c].ravel())
            np.testing.assert_allclose(weighted_sum, target[0, 0, c], atol=0.15)


class TestEmbedBilinear:
    def test_weighted_sum_approaches_target(self):
        s = DOWNSCALE_FACTOR
        w = _weight_vector_bilinear(s)
        decoy = np.full((s, s, 3), 0.2, dtype=np.float32)
        target = np.array([[[0.7, 0.7, 0.7]]], dtype=np.float32)

        result = embed_bilinear(
            decoy, target, lam=0.25, gamma_target=1.0, dark_frac=1.0
        )

        # Anamorpher's solver is approximate; tolerance is loose here.
        # See TestPILRoundtrip for the definitive end-to-end correctness check.
        for c in range(3):
            weighted_sum = np.dot(w, result[:, :, c].ravel())
            np.testing.assert_allclose(weighted_sum, target[0, 0, c], atol=0.15)


class TestRenderText:
    def test_output_shape(self):
        img = render_text_target("hello world", 100)
        assert img.shape == (100, 100, 3)
        assert img.dtype == np.float32

    def test_not_uniform(self):
        img = render_text_target("test payload", 200)
        # Text should make the image non-uniform
        assert img.std() > 0


class TestCacheKey:
    def test_deterministic(self):
        k1 = _cache_key("bicubic", "cat", "hello")
        k2 = _cache_key("bicubic", "cat", "hello")
        assert k1 == k2

    def test_different_for_different_inputs(self):
        k1 = _cache_key("bicubic", "cat", "hello")
        k2 = _cache_key("bilinear", "cat", "hello")
        k3 = _cache_key("bicubic", "boat", "hello")
        k4 = _cache_key("bicubic", "cat", "world")
        assert len({k1, k2, k3, k4}) == 4


class TestGenerateAdversarialImage:
    def test_generates_valid_png(self):
        path = generate_adversarial_image("nearest", "test payload", "cat")
        assert path.exists()
        assert path.suffix == ".png"
        with Image.open(path) as img:
            assert img.mode == "RGB"

    def test_cache_hit(self):
        path1 = generate_adversarial_image("nearest", "cache test", "cat")
        path2 = generate_adversarial_image("nearest", "cache test", "cat")
        assert path1 == path2


class TestPILRoundtrip:
    """End-to-end verification: generate adversarial image, downscale with
    the matching PIL resampler, and assert PSNR against target text image."""

    @pytest.mark.parametrize(
        "algo,resample,min_psnr",
        [
            ("nearest", Image.Resampling.NEAREST, 50.0),
            # Bilinear/bicubic thresholds are lower because PIL applies an
            # antialias prefilter during downscale, causing cross-block leakage
            # that anamorpher's per-block solver doesn't compensate for.
            ("bilinear", Image.Resampling.BILINEAR, 14.0),
            ("bicubic", Image.Resampling.BICUBIC, 12.0),
        ],
    )
    def test_downscale_matches_target(self, algo, resample, min_psnr):
        text = "roundtrip verification payload"
        path = generate_adversarial_image(algo, text, "cat")

        adv_img = Image.open(path)
        w, h = adv_img.size
        target_size = (w // DOWNSCALE_FACTOR, h // DOWNSCALE_FACTOR)

        down = adv_img.resize(target_size, resample)
        down_arr = np.array(down, dtype=np.float32)

        target_srgb = render_text_target(text, target_size[0])

        mse = float(np.mean((down_arr - target_srgb) ** 2))
        psnr = 10 * np.log10(255**2 / mse) if mse > 0 else float("inf")
        assert (
            psnr >= min_psnr
        ), f"{algo} roundtrip PSNR {psnr:.1f} dB < {min_psnr} dB threshold"

    def test_invalid_algo_raises(self):
        with pytest.raises(ValueError, match="Unknown algorithm"):
            generate_adversarial_image("invalid", "text", "cat")

    def test_invalid_decoy_raises(self):
        with pytest.raises(ValueError, match="Unknown decoy key"):
            generate_adversarial_image("nearest", "text", "nonexistent")

    def test_nearest_reveals_target_on_downscale(self):
        """Verify the attack works: downscaling the generated image reveals the target."""
        text = "verify embedding"
        path = generate_adversarial_image("nearest", text, "cat")
        with Image.open(path) as img:
            w = img.width // DOWNSCALE_FACTOR
            h = img.height // DOWNSCALE_FACTOR
            downscaled = img.resize((w, h), Image.Resampling.NEAREST)

        # Render expected target
        target_arr = render_text_target(text, w)
        target_img = Image.fromarray(target_arr.astype(np.uint8))

        # Compare: the downscaled image should be close to the rendered target
        down_arr = np.array(downscaled, dtype=np.float32)
        tgt_arr = np.array(target_img, dtype=np.float32)
        # Allow generous tolerance — the embedding preserves structure not exact pixels
        mse = ((down_arr - tgt_arr) ** 2).mean()
        assert mse < 5000, f"MSE too high ({mse}), embedding may not be working"
