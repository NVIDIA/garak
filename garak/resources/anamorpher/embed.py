# Vendored from https://github.com/trailofbits/anamorpher
# Original authors: Trail of Bits (Kikimora Morozova, Suha Sabi Hussain)
# License: Apache-2.0
#
# This module contains the adversarial image generation algorithms from
# anamorpher's backend/adversarial_generators/ directory. The code is kept
# as close to the original as practical; only CLI entry-points and cv2 I/O
# have been stripped.

from __future__ import annotations

from math import log10

import numpy as np
import numpy.typing as npt

# ---------------------------------------------------------------------------
# Types
# ---------------------------------------------------------------------------

ImageF32 = npt.NDArray[np.float32]
VecF32 = npt.NDArray[np.float32]

# ---------------------------------------------------------------------------
# Color transforms
# ---------------------------------------------------------------------------


def srgb2lin(x: ImageF32) -> ImageF32:
    """Convert sRGB (0..255) to linear-light (~0..1), elementwise."""
    x = x / 255.0
    y = np.where(x <= 0.04045, x / 12.92, ((x + 0.055) / 1.055) ** 2.4)
    return y.astype(np.float32)


def lin2srgb(y: ImageF32) -> ImageF32:
    """Convert linear-light (~0..1) to sRGB (0..255), elementwise."""
    x = np.where(y <= 0.0031308, 12.92 * y, 1.055 * np.power(y, 1 / 2.4) - 0.055)
    return (x * 255.0).clip(0, 255).astype(np.float32)


# ---------------------------------------------------------------------------
# Interpolation kernels and weight vectors
# ---------------------------------------------------------------------------


def cubic_kernel(
    x: npt.NDArray[np.floating], a: float = -0.5
) -> npt.NDArray[np.floating]:
    ax = np.abs(x)
    return np.where(
        ax <= 1,
        (a + 2) * ax**3 - (a + 3) * ax**2 + 1,
        np.where(ax < 2, a * ax**3 - 5 * a * ax**2 + 8 * a * ax - 4 * a, 0.0),
    )


def weight_vector_bicubic(scale: int = 4) -> VecF32:
    d = (scale / 2 - 1) - np.arange(scale, dtype=np.float32)
    w1d = cubic_kernel(d).astype(np.float32)
    return np.outer(w1d, w1d).astype(np.float32).reshape(-1)


def bilinear_kernel(x: npt.NDArray[np.floating]) -> npt.NDArray[np.floating]:
    """Linear (triangle) kernel for bilinear interpolation."""
    ax = np.abs(x)
    return np.where(ax <= 1, 1 - ax, 0.0)


def weight_vector_bilinear(scale: int = 4) -> VecF32:
    """
    Compute bilinear weights for a 2x2 region when downsampling by `scale`.
    For scale=4, OpenCV's bilinear uses only the 2x2 pixels at the center.
    """
    weights = np.zeros((scale, scale), dtype=np.float32)
    center = (scale - 1) / 2.0  # 1.5 for scale=4

    for y in range(scale):
        for x in range(scale):
            dy = abs(y - center)
            dx = abs(x - center)
            if dy < 1.0 and dx < 1.0:
                weights[y, x] = (1.0 - dy) * (1.0 - dx)

    weights = weights / weights.sum()
    return weights.astype(np.float32).reshape(-1)


# ---------------------------------------------------------------------------
# Luma helpers
# ---------------------------------------------------------------------------


def luma_linear(img: ImageF32) -> npt.NDArray[np.float32]:
    """Rec.709 luma in linear-light: Y = 0.2126 R + 0.7152 G + 0.0722 B."""
    return (0.2126 * img[..., 0] + 0.7152 * img[..., 1] + 0.0722 * img[..., 2]).astype(
        np.float32
    )


def bottom_luma_mask(img: ImageF32, frac: float = 0.3) -> npt.NDArray[np.bool_]:
    """Boolean mask where luma is within the bottom `frac` of observed range."""
    Y = luma_linear(img)
    y_min = float(Y.min())
    y_max = float(Y.max())
    thresh = y_min + frac * (y_max - y_min)
    return thresh >= Y


# ---------------------------------------------------------------------------
# Bicubic embedding
# ---------------------------------------------------------------------------


def embed_bicubic(
    decoy: ImageF32,
    target: ImageF32,
    lam: float = 0.25,
    eps: float = 0.0,
    gamma_target: float = 1.0,
    dark_frac: float = 0.3,
) -> ImageF32:
    """
    Adjust a high-res decoy so bicubic 4:1 downscale matches `target`,
    but only modify pixels whose luma lies in the bottom `dark_frac` of the
    image's observed luma range (computed on the original decoy, in
    linear-light).
    """
    s = 4
    w_full: VecF32 = weight_vector_bicubic(s)

    editable_mask = bottom_luma_mask(decoy, frac=dark_frac)

    adv = decoy.copy()
    tgt = (target**gamma_target).astype(np.float32)

    H_t, W_t, _ = tgt.shape
    for j in range(H_t):
        for i in range(W_t):
            y0, x0 = j * s, i * s
            blk = adv[y0 : y0 + s, x0 : x0 + s]
            blk_mask = editable_mask[y0 : y0 + s, x0 : x0 + s]

            mask_flat = blk_mask.reshape(-1)
            idx = np.flatnonzero(mask_flat)
            if idx.size == 0:
                continue

            for c in (0,):  # channel 0 only, matching upstream v1 behavior
                y_cur = float((w_full * blk[..., c].reshape(-1)).sum())
                diff = float(tgt[j, i, c] - y_cur)

                w_sub = w_full[idx]
                M = float(w_sub.size)

                sum_w_sub = float(w_sub.sum())
                w_norm2_sub = float(w_sub @ w_sub)

                denom = (M * w_norm2_sub + lam**2) - (sum_w_sub**2)
                if abs(denom) < 1e-12:
                    continue

                delta_sub = diff * (M * w_sub - lam * sum_w_sub) / denom

                if eps > 0.0 and w_sub.size >= 3:
                    C_sub = np.vstack([w_sub, np.ones_like(w_sub, dtype=np.float32)])
                    _, _, Vh_sub = np.linalg.svd(C_sub, full_matrices=True)
                    B_sub = Vh_sub[2:].astype(np.float32)
                    if B_sub.size > 0:
                        delta_sub = delta_sub + eps * (
                            B_sub.T @ np.random.randn(B_sub.shape[0])
                        ).astype(np.float32)

                delta_vec = np.zeros_like(w_full, dtype=np.float32)
                delta_vec[idx] = delta_sub.astype(np.float32)
                blk[..., c] = blk[..., c] + delta_vec.reshape(s, s)

            adv[y0 : y0 + s, x0 : x0 + s] = blk

    return adv.astype(np.float32)


# ---------------------------------------------------------------------------
# Bilinear embedding
# ---------------------------------------------------------------------------


def embed_bilinear(
    decoy: ImageF32,
    target: ImageF32,
    lam: float = 0.25,
    eps: float = 0.0,
    gamma_target: float = 1.0,
    dark_frac: float = 0.3,
) -> ImageF32:
    """
    Adjust a high-res decoy so bilinear 4:1 downscale matches `target`,
    but only modify pixels whose luma lies in the bottom `dark_frac` of the
    image's observed luma range (computed on the original decoy, in
    linear-light).
    """
    s = 4
    w_full: VecF32 = weight_vector_bilinear(s)

    editable_mask = bottom_luma_mask(decoy, frac=dark_frac)

    adv = decoy.copy()
    tgt = (target**gamma_target).astype(np.float32)

    H_t, W_t, _ = tgt.shape
    for j in range(H_t):
        for i in range(W_t):
            y0, x0 = j * s, i * s
            blk = adv[y0 : y0 + s, x0 : x0 + s]
            blk_mask = editable_mask[y0 : y0 + s, x0 : x0 + s]

            mask_flat = blk_mask.reshape(-1)
            idx = np.flatnonzero(mask_flat)
            if idx.size == 0:
                continue

            for c in (0,):  # channel 0 only, matching upstream v1 behavior
                y_cur = float((w_full * blk[..., c].reshape(-1)).sum())
                diff = float(tgt[j, i, c] - y_cur)

                w_sub = w_full[idx]
                M = float(w_sub.size)

                sum_w_sub = float(w_sub.sum())
                w_norm2_sub = float(w_sub @ w_sub)

                denom = (M * w_norm2_sub + lam**2) - (sum_w_sub**2)
                if abs(denom) < 1e-12:
                    continue

                delta_sub = diff * (M * w_sub - lam * sum_w_sub) / denom

                if eps > 0.0 and w_sub.size >= 3:
                    C_sub = np.vstack([w_sub, np.ones_like(w_sub, dtype=np.float32)])
                    _, _, Vh_sub = np.linalg.svd(C_sub, full_matrices=True)
                    B_sub = Vh_sub[2:].astype(np.float32)
                    if B_sub.size > 0:
                        delta_sub = delta_sub + eps * (
                            B_sub.T @ np.random.randn(B_sub.shape[0])
                        ).astype(np.float32)

                delta_vec = np.zeros_like(w_full, dtype=np.float32)
                delta_vec[idx] = delta_sub.astype(np.float32)
                blk[..., c] = blk[..., c] + delta_vec.reshape(s, s)

            adv[y0 : y0 + s, x0 : x0 + s] = blk

    return adv.astype(np.float32)


# ---------------------------------------------------------------------------
# Nearest-neighbour embedding
# ---------------------------------------------------------------------------


def embed_nn(
    decoy: ImageF32,
    target: ImageF32,
    lam: float = 0.25,
    eps: float = 0.0,
    gamma_target: float = 1.0,
    offset: int = 2,
) -> ImageF32:
    """
    Adjust a high-res decoy so 4:1 nearest-neighbor downscale matches `target`.

    For PIL's NEAREST, shrinking by an exact factor of 4 samples the CENTER
    of each 4x4 block. That's (offset, offset) with offset=2 (0-based).
    """
    s = 4
    n = s * s
    k = offset * s + offset

    # Null space for constraints [e_k ; ones]
    e = np.zeros(n, dtype=np.float32)
    e[k] = 1.0
    C = np.vstack([e, np.ones(n, dtype=np.float32)])  # (2,16)
    _, _, Vh = np.linalg.svd(C, full_matrices=True)
    B = Vh[2:].astype(np.float32)  # (14,16), basis for null space

    adv = decoy.copy()
    tgt = (target**gamma_target).astype(np.float32)

    H_t, W_t, _ = tgt.shape
    for j in range(H_t):
        for i in range(W_t):
            y0, x0 = j * s, i * s
            blk = adv[y0 : y0 + s, x0 : x0 + s]

            for c in (0,):  # channel 0 only, matching upstream v1 behavior
                cur = float(blk[offset, offset, c])
                diff = float(tgt[j, i, c] - cur)

                if lam <= 0.0:
                    blk[offset, offset, c] = cur + diff
                else:
                    # minimize ||delta||^2 + lam^2 (sum delta)^2  s.t. delta_k = diff
                    # yields: delta_j (j!=k) = -diff * lam^2 / (1 + 15*lam^2)
                    denom = 1.0 + 15.0 * (lam**2)
                    delta_other = -diff * (lam**2) / denom
                    blk[..., c] = blk[..., c] + delta_other
                    blk[offset, offset, c] = cur + diff

                if eps > 0.0:
                    z = (B.T @ np.random.randn(B.shape[0]).astype(np.float32)).reshape(
                        s, s
                    )
                    blk[..., c] = blk[..., c] + eps * z

            adv[y0 : y0 + s, x0 : x0 + s] = blk

    return adv.astype(np.float32)


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------


def mse_psnr(a: ImageF32, b: ImageF32) -> tuple[float, float]:
    """Mean squared error and PSNR (peak = 1.0) between two linear-light images."""
    mse = float(np.mean((a - b) ** 2))
    psnr = float("inf") if mse == 0 else 10.0 * log10(1.0 / mse)
    return mse, psnr
