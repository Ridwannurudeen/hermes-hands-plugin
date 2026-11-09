from __future__ import annotations

import io

import mss
from PIL import Image

MAX_IMAGE = 2 * 1024 * 1024
MAX_EDGE = 1568


def capture(*, allow_screen: bool) -> bytes:
    if not allow_screen:
        raise PermissionError("Screenshot capture requires serve --allow-screen")
    with mss.mss() as capture_ctx:
        shot = capture_ctx.grab(capture_ctx.monitors[1])
        image = Image.frombytes("RGB", shot.size, shot.rgb)
    image.thumbnail((MAX_EDGE, MAX_EDGE))
    output = io.BytesIO()
    image.save(output, format="PNG", optimize=True)
    data = output.getvalue()
    if len(data) <= MAX_IMAGE:
        return data
    output = io.BytesIO()
    image.save(output, format="JPEG", quality=85, optimize=True)
    data = output.getvalue()
    if len(data) > MAX_IMAGE:
        raise ValueError("Screenshot exceeds 2 MiB after JPEG compression")
    return data
