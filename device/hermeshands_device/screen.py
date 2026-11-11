from __future__ import annotations

import io

MAX_IMAGE = 2 * 1024 * 1024
MAX_EDGE = 1568
NOT_ALLOWED = "Screenshot capture requires serve --allow-screen"
NOT_INSTALLED = "Screenshot support is not available on this computer. Reinstall hermes-hands."
NO_SCREEN = "screenshot_unavailable"


def unavailable() -> str | None:
    try:
        import mss
        from mss.exception import ScreenShotError
        from PIL import Image  # noqa: F401
    except ImportError:
        return NOT_INSTALLED
    try:
        with mss.mss():
            pass
    except (ScreenShotError, OSError):
        return NO_SCREEN
    return None


def capture(*, allow_screen: bool) -> bytes:
    if not allow_screen:
        raise PermissionError(NOT_ALLOWED)
    try:
        import mss
        from mss.exception import ScreenShotError
        from PIL import Image
    except ImportError as exc:
        raise RuntimeError(NOT_INSTALLED) from exc
    try:
        with mss.mss() as capture_ctx:
            shot = capture_ctx.grab(capture_ctx.monitors[1])
            image = Image.frombytes("RGB", shot.size, shot.rgb)
    except (ScreenShotError, OSError, IndexError) as exc:
        raise RuntimeError(NO_SCREEN) from exc
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
