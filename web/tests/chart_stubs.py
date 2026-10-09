"""Stub for the plotly -> kaleido render used by ``reNgine.charts``.

``plotly.io.to_image`` starts a headless Chromium through kaleido: slow, and it
can hang indefinitely on a busy machine. Unit tests patch the name where
``reNgine.charts`` looks it up and assert on the ``go.Figure`` handed to it;
what the chart helpers do with the bytes (base64 for the PDF template) is still
exercised with a real, minimal PNG.
"""
from unittest.mock import patch

# 1x1 transparent PNG.
MINIMAL_PNG = bytes.fromhex(
    '89504e470d0a1a0a0000000d494844520000000100000001080600'
    '00001f15c4890000000b49444154789c6360000200000500017a5e'
    'ab3f0000000049454e44ae426082'
)


def patch_chart_render():
    """``patch`` of ``reNgine.charts.to_image`` returning ``MINIMAL_PNG``.

    Usable as a decorator or context manager; the mock's ``call_args`` carry
    the figure that would have been rendered.
    """
    return patch('reNgine.charts.to_image', return_value=MINIMAL_PNG)


def rendered_figure(mock_to_image):
    """Figure passed to the (stubbed) renderer on its last call."""
    return mock_to_image.call_args.args[0]
