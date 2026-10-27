"""A lab configured and kept for debugging."""

import pytest
from pytest_bdd import scenario

FEATURE = "debug.feature"

pytestmark = pytest.mark.debug


@scenario(FEATURE, "The lab is configured")
def test_debug_lab() -> None:
    pass
