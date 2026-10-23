"""Steps of the debug feature."""

from pytest_bdd import then

import logging
import time

LOGGER = logging.getLogger(__name__)


@then("the run waits for a Ctrl-C")
def run_waits_for_ctrl_c() -> None:
    """Keep the lab up until the user is done with it.

    Ctrl-C is taken here, so the scenario ends as a success and the
    session fixtures free the fleet and the portal.

    """
    LOGGER.info("The lab is configured, press Ctrl-C to stop the run")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        LOGGER.info("Ctrl-C received, the lab is freed")
