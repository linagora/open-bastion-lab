"""Step definitions, shared by the features that use them.

A module here holds steps and nothing else: no scenario, no test, so the
same steps serve several features.

pytest-bdd registers a step as a fixture, and pytest only shows the fixtures
of a module to the tests of that module. The modules of this package are
therefore loaded as plugins, named by ``addopts`` in the ``pyproject.toml``
of the lab, which makes their steps visible to every feature.

"""

from open_bastion_tests.steps import debug, ssh_access

__all__ = ["debug", "ssh_access"]
