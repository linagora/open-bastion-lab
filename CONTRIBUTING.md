# Contributing

## Before committing

The repository carries a `pre-commit` hook that runs `black`, `mypy` and a
collection of the tests, through `uv`:

```bash
uv sync
uv run pre-commit install
```

The suite itself is not part of it: it needs a free lab, the portal and the
package server. Run it by hand, see
[open_bastion_tests/README.md](open_bastion_tests/README.md).
