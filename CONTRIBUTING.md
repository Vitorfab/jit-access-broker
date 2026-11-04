# Contributing

1. Branch from `main`: `feat/...`, `fix/...`, `docs/...`, `chore/...`, `test/...`.
2. Use Conventional Commits (`feat:`, `fix:`, `docs:`, `test:`, `refactor:`, `chore:`, `ci:`, `security:`).
3. Run before opening a PR:

       uv run ruff check .
       uv run ruff format --check .
       uv run mypy
       uv run pytest

4. Open a PR (squash merge). CI must pass.
5. Never commit secrets or real data.