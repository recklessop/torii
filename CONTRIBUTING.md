# Contributing to torii

Thanks for your interest. torii is a personal-infrastructure project published
as source-available software; contributions are welcome within the bounds
below.

## License and scope

torii is licensed under **PolyForm Noncommercial 1.0.0** (see `LICENSE`) — it
is source-available, not OSI open-source. By submitting a contribution you
agree it is licensed under the same terms as the project. Please keep changes
noncommercial in nature and in the spirit of the project.

## Before you start

- **Open an issue first for anything non-trivial.** A one-line bug fix is fine
  to send directly; a new capability should start as an issue so the design is
  agreed before code is written.
- The most important rule: **there is exactly one authorization path.**
  Every caller-facing surface resolves access through `torii/rbac.py` and
  nothing else. A new endpoint that checks permissions itself will be rejected,
  however correct it looks.

## House rules that block a merge

1. **No second authorization path.** See above.
2. **Invariants belong in the schema, not a handler.** If a security rule can
   be broken by a future code path, express it as a CHECK constraint or a
   partial unique index. See `torii/migrations/0002`–`0004` for the pattern.
3. **Security tests must fail for the right reason.** Delete a line of your new
   logic and confirm a test goes red. A negative test that passes
   unconditionally is worse than none.
4. **Secrets are shown once and stored hashed/encrypted.** Nothing plaintext in
   logs, templates, or a response body returned twice.
5. **Migrations are additive and filename-ordered**, and must be safe to run on
   a live database.

## Development setup

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements-dev.txt
docker compose up -d postgres valkey        # a local Postgres + valkey
```

Run the app locally:

```bash
export PUBLIC_BASE_URL=http://localhost:8400
export SESSION_SECRET=$(python -c "import secrets; print(secrets.token_hex(32))")
python -m torii.server                       # http://localhost:8400/healthz
```

## Running the tests

The DB-backed tests need a real Postgres and valkey. Point them at a
disposable database:

```bash
TORII_TEST_DATABASE_URL=postgresql://torii:torii@localhost:5432/torii \
TORII_OAUTH_TEST_DATABASE_URL=postgresql://torii:torii@localhost:5432/torii_oauth \
DATABASE_URL=postgresql://torii:torii@localhost:5432/torii \
VALKEY_URL=redis://localhost:6379/0 \
PUBLIC_BASE_URL=https://torii.test \
pytest -q
```

A second database (`torii_oauth`) is created automatically for the suites that
drive the whole ASGI app. The full suite must pass from a **clean** database
before a PR is ready — the suite was order-dependent once, so a fresh-DB run is
the check that matters.

## Dependencies

`requirements.txt` holds loose floors and is the source of truth for *what* we
depend on. `requirements.lock` is the pinned, hashed resolution used for
reproducible builds. If you change a dependency, regenerate the lock:

```bash
uv pip compile requirements.txt --generate-hashes --python-version 3.12 -o requirements.lock
```

## Submitting

- Branch, commit, open a PR against `main`. Keep the PR focused.
- Describe the decision, not just the diff — especially any security-relevant
  tradeoff.
- CI runs the test suite and security scans (`bandit`, `pip-audit`,
  `gitleaks`). Both must be green.
- Never commit secrets, `.env`, tokens, or TOTP seeds.
