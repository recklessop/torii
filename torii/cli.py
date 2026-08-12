"""torii CLI — bootstrap operations that predate any admin user.

The critical one is `bootstrap`: it creates the first admin principal from
inside the container, so the very first login has something to log in as.
Every later admin can be created from the /ui, or from `set-password` here.
"""

import argparse
import asyncio
import sys

from . import config, credentials, crypto, db


async def bootstrap(username: str, password: str | None) -> int:
    generated = None
    if not password:
        password = credentials.generate_temp_password()
        generated = password

    pool = await db.pool()
    try:
        async with pool.acquire() as conn:
            await db.migrate()
            existing = await conn.fetchval(
                "SELECT id FROM principals WHERE username = $1", username
            )
            if existing:
                print(f"principal {username!r} already exists; use set-password instead")
                return 1
            principal_id = await conn.fetchval(
                """INSERT INTO principals (kind, username, is_admin, totp_required)
                   VALUES ('human', $1, TRUE, TRUE) RETURNING id""",
                username,
            )
            await conn.execute(
                """INSERT INTO auth_identities (principal_id, backend, password_hash, password_is_temp)
                   VALUES ($1, 'local', $2, TRUE)""",
                principal_id, credentials.hash_password(password),
            )
    finally:
        await db.close()

    print(f"created admin principal {username!r} (id {principal_id})")
    if generated:
        print(f"temporary password: {generated}")
    print("torii will force a password change and TOTP enrollment on first sign-in.")
    return 0


async def set_password(username: str, password: str | None) -> int:
    generated = None
    if not password:
        password = credentials.generate_temp_password()
        generated = password

    pool = await db.pool()
    try:
        async with pool.acquire() as conn:
            principal_id = await conn.fetchval(
                "SELECT id FROM principals WHERE username = $1 AND kind = 'human'",
                username,
            )
            if principal_id is None:
                print(f"no such human principal {username!r}", file=sys.stderr)
                return 2
            password_hash = credentials.hash_password(password)
            exists = await conn.fetchval(
                "SELECT 1 FROM auth_identities WHERE principal_id = $1 AND backend = 'local'",
                principal_id,
            )
            if exists:
                await conn.execute(
                    """UPDATE auth_identities
                          SET password_hash = $2, password_is_temp = TRUE,
                              failed_attempts = 0, locked_until = NULL,
                              totp_secret = NULL, updated_at = now()
                        WHERE principal_id = $1 AND backend = 'local'""",
                    principal_id, password_hash,
                )
            else:
                await conn.execute(
                    """INSERT INTO auth_identities (principal_id, backend, password_hash, password_is_temp)
                       VALUES ($1, 'local', $2, TRUE)""",
                    principal_id, password_hash,
                )
    finally:
        await db.close()

    print(f"reset password for {username!r}; will be changed on next sign-in, TOTP re-enrolled.")
    if generated:
        print(f"temporary password: {generated}")
    return 0


async def encrypt_secrets() -> int:
    """Encrypt any upstream credentials still stored in plaintext.

    Explicit rather than implicit: a migration that silently rewrites secrets
    is one you can't schedule around, and running this is how an operator
    confirms the key works before relying on it.
    """
    if not crypto.available():
        print("TORII_ENCRYPTION_KEY is not set — nothing to encrypt with.", file=sys.stderr)
        return 2

    pool = await db.pool()
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT id, name, auth_header_value FROM upstreams
                    WHERE auth_header_value IS NOT NULL
                      AND auth_header_value NOT LIKE $1""",
                crypto.PREFIX + "%",
            )
            if not rows:
                print("nothing to do: no plaintext upstream credentials.")
                return 0
            for row in rows:
                await conn.execute(
                    "UPDATE upstreams SET auth_header_value = $2, updated_at = now() WHERE id = $1",
                    row["id"],
                    crypto.encrypt_secret(row["auth_header_value"]),
                )
                print(f"encrypted the credential for {row['name']!r}")
            # Prove the round trip on real data before declaring success.
            for row in rows:
                stored = await conn.fetchval(
                    "SELECT auth_header_value FROM upstreams WHERE id = $1", row["id"]
                )
                if crypto.decrypt_secret(stored) != row["auth_header_value"]:
                    print(f"VERIFY FAILED for {row['name']!r} — investigate before relying on this",
                          file=sys.stderr)
                    return 1
            print(f"encrypted {len(rows)} credential(s); round-trip verified.")
    finally:
        await db.close()
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser("torii")
    sub = parser.add_subparsers(dest="command", required=True)

    b = sub.add_parser("bootstrap", help="create the first admin principal")
    b.add_argument("--username", required=True)
    b.add_argument("--password", default=None,
                   help="omit to have torii generate a temp password")

    p = sub.add_parser("set-password", help="reset a human principal's password (temp)")
    p.add_argument("--username", required=True)
    p.add_argument("--password", default=None)

    sub.add_parser(
        "encrypt-secrets",
        help="encrypt upstream credentials still stored in plaintext",
    )

    args = parser.parse_args(argv)
    if args.command == "bootstrap":
        return asyncio.run(bootstrap(args.username, args.password))
    if args.command == "set-password":
        return asyncio.run(set_password(args.username, args.password))
    if args.command == "encrypt-secrets":
        return asyncio.run(encrypt_secrets())
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
