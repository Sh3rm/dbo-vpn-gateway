"""Argon2 password hashing (python3-argon2-cffi), imported lazily.

Only hashes are ever stored. The import is lazy so modules that merely pass a
verifier around (and their tests) do not need argon2 installed.
"""

MIN_LENGTH = 12
MAX_LENGTH = 256

_hasher = None
_dummy_hash = None


def _ph():
    global _hasher
    if _hasher is None:
        from argon2 import PasswordHasher
        _hasher = PasswordHasher()
    return _hasher


def hash_password(password):
    return _ph().hash(password)


def verify_password(stored_hash, password):
    """True if password matches stored_hash. Never raises on a bad hash."""
    from argon2.exceptions import InvalidHash, VerificationError, VerifyMismatchError
    if not stored_hash:
        return False
    try:
        return _ph().verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHash):
        return False


def burn_time(password):
    """Run one verification against a throwaway hash so unknown users cost the same time."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_password("dbo-vpn-gateway-dummy-password")
    verify_password(_dummy_hash, password)


def policy_error(password, confirm, username):
    """Return an i18n message key if the password is unacceptable, else None."""
    if password != confirm:
        return "pw_mismatch"
    if len(password) < MIN_LENGTH:
        return "pw_too_short"
    if len(password) > MAX_LENGTH:
        return "pw_too_long"
    if password.strip().lower() == username.lower():
        return "pw_is_username"
    return None
