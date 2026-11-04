"""Detection for the crypto review. Runs independently of the java/spring
deep-dive -- a plain-Java service with Bouncy Castle FIPS jars and no Spring
would otherwise get no review at all."""
from __future__ import annotations

import re
from pathlib import Path

from checks.crypto import bc_inventory
from core.fsutil import iter_files, read_text_safe

_JAVA_CRYPTO = re.compile(r"javax\.crypto|java\.security|org\.bouncycastle|SSLContext|KeyStore")
_PHP_CRYPTO = re.compile(r"openssl_|random_bytes|mt_rand|\brand\s*\(|mcrypt_|sodium_|hash_hmac|password_hash|\bcrypt\s*\(")


def detect_frameworks(target_path: Path) -> list[str]:
    found = []
    if bc_inventory(target_path) or any(_JAVA_CRYPTO.search(read_text_safe(p)) for p in iter_files(target_path, (".java", ".kt"))):
        found.append("java")
    if any(_PHP_CRYPTO.search(read_text_safe(p)) for p in iter_files(target_path, (".php", ".phtml", ".inc"))):
        found.append("php")
    return found


def detect_language(target_path: Path) -> bool:
    return bool(detect_frameworks(target_path))
