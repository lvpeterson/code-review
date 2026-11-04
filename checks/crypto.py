"""Cryptography misuse checks for Java (JCA/JCE, with a Bouncy Castle FIPS
focus) and PHP (OpenSSL / key generation scripts).

Java:
  JC-0xx       AST rules in checks/java_crypto_ast.py (the line rules below are
               the fallback for files javalang can't parse) -- weak algorithms, ECB, static IVs, hardcoded keys,
               weak randomness, small keys, trust-all TrustManagers...
  JC-FIPS-0xx  project rules -- BC FIPS jar/dependency inventory, non-FIPS
               Bouncy Castle on the same classpath, approved-only mode not
               enforced, FIPS 140-2 module status, known-CVE versions.
  JC-INV-001   inventory of every Bouncy Castle artifact found (info).

PHP:
  PHP-0xx      line rules -- non-CSPRNG key/token generation, weak RSA bits,
               ECB/DES/RC4, static IVs, unencrypted key export, printed keys,
               mcrypt, disabled TLS verification.

Version facts encoded here (re-verify when they matter for a report):
  * BC-FJA (bc-fips) 1.0.x is a FIPS 140-2 validated module; 2.x is the
    FIPS 140-3 one. NIST moved remaining FIPS 140-2 certificates to the
    historical list on 2026-09-21 -- check the module's current CMVP status.
  * CVE-2022-45146: bc-fips before 1.0.2.4 on Java 13+ can zero temporary
    keys while still in use.
  * Non-FIPS bcprov before 1.78 is affected by CVE-2024-29857 / CVE-2024-30171
    / CVE-2024-30172 (and < 1.74 by CVE-2023-33201).
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Optional

from checks import secrets
from core.fsutil import _SKIP_DIRS, read_text_safe
from core.models import Finding
from core.rulescan import LineRule, make_finding, mask_comments, rel, scan_text

_SECURITY_CONTEXT = r"(?i)(?:key|token|secret|salt|nonce|\biv\b|password|passwd|otp|session|csrf|nonce)"

JAVA_RULES: list[LineRule] = [
    LineRule("JC-001", "high", "Broken cipher algorithm",
             r"Cipher\.getInstance\(\s*\"(?:DES|DESede|TripleDES|3DES|RC4|ARCFOUR|RC2|Blowfish|IDEA)\b",
             "DES/3DES/RC4/RC2/Blowfish are broken or deprecated and not FIPS-approved for new "
             "encryption (3DES encryption was disallowed after 2023). Use AES-GCM."),
    LineRule("JC-002", "high", "ECB mode",
             r"Cipher\.getInstance\(\s*\"[A-Za-z0-9]+/ECB/(?!OAEP)",
             "ECB encrypts identical blocks to identical ciphertext, leaking data patterns. Use "
             "AES/GCM/NoPadding with a unique 12-byte nonce per message.",
             exclude=r"\"RSA/ECB/"),
    LineRule("JC-002", "medium", "Cipher transformation without mode (defaults to ECB)",
             r"Cipher\.getInstance\(\s*\"(?:AES|DES|DESede)\"",
             "\"AES\" alone means AES/ECB/PKCS5Padding in most providers. Specify AES/GCM/NoPadding."),
    LineRule("JC-003", "medium", "RSA encryption without OAEP",
             r"Cipher\.getInstance\(\s*\"RSA(?:\"|/(?:ECB|NONE)/(?:PKCS1Padding|NoPadding)\")",
             "PKCS#1 v1.5 encryption padding is vulnerable to padding-oracle attacks (Bleichenbacher) "
             "and raw RSA is malleable. Use RSA/ECB/OAEPWithSHA-256AndMGF1Padding (or RSA-KEM)."),
    LineRule("JC-004", "medium", "Weak hash / signature algorithm",
             r"(?:MessageDigest|Signature|Mac|KeyPairGenerator|SecretKeyFactory)\.getInstance\(\s*\""
             r"(?:MD2|MD4|MD5|SHA-?1|SHA1with\w+|MD5with\w+|HmacMD5|PBKDF2WithHmacSHA1)\"",
             "MD5/SHA-1 are collision-broken and SHA-1 signatures aren't FIPS-approved for generation. "
             "Use SHA-256+ (and HMAC-SHA-256 / PBKDF2WithHmacSHA256)."),
    LineRule("JC-005", "high", "Static or zero IV / nonce",
             r"new\s+(?:IvParameterSpec|GCMParameterSpec)\s*\((?:\s*\d+\s*,)?\s*(?:new\s+byte\s*\[\s*\d*\s*\]|\"[^\"]*\"\.getBytes|\{)",
             "A constant IV makes CBC deterministic and, for GCM, reusing a nonce under the same key "
             "lets an attacker forge messages and recover the authentication key. Generate a fresh "
             "random IV per encryption with SecureRandom and send it with the ciphertext."),
    LineRule("JC-006", "high", "Hardcoded symmetric key",
             r"new\s+SecretKeySpec\s*\(\s*(?:\"[^\"]*\"\.getBytes|new\s+byte\s*\[\s*\]\s*\{|[A-Z_]{3,}\s*\.getBytes)",
             "The key is in the source/binary, so anyone with the jar can decrypt. Load keys from a "
             "keystore (BCFKS under FIPS), KMS or an HSM."),
    LineRule("JC-007", "medium", "Non-cryptographic RNG in security-sensitive code",
             r"new\s+(?:java\.util\.)?Random\s*\(|Math\.random\s*\(|ThreadLocalRandom\.current\(\)",
             "java.util.Random / Math.random are predictable. Use SecureRandom (DRBG via "
             "CryptoServicesRegistrar.getSecureRandom() under BC FIPS) for keys, IVs, salts and tokens.",
             file_require=_SECURITY_CONTEXT, confidence="REVIEW"),
    LineRule("JC-008", "medium", "SHA1PRNG SecureRandom",
             r"SecureRandom\.getInstance\(\s*\"SHA1PRNG\"",
             "SHA1PRNG isn't a FIPS-approved DRBG and is deterministic if seeded explicitly. Use "
             "SecureRandom.getInstance(\"DEFAULT\", \"BCFIPS\") / getInstanceStrong()."),
    LineRule("JC-008", "high", "SecureRandom seeded with a constant or the clock",
             r"\.setSeed\s*\(\s*(?:\d+L?|\"[^\"]*\"\.getBytes|System\.(?:currentTimeMillis|nanoTime)\(\))|"
             r"new\s+SecureRandom\s*\(\s*\"[^\"]*\"\.getBytes",
             "An explicitly seeded SecureRandom (SHA1PRNG in particular) produces the same output "
             "every time -- keys derived from it are predictable."),
    LineRule("JC-009", "high", "Key size too small",
             r"(?:KeyPairGenerator|kpg|keyGen|generator)\w*\.initialize\s*\(\s*(?:512|768|1024|1536)\b|"
             r"new\s+RSAKeyGenParameterSpec\s*\(\s*(?:512|768|1024|1536)\b|"
             r"KeyGenerator\w*\.init\s*\(\s*(?:40|56|64|80)\b",
             "RSA/DSA/DH below 2048 bits and symmetric keys below 128 bits are not acceptable (FIPS "
             "requires >= 2048; prefer 3072 / P-256+)."),
    LineRule("JC-010", "high", "Broken password-based encryption scheme",
             r"\"PBEWith(?:MD5|SHA1)And(?:DES|RC2|RC4|TripleDES|3KeyTripleDES|DESede)\w*\"",
             "These PBE schemes use broken hashes/ciphers. Use PBKDF2WithHmacSHA256 (>= 600k "
             "iterations) to derive an AES-GCM key, or a KMS."),
    LineRule("JC-010", "medium", "Low PBKDF2 iteration count",
             r"new\s+PBEKeySpec\s*\([^;]*,[^;]*,\s*(\d{1,4}|[1-9]\d{4})\s*[,)]",
             "OWASP recommends >= 600,000 iterations for PBKDF2-HMAC-SHA256 (FIPS SP 800-132 minimum "
             "is 1,000, which is far too low today)."),
    LineRule("JC-011", "high", "TrustManager / HostnameVerifier that accepts everything",
             r"checkServerTrusted\s*\([^)]*\)\s*(?:throws\s+[\w.,\s]+)?\{\s*\}|"
             r"(?:verify\s*\(\s*String\s+\w+\s*,\s*SSLSession\s+\w+\s*\)\s*\{\s*return\s+true\s*;)|"
             r"ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|\(\s*\w+\s*,\s*\w+\s*\)\s*->\s*true\s*\)",
             "Certificate and/or hostname validation is disabled -- any MITM can impersonate the "
             "server and read credentials.", multiline=True),
    LineRule("JC-012", "medium", "Obsolete SSL/TLS protocol",
             r"SSLContext\.getInstance\(\s*\"(?:SSL|SSLv2|SSLv3|TLSv1|TLSv1\.1)\"|setEnabledProtocols\([^)]*\"(?:SSLv3|TLSv1|TLSv1\.1)\"",
             "Use TLSv1.2/TLSv1.3 only."),
    LineRule("JC-013", "high", "Hardcoded keystore / key password",
             r"\.(?:load|getKey|store|getEntry|setKeyEntry)\s*\([^;]*\"[^\"]+\"\.toCharArray\(\)|"
             r"new\s+KeyStore\.PasswordProtection\s*\(\s*\"[^\"]+\"\.toCharArray",
             "The keystore password is in the code, so the keystore's protection is only as good as "
             "the jar's secrecy. Read it from a secrets manager / environment at runtime."),
    LineRule("JC-014", "low", "Short GCM authentication tag",
             r"new\s+GCMParameterSpec\s*\(\s*(?:32|64|96|104|112)\s*,",
             "Use the full 128-bit tag."),
    LineRule("JC-015", "low", "CBC mode without visible integrity protection",
             r"Cipher\.getInstance\(\s*\"AES/CBC/PKCS[57]Padding\"",
             "Unauthenticated CBC is malleable and padding-oracle prone if decryption errors are "
             "observable. Prefer AES/GCM, or encrypt-then-MAC with HMAC-SHA-256.",
             file_suppress=r"Mac\.getInstance\(\s*\"Hmac", confidence="REVIEW"),
    LineRule("JC-016", "medium", "Private key or secret logged",
             r"(?:log(?:ger)?\.\w+|System\.(?:out|err)\.print\w*)\s*\([^;]*(?:getEncoded\(\)|privateKey|secretKey|"
             r"getPrivate\(\)|password)",
             "Key material / passwords written to logs outlive the key's own protections.",
             confidence="REVIEW"),
]

PHP_RULES: list[LineRule] = [
    LineRule("PHP-001", "high", "Non-cryptographic RNG used for a key/token/secret",
             r"\b(?:rand|mt_rand|uniqid|lcg_value|str_shuffle|array_rand|shuffle|microtime)\s*\(",
             "rand()/mt_rand()/uniqid()/str_shuffle() are predictable (mt_rand's state can be "
             "recovered from a few outputs). Use random_bytes() / random_int().",
             file_require=_SECURITY_CONTEXT),
    LineRule("PHP-002", "high", "RNG explicitly seeded",
             r"\b(?:mt_srand|srand)\s*\(",
             "A seeded mt_rand/rand sequence is fully reproducible -- every key generated after it "
             "can be regenerated by an attacker who knows/guesses the seed (often time())."),
    LineRule("PHP-003", "high", "RSA key generated with fewer than 2048 bits",
             r"[\"']private_key_bits[\"']\s*=>\s*(?:384|512|768|1024|1536)\b",
             "Use at least 2048 bits (3072 recommended), or EC (curve_name => 'prime256v1')."),
    LineRule("PHP-004", "high", "Broken cipher / ECB mode",
             r"[\"'](?:aes-\d+-ecb|des(?:-ede3?)?(?:-cbc|-ecb|-cfb|-ofb)?|des-ede3|rc4(?:-\d+)?|bf-(?:cbc|ecb|cfb|ofb)|rc2-\w+|"
             r"idea-\w+|cast5-\w+)[\"']",
             "ECB leaks plaintext patterns; DES/3DES/RC4/Blowfish/RC2 are broken or deprecated. Use "
             "aes-256-gcm with a random 12-byte IV and verify the tag on decrypt."),
    LineRule("PHP-005", "high", "Static / predictable IV",
             r"\$\w*iv\w*\s*=\s*(?:[\"'][^\"']+[\"']|str_repeat\s*\(|substr\s*\(\s*(?:md5|sha1|hash)\s*\()|"
             # 5th argument (the IV) of openssl_encrypt/decrypt given as a literal
             r"openssl_(?:en|de)crypt\s*\((?:[^,;()]+|\([^()]*\)),(?:[^,;()]+|\([^()]*\)),(?:[^,;()]+|\([^()]*\)),"
             r"(?:[^,;()]+|\([^()]*\)),\s*[\"'][^\"']+[\"']",
             "The IV must be random and unique per message: $iv = random_bytes(openssl_cipher_iv_length($cipher))."),
    LineRule("PHP-006", "high", "MD5/SHA-1 used for passwords or key derivation",
             r"\b(?:md5|sha1)\s*\([^;]*(?:pass|pwd|secret|key)|hash\s*\(\s*[\"'](?:md5|sha1)[\"'][^;]*(?:pass|pwd|secret|key)",
             "Fast unsalted hashes are brute-forced in seconds. Use password_hash() for passwords and "
             "hash_hkdf()/hash_pbkdf2('sha256', ..., 600000) for key derivation."),
    LineRule("PHP-007", "medium", "Weak signature digest",
             r"OPENSSL_ALGO_(?:MD4|MD5|SHA1|DSS1)\b|[\"']digest_alg[\"']\s*=>\s*[\"'](?:md5|sha1)[\"']",
             "Use OPENSSL_ALGO_SHA256 or stronger."),
    LineRule("PHP-008", "medium", "Private key exported without a passphrase",
             r"openssl_pkey_export(?:_to_file)?\s*\(\s*[^,;]+,\s*[^,;)]+\s*(?:\)|,\s*(?:null|NULL|[\"']{2})\s*[,)])",
             "The PEM is written unencrypted. Pass a passphrase (from a secret store) or keep the "
             "key in a KMS/HSM; at minimum write it with 0600 permissions.", confidence="REVIEW"),
    LineRule("PHP-009", "high", "Private key / secret printed or logged",
             r"\b(?:echo|print|printf|print_r|var_dump|var_export|error_log|syslog)\b[^;]*\$\w*(?:priv|private|secret|pkey|passphrase)",
             "Key material written to stdout/logs ends up in terminal scrollback, CI logs or log "
             "aggregation, outside the key's own protection."),
    LineRule("PHP-010", "medium", "mcrypt (removed in PHP 7.2)",
             r"\bmcrypt_\w+\s*\(",
             "mcrypt is unmaintained and removed from PHP. Migrate to openssl_* or sodium_*."),
    LineRule("PHP-011", "medium", "Key file written without restricting permissions",
             r"file_put_contents\s*\([^;]*(?:key|pem|\.p12|secret)",
             "The file is created with the process umask (often 0644, world-readable). chmod($path, "
             "0600) immediately (or create it with umask(0077)).",
             file_suppress=r"\bchmod\s*\([^;]*0?[46]00\b|\bumask\s*\(\s*0?077\s*\)", confidence="REVIEW"),
    LineRule("PHP-012", "high", "TLS verification disabled",
             r"CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0)\b|CURLOPT_SSL_VERIFYHOST\s*,\s*(?:false|0)\b|"
             r"[\"']verify_peer(?:_name)?[\"']\s*=>\s*false",
             "Any MITM can read/alter the traffic (including keys or credentials being sent)."),
    LineRule("PHP-013", "low", "Non-constant-time comparison of a MAC/hash",
             r"(?:hash_hmac|md5|sha1|hash)\s*\([^;]*\)\s*(?:==|!=|===|!==)|(?:==|!=|===|!==)\s*(?:hash_hmac|md5|sha1|hash)\s*\(",
             "Use hash_equals() so the comparison time doesn't leak how many bytes matched."),
    LineRule("PHP-014", "medium", "crypt() with a weak or missing salt scheme",
             r"\bcrypt\s*\(\s*[^,;]+,\s*[\"'](?!\$2[aby]\$|\$argon2|\$6\$|\$5\$)",
             "DES/MD5 crypt schemes are weak. Use password_hash()."),
    LineRule("PHP-015", "low", "CBC encryption without visible MAC",
             r"[\"']aes-\d+-cbc[\"']",
             "Unauthenticated CBC is malleable. Use aes-256-gcm, or encrypt-then-MAC with hash_hmac('sha256').",
             file_suppress=r"hash_hmac\s*\(", confidence="REVIEW"),
]

# ── Bouncy Castle inventory ────────────────────────────────────────────────

_BC_ARTIFACT = re.compile(
    r"(?P<artifact>bc(?:-fips|pkix-fips|tls-fips|mail-fips|pg-fips|jsse-fips|prov(?:-ext)?-jdk\w+|pkix-jdk\w+|"
    r"tls-jdk\w+|util-jdk\w+|pg-jdk\w+|mail-jdk\w+))-(?P<version>\d+(?:\.\d+)*)\.jar$"
)
_POM_DEP = re.compile(
    r"<artifactId>\s*(?P<artifact>bc[\w-]*)\s*</artifactId>\s*(?:<[^>]+>[^<]*</[^>]+>\s*)*?"
    r"<version>\s*(?P<version>[\w.${}-]+)\s*</version>", re.S)
_GRADLE_DEP = re.compile(r"[\"']org\.bouncycastle:(?P<artifact>bc[\w-]*):(?P<version>[\w.-]+)[\"']")


def _vtuple(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:4])


def bc_inventory(root: Path) -> list[tuple[str, str, Path, int]]:
    """(artifact, version, file, line) for every Bouncy Castle jar/dependency."""
    found = []
    for path in root.rglob("*"):
        if not path.is_file() or any(p in _SKIP_DIRS for p in path.parts):
            continue
        name = path.name
        m = _BC_ARTIFACT.search(name)
        if m and name.endswith(".jar"):
            found.append((m.group("artifact"), m.group("version"), path, 1))
            continue
        if name in ("pom.xml", "build.gradle", "build.gradle.kts", "ivy.xml") or name.endswith((".gradle", "libs.versions.toml")):
            text = read_text_safe(path)
            for rx in (_POM_DEP, _GRADLE_DEP):
                for dm in rx.finditer(text):
                    found.append((dm.group("artifact"), dm.group("version"), path, text.count("\n", 0, dm.start()) + 1))
    return found


def _iter(root: Path, exts: tuple[str, ...]):
    for path in root.rglob("*"):
        if path.is_file() and path.suffix in exts and not any(p in _SKIP_DIRS for p in path.parts):
            yield path


def scan_java(root: Path) -> list[Finding]:
    """JC-0xx come from the javalang AST pass (checks/java_crypto_ast.py),
    which follows constants, fields, locals and method parameters to each
    sink. Files it can't parse (Kotlin, syntax errors) get the line rules."""
    from checks import java_crypto_ast

    findings: list[Finding] = []
    java_texts: dict[Path, str] = {path: read_text_safe(path) for path in _iter(root, (".java", ".kt"))}
    ast_findings, facts = java_crypto_ast.scan(root, java_texts)
    findings += ast_findings
    for path, text in java_texts.items():
        rules = secrets.secret_rules() + ([] if path in facts.parsed else JAVA_RULES)
        findings += scan_text(text, rules, rel(path, root), "c")
    findings += _bc_project_checks(root, java_texts, facts)
    return findings


def _bc_project_checks(root: Path, java_texts: dict[Path, str], facts) -> list[Finding]:
    unparsed = {p: t for p, t in java_texts.items() if p not in facts.parsed}
    findings: list[Finding] = []
    inv = bc_inventory(root)
    fips = [i for i in inv if "fips" in i[0]]
    non_fips = [i for i in inv if "fips" not in i[0]]
    if inv:
        summary = ", ".join(sorted({f"{a} {v}" for a, v, _, _ in inv}))
        first = inv[0]
        findings.append(make_finding(
            "JC-INV-001", "info", f"Bouncy Castle components: {summary}",
            "Inventory of every Bouncy Castle jar/dependency found. Confirm each is the version you "
            "expect to ship and that only one provider family (FIPS or non-FIPS) is on the classpath.",
            rel(first[2], root), first[3]))

    # Everything else (scripts, java.security, properties, Dockerfiles) can
    # carry the approved-only switch or provider config too.
    other_text = ""
    for path in root.rglob("*"):
        if path.is_file() and not any(p in _SKIP_DIRS for p in path.parts) and path.suffix in (
                ".properties", ".security", ".sh", ".conf", ".yml", ".yaml", ".xml", ".env", ".cfg", ".json") \
                or path.name in ("Dockerfile", "java.security", "jvm.config"):
            other_text += read_text_safe(path)
    all_java = "\n".join(java_texts.values())
    code_uses_fips = re.search(r"BouncyCastleFipsProvider|\"BCFIPS\"|org\.bouncycastle\.crypto\.fips", all_java)

    if fips or code_uses_fips:
        approved = re.search(r"setApprovedOnlyMode\s*\(\s*true\s*\)", all_java) or \
            re.search(r"org\.bouncycastle\.fips\.approved_only\s*[=:]\s*[\"']?true", all_java + other_text)
        anchor = _first_match(root, java_texts, r"BouncyCastleFipsProvider") or ((fips[0][2], fips[0][3]) if fips else None)
        if not approved and anchor:
            findings.append(make_finding(
                "JC-FIPS-001", "medium", "BC FIPS approved-only mode not enforced",
                "Without CryptoServicesRegistrar.setApprovedOnlyMode(true) or "
                "-Dorg.bouncycastle.fips.approved_only=true, the module happily runs non-approved "
                "algorithms -- the application isn't operating in a FIPS-approved mode just because "
                "bc-fips is on the classpath. Confirm how approved-only is enabled at deploy time.",
                rel(anchor[0], root), anchor[1], "REVIEW"))
        if non_fips and fips:
            a, v, p, line = non_fips[0]
            findings.append(make_finding(
                "JC-FIPS-002", "high", f"Non-FIPS Bouncy Castle ({a} {v}) alongside bc-fips",
                "bcprov/bcpkix (non-FIPS) and bc-fips share package names; whichever loads first wins, "
                "and anything using the \"BC\" provider runs unvalidated crypto. Replace every non-FIPS "
                "BC artifact with its -fips counterpart (bcpkix-fips, bctls-fips, bcpg-fips...).",
                rel(p, root), line))
        bc_uses = list(facts.bc_provider_uses)
        for path, text in unparsed.items():
            for m in re.finditer(r"new\s+BouncyCastleProvider\s*\(|getInstance\([^;]*,\s*\"BC\"\s*\)|"
                                 r"BouncyCastleProvider\.PROVIDER_NAME", mask_comments(text, "c")):
                bc_uses.append((path, text.count("\n", 0, m.start()) + 1, m.group(0)))
        for path, line, what in bc_uses:
            findings.append(make_finding(
                "JC-FIPS-003", "high", "Non-FIPS Bouncy Castle provider used in a FIPS project",
                f"{what} uses the non-validated \"BC\" provider instead of \"BCFIPS\".",
                rel(path, root), line))
        add = _first_match(root, java_texts, r"Security\.addProvider\s*\(\s*new\s+BouncyCastleFipsProvider")
        if add and not re.search(r"insertProviderAt\s*\([^;]*BouncyCastleFipsProvider|security\.provider\.1\s*=\s*\S*BouncyCastleFipsProvider",
                                 all_java + other_text):
            unpinned = facts.unpinned_getinstance + len(re.findall(
                r"(?:Cipher|KeyGenerator|KeyPairGenerator|Signature|MessageDigest|Mac|SecureRandom|"
                r"KeyFactory|SecretKeyFactory|KeyAgreement|KeyStore)\.getInstance\(\s*\"[^\"]+\"\s*\)",
                "\n".join(unparsed.values())))
            if unpinned:
                findings.append(make_finding(
                    "JC-FIPS-004", "medium", f"BCFIPS added at lowest priority; {unpinned} getInstance() call(s) don't name a provider",
                    "Security.addProvider() appends BCFIPS after SunJCE/SunRsaSign, so getInstance(\"AES/GCM/NoPadding\") "
                    "without a provider argument resolves to the JDK's non-validated implementation. Use "
                    "Security.insertProviderAt(new BouncyCastleFipsProvider(), 1), configure java.security, "
                    "or pass \"BCFIPS\" explicitly.",
                    rel(add[0], root), add[1], "REVIEW"))
        ks_at = facts.keystore_types[0][:2] if facts.keystore_types else \
            _first_match(root, unparsed, r"KeyStore\.getInstance\(\s*\"(?:JKS|JCEKS|PKCS12)\"")
        if ks_at:
            findings.append(make_finding(
                "JC-FIPS-007", "low", "Non-FIPS keystore type in a FIPS project",
                "JKS/JCEKS use non-approved protection; PKCS12 under BC FIPS needs care. BCFKS is the "
                "FIPS keystore format.", rel(ks_at[0], root), ks_at[1], "REVIEW"))

    for a, v, p, line in fips:
        if a == "bc-fips":
            vt = _vtuple(v)
            if vt and vt < (1, 0, 2, 4):
                findings.append(make_finding(
                    "JC-FIPS-005", "medium", f"bc-fips {v} affected by CVE-2022-45146",
                    "On Java 13+, BC-FJA before 1.0.2.4 can zero temporary keys while they're still in "
                    "use (errors / possible information loss). Upgrade.", rel(p, root), line))
            if vt and vt[0] < 2:
                findings.append(make_finding(
                    "JC-FIPS-006", "medium", f"bc-fips {v} is a FIPS 140-2 module",
                    "BC-FJA 1.x is validated under FIPS 140-2; NIST moved FIPS 140-2 certificates to the "
                    "historical list on 2026-09-21, so it can no longer be cited for new federal "
                    "procurements. Check the module's CMVP status and plan the move to bc-fips 2.x "
                    "(FIPS 140-3).", rel(p, root), line, "REVIEW"))
    for a, v, p, line in non_fips:
        if a.startswith(("bcprov", "bcpkix", "bcutil", "bctls")):
            vt = _vtuple(v)
            if vt and vt < (1, 78):
                findings.append(make_finding(
                    "JC-FIPS-008", "medium", f"{a} {v} has known CVEs",
                    "Bouncy Castle (non-FIPS) before 1.78 is affected by CVE-2024-29857, CVE-2024-30171 "
                    "(RSA timing side channel) and CVE-2024-30172; before 1.74 also CVE-2023-33201 (LDAP "
                    "injection). Upgrade to the latest release.", rel(p, root), line))
    return findings


def _first_match(root: Path, texts: dict[Path, str], pattern: str) -> Optional[tuple[Path, int]]:
    rx = re.compile(pattern)
    for path, text in texts.items():
        m = rx.search(mask_comments(text, "c"))
        if m:
            return path, text.count("\n", 0, m.start()) + 1
    return None


def scan_php(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in _iter(root, (".php", ".phtml", ".inc")):
        text = read_text_safe(path)
        findings += scan_text(text, PHP_RULES + secrets.secret_rules(), rel(path, root), "hcl")
    return findings
