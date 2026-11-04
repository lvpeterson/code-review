# crypto -- Java (JCA + Bouncy Castle FIPS) and PHP key-management review

Runs independently of the application analyzers, so a plain-Java service
with BC FIPS jars and no Spring, or a lone PHP key-generation script, still
gets reviewed. Findings are project-wide and show up in the HTML report's
**Infrastructure** tab, mostly under **ISR05 Insecure Use of Cryptography**.

## java (`checks/crypto.py`)

Detected when there's any Bouncy Castle jar/dependency, or `.java`/`.kt`
code using `javax.crypto` / `java.security` / `org.bouncycastle` /
`SSLContext` / `KeyStore`.

JC rules run on a **javalang AST** (`checks/java_crypto_ast.py`), not line
regex. The value reaching each sink is resolved through:

- constants in any class (`Config.TRANSFORM`), static imports, string concatenation
- fields, including ones assigned in a constructor and used in another method
- local variables (every assignment), ternaries, casts
- method parameters, by resolving the argument at every call site
  (`util.encrypt(data, FIXED_IV)` -> `new GCMParameterSpec(128, iv)`)
- return values of helpers (`getTransform() { return X; }`)
- `"..".getBytes()` / `.toCharArray()`, Base64/Hex decoding of literals
- byte arrays allocated but never filled (all-zero IV/key) vs. filled by
  `SecureRandom.nextBytes`
- the algorithm a `KeyPairGenerator` was created with (EC 256 is fine, RSA 1024 isn't)

Each finding's description ends with the chain it followed, e.g.
`Value resolved via parameter nonce of encryptGcm(), called from Service.java:8 <- via field Config.FIXED_IV (Config.java:5)`.
Comments are never matched. Files javalang can't parse (Kotlin, syntax
errors) fall back to the equivalent line regexes in `checks/crypto.py`.
If the analyzer itself throws on a file, that file also falls back.

| id | what |
|---|---|
| JC-001 | DES/3DES/RC4/RC2/Blowfish/IDEA ciphers |
| JC-002 | `/ECB/` mode (high), or bare `"AES"` (defaults to ECB) |
| JC-003 | RSA encryption without OAEP |
| JC-004 | MD5/SHA-1 digests, SHA1withRSA signatures, HmacMD5, PBKDF2WithHmacSHA1 |
| JC-005 | static / zero IV or GCM nonce |
| JC-006 | hardcoded `SecretKeySpec` key |
| JC-007 | `java.util.Random` / `Math.random` / `ThreadLocalRandom` in a method/class whose names involve keys, tokens, sessions, salts... (REVIEW) |
| JC-008 | SHA1PRNG; SecureRandom seeded with a constant or the clock |
| JC-009 | RSA/DSA < 2048, symmetric keys < 128 bits |
| JC-010 | `PBEWithMD5AndDES`-style schemes; PBKDF2 iterations < 100k |
| JC-011 | `checkServerTrusted`/`checkClientTrusted` that neither validates nor throws (incl. anonymous classes), `verify()` / lambdas returning true, `NoopHostnameVerifier`, `TrustAllStrategy` |
| JC-012 | `SSLContext` SSL/TLSv1/TLSv1.1 |
| JC-013 | hardcoded keystore / key passwords (`"changeit".toCharArray()`) |
| JC-014 | GCM tag < 128 bits |
| JC-015 | AES/CBC with no HMAC anywhere in the file (REVIEW) |
| JC-016 | keys / passwords logged (by declared type `PrivateKey`/`SecretKey`/`char[]`, `getEncoded()`/`getPrivate()`, or name) |
| JC-017 | constant salt passed to `PBEKeySpec` |

Project rules for **Bouncy Castle FIPS**. Jars are inventoried by filename
(`bc-fips-1.0.2.4.jar`) and from `pom.xml` / Gradle dependency declarations:

| id | what |
|---|---|
| JC-INV-001 | inventory of every BC artifact + version found (info, ISR10) |
| JC-FIPS-001 | BC FIPS present but approved-only mode never enabled (`CryptoServicesRegistrar.setApprovedOnlyMode(true)` or `-Dorg.bouncycastle.fips.approved_only=true` anywhere in code, scripts, properties, Dockerfiles, CI) -- REVIEW |
| JC-FIPS-002 | non-FIPS `bcprov`/`bcpkix` on the same classpath as `bc-fips` |
| JC-FIPS-003 | code using the non-FIPS `"BC"` provider / `new BouncyCastleProvider()` in a FIPS project |
| JC-FIPS-004 | BCFIPS added with `addProvider` (lowest priority) while `getInstance()` calls don't name a provider -> they resolve to the JDK's non-validated providers |
| JC-FIPS-005 | bc-fips < 1.0.2.4 (CVE-2022-45146) |
| JC-FIPS-006 | bc-fips 1.x is a FIPS **140-2** module. 140-2 certs moved to the CMVP historical list on 2026-09-21, so plan for 2.x (140-3). REVIEW: confirm current status on the CMVP site |
| JC-FIPS-007 | JKS/JCEKS/PKCS12 keystores in a FIPS project (BCFKS is the FIPS format) |
| JC-FIPS-008 | non-FIPS bcprov/bcpkix < 1.78 (CVE-2024-29857/30171/30172; < 1.74 also CVE-2023-33201) |

Versions and dates above are encoded in `checks/crypto.py`'s docstring.
Re-verify them before quoting in a report.

## php

Detected when any `.php`/`.phtml`/`.inc` uses OpenSSL, sodium, `rand`/`mt_rand`, `mcrypt`, `crypt`, `password_hash` or `hash_hmac`.

| id | what |
|---|---|
| PHP-001 | `rand`/`mt_rand`/`uniqid`/`str_shuffle`/`lcg_value`/`microtime` in files that generate keys/tokens/secrets |
| PHP-002 | `mt_srand`/`srand` (reproducible sequence) |
| PHP-003 | `private_key_bits` < 2048 |
| PHP-004 | ECB / DES / 3DES / RC4 / Blowfish / RC2 cipher names |
| PHP-005 | literal IV variable, or a literal 5th argument to `openssl_encrypt/decrypt` |
| PHP-006 | md5/sha1 over passwords/keys |
| PHP-007 | MD5/SHA1 signature digests |
| PHP-008 | `openssl_pkey_export` without a passphrase |
| PHP-009 | private keys / secrets echoed or logged |
| PHP-010 | mcrypt |
| PHP-011 | key files written without `chmod 0600` / `umask(0077)` |
| PHP-012 | cURL / stream TLS verification disabled |
| PHP-013 | `==` comparison of a MAC/hash (use `hash_equals`) |
| PHP-014 | `crypt()` with DES/MD5 salt schemes |
| PHP-015 | AES-CBC with no `hash_hmac` in the file |

## Still manual

- Values from outside the source tree (properties files, env vars, Spring
  `@Value`, a keystore on disk) resolve to "unknown" and are not flagged;
  check where those come from. Inherited fields and overloaded methods are
  matched by name/arity only.

- How the JVM is actually launched in each environment (approved-only flag, `java.security` provider order, `-Djava.security.properties`).
- Whether the deployed jars match the ones in the repo (container images, app-server lib dirs).
- Key lifecycle: where generated keys are stored, who can read them, rotation, and whether the PHP script's output ever lands in logs/artifacts.
- Entropy source and DRBG configuration under FIPS (`CryptoServicesRegistrar.setSecureRandom`).
