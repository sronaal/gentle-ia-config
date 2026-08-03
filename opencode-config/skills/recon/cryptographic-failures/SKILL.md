---
name: cryptographic-failures
description: "Trigger: crypto audit, weak cipher, TLS scan, padding oracle, ECB. Detect and exploit cryptographic weaknesses across web, API, and mobile targets."
license: Apache-2.0
metadata:
  author: "pentest-orchestrator"
  version: "1.0"
---

## Activation Contract

Load when the user asks to audit cryptography, test TLS, find weak ciphers, check for padding oracle, ECB mode, hash length extension, or JWT alg:none.

## Hard Rules

- Do NOT modify target systems' crypto configs — only detect and report.
- Use passive detection before active probing.
- Log all cipher strength findings with evidence (captured handshake, response).

## Decision Gates

| Target Type | Approach | Tools |
|-------------|----------|-------|
| TLS endpoint | Passive: cipher scan, cert analysis | testssl.sh, tls-client, openssl s_client |
| JWT token | Decode header, test alg confusion, kid injection | jwt_tool, custom Python |
| Cookie/token | ECB detection (copy-paste block test) | Burp Sequencer, custom script |
| Hash endpoint | Length extension test (SHA256/SHA1) | hash_extender, custom |
| Mobile app | KeyStore/Keychain audit, hardcoded keys | objection, radare2, MobSF |
| Custom crypto | Response analysis for ECB patterns | Custom Python / manual |

## Execution Steps

1. **TLS scan**: `testssl.sh --wide --cipher-per-proto <target>` or `openssl s_client -connect <target>:443 -tls1_2 -cipher ALL`
2. **JWT audit**: Decode JWT header → test `alg: none`, `alg: HS256` with public key, `kid` SQLi/path traversal, `jku`/`jwk` injection
3. **ECB detection**: Capture encrypted cookie/parameter → modify one block → observe if decryption succeeds in partial blocks
4. **Padding oracle**: Send modified ciphertext → observe error responses (padding vs MAC fail) → automate with padbuster or custom
5. **Hash length extension**: If `signature = H(secret + message)` format detected, extend with hash_extender
6. **Weak PRNG**: Collect consecutive session tokens → test predictability with Burp Sequencer
7. **Hardcoded keys**: Scan JS, APK, IPA, config files for base64-encoded keys, `-----BEGIN`, `private_key`, `api_secret`
8. **Self-signed cert**: Accept any cert → test MiTM resilience of API client

## Output Contract

Return findings list:
- **type**: tls_weak_cipher | jwt_alg_confusion | ecb_detection | padding_oracle | hash_extension | weak_prng | hardcoded_key | self_signed_accept
- **severity**: Critical / High / Medium / Low
- **evidence**: Captured handshake / JWT header / ciphertext blocks / stack trace
- **remediation**: Specific fix (e.g., "Disable TLS 1.0, remove alg:none support")
