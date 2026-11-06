# Fogma: FO-Transformed Goldwasser-Micali KEM

A single-file, educational demonstration of a **Fujisaki-Okamoto-transformed Goldwasser-Micali KEM** using:

- Goldwasser-Micali probabilistic encryption
- Quadratic residuosity modulo an RSA-style modulus
- Blum primes `p ≡ q ≡ 3 mod 4`
- FO deterministic coin derivation
- FO re-encryption verification
- Implicit rejection
- Constant-time-style FO verification accumulator
- Bulk AES-CTR deterministic randomness generation
- WebCrypto HKDF / SHA-256 / AES-GCM-compatible key derivation

This project is intended as a **teaching and experimentation tool**, not as production cryptography.

> **WARNING:**  
> This code demonstrates cryptographic structure. It is **not audited**, and JavaScript `BigInt` arithmetic is **not guaranteed constant-time**. Do not use this to protect real data.

---

## Overview

Goldwasser-Micali encryption encrypts a single bit using the quadratic residuosity problem:

```text
C = x^b * r^2 mod N
```

where:

- `N = p * q`
- `x` is a quadratic non-residue modulo `N` with Jacobi symbol `+1`
- `r` is a random unit modulo `N`
- `b` is the plaintext bit

Because GM encrypts only one bit per ciphertext, sending a 256-bit symmetric seed requires 256 ciphertexts. This is pedagogically useful but extremely inefficient.

This demo upgrades GM using the **Fujisaki-Okamoto transform**, making it resistant to active chosen-ciphertext tampering by:

1. Deriving encryption randomness deterministically from the seed.
2. Encrypting the seed.
3. Decrypting the ciphertext.
4. Re-encrypting the decrypted seed.
5. Checking that the re-encrypted ciphertext matches the received ciphertext.
6. If the check fails, silently deriving a fallback pseudorandom key instead of returning an error.

This is the same structural idea used in many modern KEM constructions: decryption failure must not become an oracle.

---

## Security Status

This implementation is for **education and demonstration only**.

### Not suitable for production because:

- JavaScript `BigInt` operations are not guaranteed constant-time.
- The browser timing environment is not suitable for high-assurance cryptography.
- The GM public key is not authenticated; a real protocol would need signatures or an authenticated key exchange.
- Goldwasser-Micali has enormous ciphertext expansion.
- This implementation has not been independently reviewed or audited.

### For practical key exchange, use:

- X25519
- ECDH P-256 / P-384
- HPKE
- ML-KEM / Kyber for post-quantum key encapsulation

---

## Features

- Self-contained single-file HTML demo
- No build step
- No external dependencies
- Uses browser WebCrypto:
  - `crypto.getRandomValues()`
  - HKDF
  - SHA-256
  - AES-CTR for bulk deterministic coin generation
- Generates Alice’s GM parameters once and reuses them
- Uses a 2048-bit GM modulus by default
- Uses a 256-bit seed suitable for deriving AES-256 key material
- Demonstrates honest decapsulation
- Demonstrates active tampering and implicit rejection
- Avoids early termination during FO verification

---

## Quick Start

Save the demo as:

```text
index.html
```

Then open it in a modern browser.

Some browsers restrict WebCrypto to secure contexts. If `crypto.subtle` is unavailable, serve the file locally:

```bash
python3 -m http.server
```

Then open:

```text
http://localhost:8000
```

Click:

- **Run Honest Exchange** to perform a normal encapsulation/decapsulation.
- **Run Tampered CCA Exchange** to modify one ciphertext in transit and observe FO rejection.

---

## What the Demo Shows

### Honest Exchange

1. Alice generates or reuses GM parameters:
   - Blum primes `p` and `q`
   - modulus `N = p * q`
   - quadratic non-residue `x`
   - implicit rejection secret `sigmaSecret`

2. Bob generates a random 256-bit seed `K`.

3. Bob derives deterministic GM coins from `K`.

4. Bob encrypts every bit of `K` using GM.

5. Alice decrypts the ciphertexts to recover `K'`.

6. Alice re-derives the deterministic coins from `K'`.

7. Alice re-encrypts `K'` and verifies that the re-encryption matches the received ciphertexts.

8. If verification succeeds, both parties derive the same session key.

### Tampered Exchange

The tamper test multiplies the first ciphertext by `4`:

```text
C' = 4 * C mod N
```

Because `4` is a quadratic residue, this does **not** change the decrypted bit. This demonstrates GM’s malleability.

However, the FO re-encryption check detects that the received ciphertext no longer matches the deterministic re-encryption of the decrypted seed.

Alice then performs **implicit rejection**:

- She does not return an error.
- She does not reveal whether the ciphertext was valid.
- She derives a pseudorandom fallback key using her private rejection secret.

Bob and Alice end up with different keys, but the attacker receives no explicit decryption failure oracle.

---

## Parameters

Default configuration:

```js
const PRIME_BITS = 1024;
const MR_ROUNDS = 40;
const SEED_BYTES = 32;
```

### Meaning

| Parameter | Default | Meaning | Notes |
|---|---:|---|---|
| `PRIME_BITS` | `1024` | Size of each GM prime | Produces a 2048-bit modulus `N`. |
| `MR_ROUNDS` | `40` | Miller-Rabin rounds | Practical for demo use. |
| `SEED_BYTES` | `32` | Size of encapsulated seed | 256-bit seed, suitable for AES-256 key derivation. |

### Tuning

For faster operation with approximately 128-bit symmetric security:

```js
const SEED_BYTES = 16;
```

This halves the number of GM ciphertexts.

For a stronger classical RSA-style modulus:

```js
const PRIME_BITS = 1536;
```

This gives a 3072-bit modulus, but will be significantly slower.

---

## Why This Variant Is Faster

The original browser implementation performed many slow operations per exchange:

- regenerated 1024-bit primes every run
- called HKDF once per encrypted bit
- performed many asynchronous WebCrypto calls
- used early-exit FO verification

This optimized version improves performance by:

### 1. Caching Alice’s GM key

Prime generation is expensive. The optimized version generates Alice’s parameters once and reuses them for subsequent exchanges.

### 2. Bulk deterministic coin derivation

Instead of:

```text
HKDF(seed, index 0)
HKDF(seed, index 1)
HKDF(seed, index 2)
...
HKDF(seed, index 255)
```

the optimized version derives a single AES-CTR keystream from the seed and parses it into GM randomness values.

This greatly reduces WebCrypto overhead.

### 3. Constant-time-style FO verification

The verification loop checks all ciphertexts and accumulates the result:

```js
validBits += BigInt(cRe === ciphertexts[i]);
```

It does not stop early when a mismatch is found.

This avoids leaking which ciphertext index failed.

### 4. Branchless GM plaintext selection

The code uses a bitwise mask to select between `1` and `x`:

```js
const mask = -BigInt(bit);
const x_b = 1n ^ (xSelect & mask);
```

This avoids obvious secret-dependent branches in the encryption path.

JavaScript still cannot guarantee constant-time behavior, but this avoids adding unnecessary high-level branching.

### 5. Fixed Miller-Rabin implementation bug

In an earlier variant, the Miller-Rabin value `d` was mutated inside the witness loop and not reset for later rounds. This version fixes that by using a fresh inner-loop value for each witness.

---

## Side-Channel Notes

This code avoids some protocol-level timing mistakes:

- no early decryption failure
- no early FO rejection
- no error oracle for malformed ciphertexts
- constant-time-style equality accumulation

However, this does **not** mean the implementation is fully side-channel resistant.

JavaScript `BigInt` operations may leak timing information through:

- multiplication
- modular reduction
- comparison
- bit length
- memory allocation
- engine optimizations

For real side-channel resistance, use native cryptographic primitives, such as:

- WebCrypto ECDH
- WebCrypto AES
- WebCrypto HKDF
- a vetted native library
- a vetted post-quantum KEM implementation

---

## Ciphertext Expansion

Goldwasser-Micali encrypts one bit per ciphertext.

With the default settings:

```text
256 ciphertexts × 2048-bit modulus
= 524,288 bits
= 65,536 bytes
= 64 KiB
```

So this KEM sends approximately **64 KiB** to encapsulate a **32-byte seed**.

This is the main reason GM is not used for practical key exchange.

---

## Mathematical Notes

### GM Public Key

Alice chooses Blum primes:

```text
p ≡ 3 mod 4
q ≡ 3 mod 4
N = p * q
```

She chooses `x` such that:

```text
Legendre(x, p) = -1
Legendre(x, q) = -1
```

Therefore:

```text
Jacobi(x, N) = +1
```

but `x` is not a quadratic residue modulo `N`.

### Encryption

For bit `b`:

```text
C = x^b * r^2 mod N
```

### Decryption

Alice computes the Legendre symbol modulo `p`:

```text
C^((p - 1) / 2) mod p
```

If the result is `1`, the bit is `0`.

If the result is `-1 mod p`, the bit is `1`.

### FO Transform

The FO transform makes the scheme CCA2-secure by making encryption deterministic from the seed and checking re-encryption:

```text
r = G(K)
C = Enc(K; r)
K' = Dec(C)
C' = Enc(K'; G(K'))

if C' == C:
    accept
else:
    implicitly reject
```

---

## Browser Requirements

Requires a browser with WebCrypto support for:

- `crypto.getRandomValues()`
- `crypto.subtle.importKey()`
- `crypto.subtle.deriveKey()`
- `crypto.subtle.deriveBits()`
- HKDF
- SHA-256
- AES-CTR

If AES-CTR is unavailable, the code falls back to slower per-index HKDF coin derivation.

---

## File Layout

Expected repository layout:

```text
README.md
index.html
```

The implementation is self-contained in `index.html`.

---

## Production Guidance

Do not use this code for production security.

For practical key encapsulation or key agreement, prefer:

- X25519
- ECDH P-256
- ECDH P-384
- HPKE
- ML-KEM / Kyber

These are dramatically faster, smaller, and supported by vetted native implementations.

---

## License

This project is dedicated to the public domain under the Creative Commons Zero v1.0 Universal license.

SPDX-License-Identifier: CC0-1.0

To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring rights to this software to the public domain worldwide.

This software is distributed without any warranty.

You should have received a copy of the CC0 Public Domain Dedication along with this software. If not, see:

<https://creativecommons.org/publicdomain/zero/1.0/>

---

## NO WARRANTY

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
