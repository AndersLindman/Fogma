// Fogma.js

export class FogmaKEM {
    constructor(params, options = {}) {
        this.params = params;
        this.seedBytesCount = options.seedBytes || 32; // 256-bit default seed
    }

    /**
     * Asynchronously generates a new set of Blum primes and GM parameters.
     * Cached or generated once per session.
     */
    static async generate(primeBits = 1024, mrRounds = 40) {
        const p = getLargePrime(primeBits, mrRounds);
        let q;
        do {
            q = getLargePrime(primeBits, mrRounds);
        } while (q === p);

        const N = p * q;
        const x = findQNR(p, q, N);
        const sigmaSecret = crypto.getRandomValues(new Uint8Array(32));
        const xSelect = 1n ^ x;

        return new FogmaKEM({ p, q, N, x, xSelect, sigmaSecret });
    }

    /**
     * Bob encapsulates a random session seed K into a ciphertext vector.
     */
    async encapsulate() {
        const K_seed = crypto.getRandomValues(new Uint8Array(this.seedBytesCount));
        const numBits = this.seedBytesCount * 8;

        const bobCoins = await deriveCoins(K_seed, numBits, this.params.N);
        const ciphertexts = encryptBitsWithCoins(K_seed, bobCoins, this.params.N, this.params.xSelect);
        const sessionKey = await deriveFinalSessionKey(K_seed, ciphertexts);

        return {
            ciphertexts,
            sessionKey
        };
    }

    /**
     * Alice decapsulates the ciphertext vector, verifies via FO transform,
     * and returns the shared session key (with implicit rejection on tampering).
     */
    async decapsulate(ciphertexts) {
        const numBits = this.seedBytesCount * 8;
        const K_prime = decryptCiphertexts(ciphertexts, this.params.p, numBits);

        const aliceCoins = await deriveCoins(K_prime, numBits, this.params.N);
        const isValid = reencryptAndVerify(K_prime, aliceCoins, ciphertexts, this.params.N, this.params.xSelect);

        let sessionKey;
        if (isValid) {
            sessionKey = await deriveFinalSessionKey(K_prime, ciphertexts);
        } else {
            // Implicit rejection fallback
            sessionKey = await deriveFinalSessionKey(this.params.sigmaSecret, ciphertexts);
        }

        return {
            sessionKey,
            isValid
        };
    }
}

// ============================================================
// INTERNAL HELPER FUNCTIONS
// ============================================================

const enc = new TextEncoder();

function modPow(base, exp, mod) {
    let res = 1n;
    base = base % mod;
    while (exp > 0n) {
        if (exp & 1n) res = (res * base) % mod;
        base = (base * base) % mod;
        exp >>= 1n;
    }
    return res;
}

function gcd(a, b) {
    while (b !== 0n) {
        const t = a % b;
        a = b;
        b = t;
    }
    return a;
}

function cryptoRandomBigInt(bits) {
    const bytes = new Uint8Array(Math.ceil(bits / 8));
    crypto.getRandomValues(bytes);
    let value = 0n;
    for (const byte of bytes) {
        value = (value << 8n) | BigInt(byte);
    }
    return value;
}

function bytesToBigIntBE(bytes, start, length) {
    let value = 0n;
    const end = start + length;
    for (let i = start; i < end; i++) {
        value = (value << 8n) | BigInt(bytes[i]);
    }
    return value;
}

function bytesToHex(bytes) {
    return Array.from(bytes).map(b => b.toString(16).padStart(2, "0")).join("");
}

const SMALL_PRIMES = [3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n, 41n, 43n, 47n, 53n, 59n, 61n, 67n, 71n, 73n, 79n, 83n, 89n, 97n, 101n, 103n, 107n, 109n, 113n, 127n, 131n, 137n, 139n, 149n];

function isPrime(n, rounds) {
    if (n < 2n) return false;
    if ((n & 1n) === 0n) return n === 2n;
    for (const p of SMALL_PRIMES) {
        if (n === p) return true;
        if (n % p === 0n) return false;
    }
    let d = n - 1n;
    let s = 0n;
    while ((d & 1n) === 0n) {
        d >>= 1n;
        s++;
    }
    const nBits = n.toString(2).length;
    for (let i = 0; i < rounds; i++) {
        const a = 2n + (cryptoRandomBigInt(nBits) % (n - 4n));
        let x = modPow(a, d, n);
        if (x === 1n || x === n - 1n) continue;
        let composite = true;
        for (let j = 1n; j < s; j++) {
            x = (x * x) % n;
            if (x === n - 1n) { composite = false; break; }
            if (x === 1n) break;
        }
        if (composite) return false;
    }
    return true;
}

function getLargePrime(bits, rounds) {
    while (true) {
        let p = cryptoRandomBigInt(bits);
        p |= (1n << BigInt(bits - 1));
        p |= 3n; // Blum prime condition: p = 3 mod 4
        if (isPrime(p, rounds)) return p;
    }
}

function findQNR(p, q, N) {
    const bits = N.toString(2).length;
    while (true) {
        const x = 2n + (cryptoRandomBigInt(bits) % (N - 4n));
        if (gcd(x, N) !== 1n) continue;
        const legP = modPow(x, (p - 1n) / 2n, p);
        const legQ = modPow(x, (q - 1n) / 2n, q);
        if (legP === p - 1n && legQ === q - 1n) return x;
    }
}

async function aesCtrStream(seedBytes, length) {
    const salt = enc.encode("Fogma-PRG-Salt-v1");
    const ikm = await crypto.subtle.importKey("raw", seedBytes, "HKDF", false, ["deriveKey", "deriveBits"]);
    const aesKey = await crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt, info: enc.encode("Fogma-PRG-Key-v1") },
        ikm,
        { name: "AES-CTR", length: 256 },
        false,
        ["encrypt"]
    );
    const counterBuf = await crypto.subtle.deriveBits(
        { name: "HKDF", hash: "SHA-256", salt, info: enc.encode("Fogma-PRG-Counter-v1") },
        ikm,
        16 * 8
    );
    const counter = new Uint8Array(counterBuf);
    const zeros = new Uint8Array(length);
    const keystream = await crypto.subtle.encrypt({ name: "AES-CTR", counter, length: 64 }, aesKey, zeros);
    return new Uint8Array(keystream);
}

async function deriveCoins(seedBytes, numCoins, N) {
    const byteLen = Math.ceil(N.toString(2).length / 8) + 8;
    const safetyCoins = numCoins + 8;
    const stream = await aesCtrStream(seedBytes, safetyCoins * byteLen);
    const coins = [];
    let offset = 0;
    while (coins.length < numCoins && offset + byteLen <= stream.length) {
        let r = bytesToBigIntBE(stream, offset, byteLen) % N;
        offset += byteLen;
        if (r > 1n && gcd(r, N) === 1n) coins.push(r);
    }
    return coins;
}

async function deriveFinalSessionKey(seedBytes, ciphertexts) {
    const seedHash = await crypto.subtle.digest("SHA-256", seedBytes);
    const first = ciphertexts[0].toString(16);
    const last = ciphertexts[ciphertexts.length - 1].toString(16);
    const transcript = enc.encode(ciphertexts.length + "|" + first + "|" + last);
    const transcriptHash = await crypto.subtle.digest("SHA-256", transcript);

    const combined = new Uint8Array(seedHash.byteLength + transcriptHash.byteLength);
    combined.set(new Uint8Array(seedHash), 0);
    combined.set(new Uint8Array(transcriptHash), seedHash.byteLength);

    const finalHash = await crypto.subtle.digest("SHA-256", combined);
    return bytesToHex(new Uint8Array(finalHash));
}

function encryptBitsWithCoins(seedBytes, coins, N, xSelect) {
    const numBits = seedBytes.length * 8;
    const ciphertexts = new Array(numBits);
    for (let i = 0; i < numBits; i++) {
        const byteIdx = Math.floor(i / 8);
        const bitIdx = 7 - (i % 8);
        const bit = (seedBytes[byteIdx] >> bitIdx) & 1;
        const r2 = (coins[i] * coins[i]) % N;
        const mask = -BigInt(bit);
        const x_b = 1n ^ (xSelect & mask);
        ciphertexts[i] = (r2 * x_b) % N;
    }
    return ciphertexts;
}

function decryptCiphertexts(ciphertexts, p, numBits) {
    const seed = new Uint8Array(numBits / 8);
    const exponent = (p - 1n) / 2n;
    for (let i = 0; i < numBits; i++) {
        const legP = modPow(ciphertexts[i], exponent, p);
        const bit = Number(legP !== 1n);
        const byteIdx = Math.floor(i / 8);
        const bitIdx = 7 - (i % 8);
        seed[byteIdx] |= bit << bitIdx;
    }
    return seed;
}

function reencryptAndVerify(K_prime, coins, ciphertexts, N, xSelect) {
    const numBits = ciphertexts.length;
    let validBits = 0n;
    for (let i = 0; i < numBits; i++) {
        const byteIdx = Math.floor(i / 8);
        const bitIdx = 7 - (i % 8);
        const bit = (K_prime[byteIdx] >> bitIdx) & 1;
        const r2 = (coins[i] * coins[i]) % N;
        const mask = -BigInt(bit);
        const x_b = 1n ^ (xSelect & mask);
        const cRe = (r2 * x_b) % N;
        validBits += BigInt(cRe === ciphertexts[i]);
    }
    return validBits === BigInt(numBits);
}
