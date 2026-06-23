// BIP-39 mnemonic encode/decode + seed derivation. Byte-faithful port of
// the iOS BIP39.swift so a holder's 24-word phrase + passphrase derives
// the SAME 32-byte ML-DSA-65 master seed on Android as on iOS, and so a
// phrase written down on one platform restores on the other.
//
// Master-seed derivation (matches IdentitySandwich.swift):
//
//   entropy (32 bytes)  <->  24-word mnemonic   (this file: checksum =
//                                                 top 8 bits of SHA-256)
//   bip39_seed = PBKDF2-HMAC-SHA512(mnemonic, "mnemonic" + passphrase,
//                                   c = 2048, dkLen = 64)
//   mldsa_seed = bip39_seed[0..32]
//
// iOS normalizes both the mnemonic and the passphrase with NFKC
// (`precomposedStringWithCompatibilityMapping`); we match that here even
// though it differs from BIP-39's NFKD (the two are identical for ASCII,
// which covers the English wordlist + ASCII passphrases). The PBKDF2 is
// hand-rolled over javax.crypto.Mac (HmacSHA512) so we control the exact
// password/salt UTF-8 bytes, mirroring Hkdf.kt.

package com.elabify.core

import java.security.MessageDigest
import java.text.Normalizer
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

sealed class Bip39Error(message: String) : Exception(message) {
    class BadEntropyLength(val got: Int) : Bip39Error("expected 32 bytes of entropy, got $got")
    class WrongWordCount(val got: Int) : Bip39Error("expected 24 words, got $got")
    class UnknownWord(val word: String) : Bip39Error("not in BIP-39 wordlist: $word")
    class BadChecksum : Bip39Error("BIP-39 checksum mismatch")
}

object Bip39 {
    private val INDEX_OF: Map<String, Int> =
        BIP39_WORDLIST.withIndex().associate { (i, w) -> w to i }

    /** Encode 32 bytes of entropy as a 24-word BIP-39 English mnemonic.
     *  Checksum = top 8 bits of SHA-256(entropy) (256-bit entropy -> 8-bit
     *  checksum -> 264 bits -> 24 * 11-bit indices). */
    fun mnemonicFromEntropy(entropy: ByteArray): List<String> {
        if (entropy.size != 32) throw Bip39Error.BadEntropyLength(entropy.size)
        val checksum = MessageDigest.getInstance("SHA-256").digest(entropy)[0]
        val combined = entropy + byteArrayOf(checksum) // 33 bytes = 264 bits
        val words = ArrayList<String>(24)
        var acc = 0
        var bits = 0
        for (b in combined) {
            acc = (acc shl 8) or (b.toInt() and 0xff)
            bits += 8
            while (bits >= 11) {
                bits -= 11
                val idx = (acc ushr bits) and 0x7ff
                words.add(BIP39_WORDLIST[idx])
            }
        }
        return words
    }

    /** Decode a 24-word mnemonic back to 32 bytes of entropy, validating
     *  the checksum. */
    fun entropyFromMnemonic(words: List<String>): ByteArray {
        if (words.size != 24) throw Bip39Error.WrongWordCount(words.size)
        var acc = 0
        var bits = 0
        val combined = ByteArray(33)
        var outPos = 0
        for (w in words) {
            val idx = INDEX_OF[w] ?: throw Bip39Error.UnknownWord(w)
            acc = (acc shl 11) or idx
            bits += 11
            while (bits >= 8) {
                bits -= 8
                combined[outPos++] = ((acc ushr bits) and 0xff).toByte()
            }
        }
        val entropy = combined.copyOfRange(0, 32)
        val expected = MessageDigest.getInstance("SHA-256").digest(entropy)[0]
        if (combined[32] != expected) throw Bip39Error.BadChecksum()
        return entropy
    }

    fun isValidWord(word: String): Boolean = INDEX_OF.containsKey(word)

    /** The canonical 64-byte BIP-39 seed (NFKC-normalized, as iOS does). */
    fun derivedSeed(words: List<String>, passphrase: String): ByteArray =
        derivedSeed(words.joinToString(" "), passphrase)

    fun derivedSeed(mnemonic: String, passphrase: String): ByteArray {
        val normMnemonic = Normalizer.normalize(mnemonic, Normalizer.Form.NFKC)
        val normPassphrase = Normalizer.normalize(passphrase, Normalizer.Form.NFKC)
        val password = normMnemonic.toByteArray(Charsets.UTF_8)
        val salt = ("mnemonic" + normPassphrase).toByteArray(Charsets.UTF_8)
        return pbkdf2HmacSha512(password, salt, iterations = 2048, dkLen = 64)
    }

    /** The 32-byte ML-DSA-65 master seed = first 32 bytes of the BIP-39
     *  seed. Feed this to pq-crypto-core's mldsa65_public_key. */
    fun masterSeed(words: List<String>, passphrase: String): ByteArray =
        derivedSeed(words, passphrase).copyOfRange(0, 32)

    private fun pbkdf2HmacSha512(
        password: ByteArray,
        salt: ByteArray,
        iterations: Int,
        dkLen: Int,
    ): ByteArray {
        val mac = Mac.getInstance("HmacSHA512")
        mac.init(SecretKeySpec(password, "HmacSHA512"))
        val hLen = mac.macLength // 64
        val blocks = (dkLen + hLen - 1) / hLen
        val out = ByteArray(blocks * hLen)
        var offset = 0
        for (i in 1..blocks) {
            // U1 = PRF(password, salt || INT_32_BE(i))
            mac.update(salt)
            mac.update(byteArrayOf((i ushr 24).toByte(), (i ushr 16).toByte(), (i ushr 8).toByte(), i.toByte()))
            var u = mac.doFinal()
            val t = u.copyOf()
            for (c in 2..iterations) {
                u = mac.doFinal(u)
                for (k in t.indices) t[k] = (t[k].toInt() xor u[k].toInt()).toByte()
            }
            System.arraycopy(t, 0, out, offset, hLen)
            offset += hLen
        }
        return out.copyOfRange(0, dkLen)
    }
}
