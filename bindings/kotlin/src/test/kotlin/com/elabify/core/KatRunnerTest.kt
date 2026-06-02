// Cross-binding KAT runner. Drives the same test-vectors/*.kat.json corpus
// that the TypeScript reference + Swift binding pass, and asserts byte-
// equivalence for every vector against the Kotlin implementation.
//
// If even one vector fails, the Kotlin port disagrees with the TS
// reference on the wire format. That's the gate that makes any Kotlin
// change "M0-safe" before it can ship.

package com.elabify.core

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class KatRunnerTest {

    @Test
    fun fullCorpus() {
        val dir = locateVectorDir()
        val files = dir.listFiles { f -> f.isFile && f.name.endsWith(".kat.json") }
            ?.sortedBy { it.name }
            ?: error("test-vectors/ is empty under ${dir.absolutePath}")

        assertTrue(files.isNotEmpty(), "no .kat.json files found in ${dir.absolutePath}")

        var totalPass = 0
        var totalFail = 0
        val failures = mutableListOf<String>()

        for (file in files) {
            val body = JSONObject(file.readText(Charsets.UTF_8))
            val function = body.getString("function")
            val vectors = body.getJSONArray("vectors")
            var filePass = 0
            var fileFail = 0
            for (i in 0 until vectors.length()) {
                val v = vectors.getJSONObject(i)
                val name = v.getString("name")
                val input = v.getJSONObject("input")
                val expected = v.getJSONObject("expected")
                val err = runVector(function, input, expected)
                if (err == null) filePass++
                else {
                    fileFail++
                    failures.add("${file.name}::$name — $err")
                }
            }
            totalPass += filePass
            totalFail += fileFail
            val mark = if (fileFail == 0) "✓" else "✗"
            println("  $mark ${file.name.padEnd(34)} $filePass/${vectors.length()}")
        }

        println("\nKotlin KAT: $totalPass passed, $totalFail failed (${totalPass + totalFail} vectors).")
        for (failure in failures) println("  $failure")
        assertEquals(0, totalFail, "Kotlin KAT corpus mismatch — see stdout for failing vectors")
    }

    // MARK: -- per-function dispatch

    private fun runVector(function: String, input: JSONObject, expected: JSONObject): String? {
        return when (function) {
            "rpo256"         -> runRpo256(input, expected)
            "rpo256Tagged"   -> runRpo256Tagged(input, expected)
            "canonicalize"   -> runCanonicalize(input, expected)
            "claimLeafHash"  -> runClaimLeafHash(input, expected)
            "leafHash"       -> runLeafHash(input, expected)
            "emptyLeafHash"  -> runEmptyLeafHash(input, expected)
            "MerkleTree"     -> runMerkle(input, expected)
            "deriveCid"      -> runDeriveCid(input, expected)
            "hkdfSha256"     -> runHkdf(input, expected)
            "parseDID"       -> runParseDid(input, expected)
            else             -> "no Kotlin runner for function \"$function\""
        }
    }

    private fun runRpo256(input: JSONObject, expected: JSONObject): String? {
        val got = bytesToHex(rpo256(hexToBytes(input.getString("hex"))))
        return matchHex(got, expected.getString("hex"))
    }

    private fun runRpo256Tagged(input: JSONObject, expected: JSONObject): String? {
        val tag = input.getInt("tag")
        val content = hexToBytes(input.getString("contentHex"))
        val got = bytesToHex(rpo256Tagged(tag, content))
        return matchHex(got, expected.getString("hex"))
    }

    private fun runCanonicalize(input: JSONObject, expected: JSONObject): String? {
        val value = reconstructCanonicalizeInput(input)
        return try {
            val bytes = canonicalize(value)
            val got = bytesToHex(bytes)
            if (expected.has("error")) {
                "expected error \"${expected.getString("error")}\", got success $got"
            } else {
                matchHex(got, expected.getString("hex"))
            }
        } catch (e: CanonicalizeError) {
            val code = e.code.toWireCode()
            if (expected.has("error")) {
                val want = expected.getString("error")
                if (code == want) null else "expected error \"$want\", got \"$code\""
            } else {
                "unexpected CanonicalizeError \"$code\""
            }
        }
    }

    private fun runClaimLeafHash(input: JSONObject, expected: JSONObject): String? {
        val key = input.getString("key")
        val value = jsonValueToAny(input.get("value"))
        val got = bytesToHex(claimLeafHash(key, value))
        return matchHex(got, expected.getString("hex"))
    }

    private fun runLeafHash(input: JSONObject, expected: JSONObject): String? {
        val kh = hexToBytes(input.getString("keyHex"))
        val vh = hexToBytes(input.getString("valueHex"))
        val got = bytesToHex(leafHash(kh, vh))
        return matchHex(got, expected.getString("hex"))
    }

    private fun runEmptyLeafHash(input: JSONObject, expected: JSONObject): String? {
        val index = input.getLong("index")
        val got = bytesToHex(emptyLeafHash(index))
        return matchHex(got, expected.getString("hex"))
    }

    private fun runMerkle(input: JSONObject, expected: JSONObject): String? {
        val entriesJson = input.getJSONArray("entries")
        val entries = (0 until entriesJson.length()).map { i ->
            val e = entriesJson.getJSONObject(i)
            e.getString("key") to jsonValueToAny(e.get("value"))
        }
        val tree = MerkleTree(entries)
        if (tree.paddedSize != expected.getInt("paddedSize")) return "paddedSize: ${tree.paddedSize} ≠ ${expected.getInt("paddedSize")}"
        if (tree.depth != expected.getInt("depth")) return "depth: ${tree.depth} ≠ ${expected.getInt("depth")}"
        if (tree.rootHex != expected.getString("rootHex")) {
            return "rootHex:\n      got      ${tree.rootHex}\n      expected ${expected.getString("rootHex")}"
        }
        val proofsJson = expected.getJSONArray("proofs")
        for (i in 0 until tree.paddedSize) {
            val actual = tree.proof(i)
            val exp = proofsJson.getJSONObject(i).getJSONArray("sibling")
            if (actual.size != exp.length()) return "proof[$i] length: ${actual.size} ≠ ${exp.length()}"
            for (j in 0 until actual.size) {
                val a = actual[j]
                val e = exp.getJSONObject(j)
                val expSib = e.getString("siblingHex")
                val expRight = e.getBoolean("isRight")
                if (bytesToHex(a.sibling) != expSib || a.isRight != expRight) {
                    return "proof[$i][$j] mismatch"
                }
            }
        }
        return null
    }

    private fun runDeriveCid(input: JSONObject, expected: JSONObject): String? {
        val headerJson = input.getJSONObject("headerWithoutCid")
        val header = jsonValueToAny(headerJson) as Map<String, Any?>
        val iat = input.getLong("iat")
        val got = bytesToHex(deriveCid(header, iat))
        return matchHex(got, expected.getString("hex"))
    }

    private fun runHkdf(input: JSONObject, expected: JSONObject): String? {
        val ikm = hexToBytes(input.getString("ikmHex"))
        val salt = hexToBytes(input.getString("saltHex"))
        val info = hexToBytes(input.getString("infoHex"))
        val length = input.getInt("length")
        val got = bytesToHex(hkdfSha256(ikm, salt, info, length))
        return matchHex(got, expected.getString("hex"))
    }

    private fun runParseDid(input: JSONObject, expected: JSONObject): String? {
        val s = input.getString("did")
        return try {
            val parsed = parseDID(s)
            if (expected.has("error")) {
                "expected error \"${expected.getString("error")}\", got success $parsed"
            } else {
                val expNet = expected.getString("network")
                val expEnt = expected.getString("entityType")
                val expId  = expected.getString("identifier")
                if (parsed.network != expNet || parsed.entityType != expEnt || parsed.identifier != expId) {
                    "parsed mismatch: $parsed ≠ {network:$expNet, entityType:$expEnt, identifier:$expId}"
                } else {
                    val round = formatDID(parsed)
                    if (round != s) "round-trip: $round ≠ $s" else null
                }
            }
        } catch (e: DIDError) {
            val code = e.code.toWireCode()
            if (expected.has("error")) {
                val want = expected.getString("error")
                if (code == want) null else "expected error \"$want\", got \"$code\""
            } else {
                "unexpected DIDError \"$code\""
            }
        }
    }

    // MARK: -- helpers

    private fun matchHex(got: String, expected: String): String? =
        if (got == expected) null
        else "hex mismatch:\n      got      $got\n      expected $expected"

    private fun CanonicalizeErrorCode.toWireCode(): String = when (this) {
        CanonicalizeErrorCode.FLOAT             -> "float"
        CanonicalizeErrorCode.CYCLE             -> "cycle"
        CanonicalizeErrorCode.DEPTH             -> "depth"
        CanonicalizeErrorCode.STRING_TOO_LONG   -> "string-too-long"
        CanonicalizeErrorCode.NAN_OR_INF        -> "nan-or-inf"
    }

    private fun DIDErrorCode.toWireCode(): String = when (this) {
        DIDErrorCode.MALFORMED       -> "malformed"
        DIDErrorCode.EXTRA_COLONS    -> "extra-colons"
        DIDErrorCode.EMPTY_COMPONENT -> "empty-component"
    }

    /** Mirror of the TS runner's reconstructCanonicalizeInput: rebuild
     *  inputs that can't round-trip cleanly through JSON (cycles, NaN,
     *  Infinity, synthesized depth/long-string). */
    private fun reconstructCanonicalizeInput(input: JSONObject): Any? {
        if (input.has("synthesize")) {
            return when (val tag = input.getString("synthesize")) {
                "cycle-self" -> {
                    val m = mutableMapOf<String, Any?>()
                    m["name"] = "cycle"
                    m["self"] = m
                    m
                }
                "depth" -> {
                    val levels = input.getInt("levels")
                    var deep: Any? = "leaf"
                    repeat(levels) { deep = mapOf("n" to deep) }
                    deep
                }
                "long-string" -> {
                    val bytes = input.getInt("utf8Bytes")
                    "a".repeat(bytes)
                }
                else -> error("unknown synthesize tag: $tag")
            }
        }
        if (input.has("nonJsonable")) {
            return when (input.getString("nonJsonable")) {
                "NaN"       -> Double.NaN
                "Infinity"  -> Double.POSITIVE_INFINITY
                "-Infinity" -> Double.NEGATIVE_INFINITY
                "undefined" -> null  // closest Kotlin equivalent; canonicalize emits "null"
                else        -> error("unknown nonJsonable tag")
            }
        }
        return jsonValueToAny(input.get("json"))
    }

    /** Convert any JSON value (org.json.JSONObject / JSONArray / primitives)
     *  to the equivalent Kotlin Map / List / primitive that canonicalize
     *  understands. org.json may return numbers as Int, Long, Double,
     *  BigDecimal, or BigInteger depending on the input's literal form
     *  and precision; we accept all of them and let canonicalize() decide
     *  whether the value is integer-valued. */
    private fun jsonValueToAny(value: Any?): Any? {
        if (value == null || value == JSONObject.NULL) return null
        return when (value) {
            is Boolean -> value
            is Int     -> value.toLong()  // canonicalize emits via Long.toString anyway
            is Long    -> value
            is Double  -> value
            is Float   -> value.toDouble()
            is java.math.BigInteger -> value
            is java.math.BigDecimal -> {
                // org.json sometimes returns BigDecimal for integer-valued
                // numbers. Downcast to Long when it fits losslessly.
                try {
                    value.longValueExact()
                } catch (_: ArithmeticException) {
                    value.toDouble()
                }
            }
            is String  -> value
            is JSONArray -> {
                (0 until value.length()).map { jsonValueToAny(value.get(it)) }
            }
            is JSONObject -> {
                val m = LinkedHashMap<String, Any?>(value.length())
                for (k in value.keys()) m[k] = jsonValueToAny(value.get(k))
                m
            }
            else -> error("unsupported JSON value: ${value::class.simpleName}")
        }
    }

    private fun locateVectorDir(): File {
        val path = System.getProperty("elabify.testVectorsPath")
            ?: error("system property elabify.testVectorsPath not set (build.gradle.kts should pass it)")
        val dir = File(path)
        require(dir.isDirectory) { "test-vectors directory not found at $path" }
        return dir
    }
}
