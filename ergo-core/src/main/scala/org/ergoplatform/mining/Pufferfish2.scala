package org.ergoplatform.mining

import java.security.SecureRandom
import scala.util.control.Breaks._
import java.nio.ByteBuffer
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.bouncycastle.crypto.macs.HMac
import org.bouncycastle.crypto.digests.SHA512Digest
import org.bouncycastle.crypto.params.KeyParameter

object Pufferfish2 {

  val PF_ID = "$PF2$"
  val PF_ID_SZ = PF_ID.length
  val PF_SBOX_N = 4
  val PF_SALT_SZ = 16
  val PF_DIGEST_LENGTH = 64
  val PF_DIGEST = "SHA-512"

  val pf_salt_size = 1 + 1 + PF_SALT_SZ // cost_t + cost_m + salt
  val PF_SALTSPACE = 2 + PF_ID_SZ + bin2enc_len(pf_salt_size)
  val PF_HASHSPACE = PF_SALTSPACE + bin2enc_len(PF_DIGEST_LENGTH)

  val itoa64: Array[Char] = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".toCharArray
  val idx64: Array[Int] = Array(
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,   0,   1,
     54,  55,  56,  57,  58,  59,  60,  61,  62,  63, 255, 255, 255, 255, 255, 255,
    255,   2,   3,   4,   5,   6,   7,   8,   9,  10,  11,  12,  13,  14,  15,  16,
     17,  18,  19,  20,  21,  22,  23,  24,  25,  26,  27, 255, 255, 255, 255, 255,
    255,  28,  29,  30,  31,  32,  33,  34,  35,  36,  37,  38,  39,  40,  41,  42,
     43,  44,  45,  46,  47,  48,  49,  50,  51,  52,  53, 255, 255, 255, 255, 255
  )

  // Helper functions
  def bin2enc_len(x: Int): Int = ((x + 2) / 3) * 4
  def chr64(c: Char): Int = {
    val ci = c.toInt
    if (ci >= 0 && ci < idx64.length) idx64(ci) else 255
  }

  case class PfSalt(cost_t: Int, cost_m: Int, salt: Array[Byte])

  // PF_HMAC function
  def PF_HMAC(key: Array[Byte], data: Array[Byte]): Array[Byte] = {
    val digest = new SHA512Digest()
    val hmac = new HMac(digest)
    val keyParam = new KeyParameter(key)
    hmac.init(keyParam)
    hmac.update(data, 0, data.length)
    val out = new Array[Byte](hmac.getMacSize)
    hmac.doFinal(out, 0)
    out
  }

  // PF encode function
  def pf_encode(src: Array[Byte]): String = {
    val sb = new StringBuilder
    var sptr = 0
    val size = src.length
    while (sptr < size) {
      var c1 = src(sptr) & 0xff
      sptr += 1
      sb.append(itoa64(c1 >> 2))
      c1 = (c1 & 0x03) << 4

      if (sptr >= size) {
        sb.append(itoa64(c1))
        return sb.toString
      }

      var c2 = src(sptr) & 0xff
      sptr += 1
      c1 |= (c2 >> 4) & 0x0f
      sb.append(itoa64(c1))
      c1 = (c2 & 0x0f) << 2

      if (sptr >= size) {
        sb.append(itoa64(c1))
        return sb.toString
      }

      c2 = src(sptr) & 0xff
      sptr += 1
      c1 |= (c2 >> 6) & 0x03
      sb.append(itoa64(c1))
      sb.append(itoa64(c2 & 0x3f))
    }
    sb.toString
  }

  // PF decode function
  def pf_decode(src: String, size: Int): Array[Byte] = {
    val dst = new Array[Byte](size)
    var sptr = 0
    var dptr = 0
    val end = size

    breakable {
      while (dptr < end && sptr < src.length) {
        val c1 = chr64(src.charAt(sptr))
        val c2 = chr64(src.charAt(sptr + 1))

        if (c1 == 255 || c2 == 255) break

        dst(dptr) = ((c1 << 2) | ((c2 & 0x30) >> 4)).toByte
        dptr += 1
        if (dptr >= end || sptr + 2 >= src.length) break

        val c3 = chr64(src.charAt(sptr + 2))
        if (c3 == 255) break

        dst(dptr) = (((c2 & 0x0f) << 4) | ((c3 & 0x3c) >> 2)).toByte
        dptr += 1
        if (dptr >= end || sptr + 3 >= src.length) break

        val c4 = chr64(src.charAt(sptr + 3))
        if (c4 == 255) break

        dst(dptr) = (((c3 & 0x03) << 6) | c4).toByte
        dptr += 1
        sptr += 4
      }
    }
    dst.slice(0, dptr)
  }

  // Function to generate a new salt
  def pf_mksalt(cost_t: Int, cost_m: Int): String = {
    val settings = new Array[Byte](pf_salt_size)
    settings(0) = cost_t.toByte
    settings(1) = cost_m.toByte
    // Generate random salt of PF_SALT_SZ bytes
    val randomSalt = new Array[Byte](PF_SALT_SZ)
    new SecureRandom().nextBytes(randomSalt)
    System.arraycopy(randomSalt, 0, settings, 2, PF_SALT_SZ)
    val saltEncoded = pf_encode(settings)
    PF_ID + saltEncoded + "$"
  }

  // Function to perform password hashing
def pf_hashpass(
      salt_r: Array[Byte],
      cost_t: Int,
      cost_m: Int,
      key_r: Array[Byte]
  ): Array[Byte] = {

    // Initialize key and salt arrays
    val key = new Array[Byte](PF_DIGEST_LENGTH)
    val salt = new Array[Byte](PF_DIGEST_LENGTH)

    // Initialize variables
    var L: Long = 0L
    var R: Long = 0L
    var LL: Long = 0L
    var RR: Long = 0L
    var count: Long = 0L
    var sbox_sz: Long = 0L
    var log2_sbox_sz: Int = 0
    var j: Long = 0L

    // Convert key and salt to LongBuffers for 64-bit operations
    val key_u64 = ByteBuffer.wrap(key).order(ByteOrder.BIG_ENDIAN).asLongBuffer()
    val salt_u64 = ByteBuffer.wrap(salt).order(ByteOrder.BIG_ENDIAN).asLongBuffer()

    // Compute sbox size
    log2_sbox_sz = cost_m + 5
    sbox_sz = 1L << log2_sbox_sz

    // Perform initial HMAC operations
    val emptyKey = new Array[Byte](0)
    val saltHmac = PF_HMAC(emptyKey, salt_r)
    System.arraycopy(saltHmac, 0, salt, 0, PF_DIGEST_LENGTH)

    val keyHmac = PF_HMAC(salt, key_r)
    System.arraycopy(keyHmac, 0, key, 0, PF_DIGEST_LENGTH)

    // Initialize S-boxes
    val S = Array.fill(PF_SBOX_N)(new Array[Long](sbox_sz.toInt))
    for (i <- 0 until PF_SBOX_N) {
      j = 0L
      while (j < sbox_sz) {
        val keyHmacInner = PF_HMAC(key, salt)
        System.arraycopy(keyHmacInner, 0, key, 0, PF_DIGEST_LENGTH)
        val key_u64_inner = ByteBuffer.wrap(key).order(ByteOrder.BIG_ENDIAN).asLongBuffer()
        for (k <- 0 until (PF_DIGEST_LENGTH / 8)) {
          S(i)((j + k).toInt) = key_u64_inner.get(k)
        }
        j += PF_DIGEST_LENGTH / 8
      }
    }

    // Define F function
    def F(x: Long): Long = {
      val idx0 = (x >>> (64 - log2_sbox_sz)).toInt
      val idx1 = ((x >>> 35) & (sbox_sz - 1)).toInt
      val idx2 = ((x >>> 19) & (sbox_sz - 1)).toInt
      val idx3 = ((x >>> 3) & (sbox_sz - 1)).toInt
      (((S(0)(idx0) ^ S(1)(idx1)) + S(2)(idx2)) ^ S(3)(idx3))
    }

    // Initialize P-array
    val P = new Array[Long](18)
    for (i <- 0 until 18) {
      val keyIndex = i % 8
      val keyValue = key_u64.get(keyIndex)
      val initialP = i match {
        case 0  => 0x243f6a8885a308d3L
        case 1  => 0x13198a2e03707344L
        case 2  => 0xa4093822299f31d0L
        case 3  => 0x082efa98ec4e6c89L
        case 4  => 0x452821e638d01377L
        case 5  => 0xbe5466cf34e90c6cL
        case 6  => 0xc0ac29b7c97c50ddL
        case 7  => 0x3f84d5b5b5470917L
        case 8  => 0x9216d5d98979fb1bL
        case 9  => 0xd1310ba698dfb5acL
        case 10 => 0x2ffd72dbd01adfb7L
        case 11 => 0xb8e1afed6a267e96L
        case 12 => 0xba7c9045f12c7f99L
        case 13 => 0x24a19947b3916cf7L
        case 14 => 0x0801f2e2858efc16L
        case 15 => 0x636920d871574e69L
        case 16 => 0xa458fea3f4933d7eL
        case 17 => 0x0d95748f728eb658L
      }
      P(i) = initialP ^ keyValue
    }

    // Define ENCIPHER function
    def ENCIPHER(): Unit = {
      L ^= P(0)
      R = (R ^ F(L)) ^ P(1)
      L = (L ^ F(R)) ^ P(2)
      R = (R ^ F(L)) ^ P(3)
      L = (L ^ F(R)) ^ P(4)
      R = (R ^ F(L)) ^ P(5)
      L = (L ^ F(R)) ^ P(6)
      R = (R ^ F(L)) ^ P(7)
      L = (L ^ F(R)) ^ P(8)
      R = (R ^ F(L)) ^ P(9)
      L = (L ^ F(R)) ^ P(10)
      R = (R ^ F(L)) ^ P(11)
      L = (L ^ F(R)) ^ P(12)
      R = (R ^ F(L)) ^ P(13)
      L = (L ^ F(R)) ^ P(14)
      R = (R ^ F(L)) ^ P(15)
      L = (L ^ F(R)) ^ P(16)
      R ^= P(17)
      LL = R
      RR = L
      L = LL
      R = RR
    }

    // Define EXPANDSTATE function
    def EXPANDSTATE(a: Long, b: Long): (Long, Long) = {
      L ^= a
      R ^= b
      ENCIPHER()
      (L, R)
    }

    // Implement ENCRYPT_P
    def ENCRYPT_P(): Unit = {
      var result: (Long, Long) = null
      result = EXPANDSTATE(salt_u64.get(0), salt_u64.get(1)); P(0) = result._1; P(1) = result._2
      result = EXPANDSTATE(salt_u64.get(2), salt_u64.get(3)); P(2) = result._1; P(3) = result._2
      result = EXPANDSTATE(salt_u64.get(4), salt_u64.get(5)); P(4) = result._1; P(5) = result._2
      result = EXPANDSTATE(salt_u64.get(6), salt_u64.get(7)); P(6) = result._1; P(7) = result._2
      result = EXPANDSTATE(salt_u64.get(0), salt_u64.get(1)); P(8) = result._1; P(9) = result._2
      result = EXPANDSTATE(salt_u64.get(2), salt_u64.get(3)); P(10) = result._1; P(11) = result._2
      result = EXPANDSTATE(salt_u64.get(4), salt_u64.get(5)); P(12) = result._1; P(13) = result._2
      result = EXPANDSTATE(salt_u64.get(6), salt_u64.get(7)); P(14) = result._1; P(15) = result._2
      result = EXPANDSTATE(salt_u64.get(0), salt_u64.get(1)); P(16) = result._1; P(17) = result._2
    }

    // Implement ENCRYPT_S
    def ENCRYPT_S(): Unit = {
      for (i <- 0 until sbox_sz.toInt by 2) {
        val idx_a = (i & 7)
        val idx_b = ((i + 1) & 7)
        val result = EXPANDSTATE(salt_u64.get(idx_a), salt_u64.get(idx_b))
        S(0)(i) = result._1; S(0)(i + 1) = result._2
      }
      for (i <- 0 until sbox_sz.toInt by 2) {
        val idx_a = (i & 7)
        val idx_b = ((i + 1) & 7)
        val result = EXPANDSTATE(salt_u64.get(idx_a), salt_u64.get(idx_b))
        S(1)(i) = result._1; S(1)(i + 1) = result._2
      }
      for (i <- 0 until sbox_sz.toInt by 2) {
        val idx_a = (i & 7)
        val idx_b = ((i + 1) & 7)
        val result = EXPANDSTATE(salt_u64.get(idx_a), salt_u64.get(idx_b))
        S(2)(i) = result._1; S(2)(i + 1) = result._2
      }
      for (i <- 0 until sbox_sz.toInt by 2) {
        val idx_a = (i & 7)
        val idx_b = ((i + 1) & 7)
        val result = EXPANDSTATE(salt_u64.get(idx_a), salt_u64.get(idx_b))
        S(3)(i) = result._1; S(3)(i + 1) = result._2
      }
    }

    // Implement EXPANDSTATE_NULL function
    def EXPANDSTATE_NULL(): (Long, Long) = {
      ENCIPHER()
      (L, R)
    }

    // Implement REKEY function
    def REKEY(): Unit = {
      for (i <- 0 until 18) {
        P(i) ^= key_u64.get(i % 8)
      }
      for (i <- 0 until 18 by 2) {
        val result = EXPANDSTATE_NULL()
        P(i) = result._1; P(i + 1) = result._2
      }
      for (sbox <- S) {
        for (i <- 0 until sbox_sz.toInt by 2) {
          val result = EXPANDSTATE_NULL()
          sbox(i) = result._1; sbox(i + 1) = result._2
        }
      }
    }

    // Implement HASH_SBOX function
    def HASH_SBOX(x: Array[Byte]): Unit = {
      for (i <- 0 until PF_SBOX_N) {
        val S_i_bytes = new Array[Byte](sbox_sz.toInt * 8)
        val buffer = ByteBuffer.wrap(S_i_bytes).order(ByteOrder.BIG_ENDIAN)
        for (j <- 0 until sbox_sz.toInt) {
          buffer.putLong(S(i)(j))
        }
        val hmacResult = PF_HMAC(x, S_i_bytes)
        System.arraycopy(hmacResult, 0, x, 0, PF_DIGEST_LENGTH)
      }
    }

    // Begin encryption steps
    ENCRYPT_P()
    ENCRYPT_S()

    // Main hashing loop
    count = (1L << cost_t) + 1
    while (count > 0) {
      L = 0L
      R = 0L
      HASH_SBOX(key)
      REKEY()
      count -= 1
    }

    // Final hash computation
    HASH_SBOX(key)

    // Prepare output
    val out = new Array[Byte](PF_DIGEST_LENGTH)
    System.arraycopy(key, 0, out, 0, PF_DIGEST_LENGTH)

    // Return the final hash
    out
  }

  // Function to perform crypt operation
  def pf_crypt(saltStr: String, pass: Array[Byte]): String = {
    if (!saltStr.startsWith(PF_ID))
      throw new IllegalArgumentException("Invalid salt prefix")

    val p = saltStr.lastIndexOf('$')
    if (p == -1)
      throw new IllegalArgumentException("Invalid salt format")

    val settingsEncoded = saltStr.substring(PF_ID_SZ, p)
    val settingsBytes = pf_decode(settingsEncoded, pf_salt_size)
    if (settingsBytes.length != pf_salt_size)
      throw new IllegalArgumentException("Invalid salt data")

    val cost_t = settingsBytes(0) & 0xff
    val cost_m = settingsBytes(1) & 0xff
    val salt = settingsBytes.slice(2, 2 + PF_SALT_SZ)

    val buf = pf_hashpass(salt, cost_t, cost_m, pass)

    val hashEncoded = pf_encode(buf)
    val hash = saltStr.substring(0, p + 1) + hashEncoded

    hash
  }

  // Function to create a new hash
  def pf_newhash(pass: Array[Byte], cost_t: Int, cost_m: Int): String = {
    if (cost_t > 63 || cost_m > 53)
      throw new IllegalArgumentException("Cost parameters are too high")

    val salt = pf_mksalt(cost_t, cost_m)
    pf_crypt(salt, pass)
  }

  // Function to check a password against a valid hash
  def pf_checkpass(valid: String, pass: Array[Byte]): Boolean = {
    val hash = pf_crypt(valid, pass)
    java.util.Arrays.equals(hash.getBytes("UTF-8"), valid.getBytes("UTF-8"))
  }
}
