package org.ergoplatform.mining

import org.scalatest.flatspec.AnyFlatSpec
import org.scalatest.matchers.should.Matchers

class Pufferfish2Spec extends AnyFlatSpec with Matchers {

    "pf_salt_size" should "be correctly calculated" in {
        val expectedSaltSize = 1 + 1 + Pufferfish2.PF_SALT_SZ
        Pufferfish2.pf_salt_size shouldEqual expectedSaltSize
    }

    "pf_mksalt" should "generate a salt of correct format and length" in {
        val cost_t = 10
        val cost_m = 10
        val salt = Pufferfish2.pf_mksalt(cost_t, cost_m)
        salt should startWith(Pufferfish2.PF_ID)
        salt.length should be > Pufferfish2.PF_ID_SZ
    }

    "pf_encode and pf_decode" should "correctly encode and decode data" in {
        val data = Array[Byte](1, 2, 3, 4, 5)
        val encoded = Pufferfish2.pf_encode(data)
        val decoded = Pufferfish2.pf_decode(encoded, data.length)
        decoded shouldEqual data
    }

    "pf_hashpass" should "generate a hash of correct length" in {
        val salt = Array.fill[Byte](Pufferfish2.PF_SALT_SZ)(0)
        val cost_t = 10
        val cost_m = 10
        val password = "password".getBytes("UTF-8")
        val hash = Pufferfish2.pf_hashpass(salt, cost_t, cost_m, password)
        hash.length shouldEqual Pufferfish2.PF_DIGEST_LENGTH
    }

    "pf_crypt" should "generate a valid hash" in {
        val password = "password".getBytes("UTF-8")
        val salt = Pufferfish2.pf_mksalt(10, 10)
        val hash = Pufferfish2.pf_crypt(salt, password)
        hash should startWith(Pufferfish2.PF_ID)
    }

    "pf_checkpass" should "correctly validate a password" in {
        val password = "password".getBytes("UTF-8")
        val hash = Pufferfish2.pf_newhash(password, 10, 10)
        Pufferfish2.pf_checkpass(hash, password) shouldBe true
        Pufferfish2.pf_checkpass(hash, "wrongpassword".getBytes("UTF-8")) shouldBe false
    }
}
