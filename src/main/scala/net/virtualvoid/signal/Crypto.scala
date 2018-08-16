package net.virtualvoid.signal

import java.security.MessageDigest

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

import scala.annotation.tailrec

final case class Keys(
    encryptionKey: Array[Byte],
    macKey:        Array[Byte]
)

object Crypto {
  val BackupKeyDerivationExtra = "Backup Export".getBytes("ASCII")
  def getBackupKeys(passphrase: String, salt: Array[Byte]): Keys = {
    val key = getBackupKey(passphrase, salt)
    val derived = Crypto.hkdf3(key, BackupKeyDerivationExtra, 64)

    Keys(
      derived.take(32),
      derived.drop(32)
    )
  }

  def getBackupKey(passphrase: String, salt: Array[Byte]): Array[Byte] = {
    val digest = MessageDigest.getInstance("SHA-512")
    if (salt != null) digest.update(salt)

    val input = passphrase.getBytes("ASCII")

    @tailrec
    def nextRound(hash: Array[Byte], remaining: Int): Array[Byte] =
      if (remaining == 0) hash
      else {
        digest.update(hash)
        val newHash = digest.digest(input)
        nextRound(newHash, remaining - 1)
      }

    nextRound(input, 250000)
      .take(32)
  }

  def hkdf3(key: Array[Byte], extra: Array[Byte], outputLength: Int, salt: Array[Byte] = new Array[Byte](32)): Array[Byte] = {
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(new SecretKeySpec(salt, "HmacSHA256"))
    val key2 = mac.doFinal(key)
    mac.init(new SecretKeySpec(key2, "HmacSHA256"))

    val result = new Array[Byte](outputLength)

    @tailrec
    def step(lastResult: Array[Byte], iteration: Int, resultOffset: Int): Array[Byte] =
      if (resultOffset >= outputLength) result
      else {
        mac.update(lastResult)
        mac.update(extra)
        mac.update(iteration.toByte)

        val newData = mac.doFinal()
        val needed = math.min(newData.size, outputLength - resultOffset)
        System.arraycopy(newData, 0, result, resultOffset, needed)
        step(newData, iteration + 1, resultOffset + needed)
      }

    step(Array.empty, iteration = 1, 0)
  }
}
