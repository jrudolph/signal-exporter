package net.virtualvoid.signal

import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

import org.thoughtcrime.securesms.backup.BackupProtos
import org.thoughtcrime.securesms.backup.BackupProtos.BackupFrame
import org.whispersystems.libsignal.kdf.HKDFv3

import scala.annotation.tailrec
import scala.io.Source

object Exporter extends App {
  def existingFile(role: String, path: String): File = {
    val file = new File(path)
    if (!file.exists) {
      println(s"$role is missing at ${file.getAbsolutePath}")
      sys.exit(1)
    }
    file
  }

  val backupFile = existingFile("Backup file", "backup.bin")
  val passFile = existingFile("Passphrase file", "passphrase.txt")
  val pass = Source.fromFile(passFile).mkString.trim.replaceAll(" ", "")
  require(pass.length == 30, s"Passphrase must have 30 characters but had ${pass.length}")

  val attachmentsDir = existingFile("Attachments dir", "attachments")

  val fis = new FileInputStream(backupFile)

  def uint32BE(): Int =
    fis.read() << 24 |
      fis.read() << 16 |
      fis.read() << 8 |
      fis.read()

  def uint32BE(bytes: Array[Byte]): Int =
    (bytes(0) & 0xff) << 24 |
      (bytes(1) & 0xff) << 16 |
      (bytes(2) & 0xff) << 8 |
      (bytes(3) & 0xff)

  def uint32BE(i: Int): Array[Byte] = {
    val buf = new Array[Byte](4)
    buf(0) = (i >> 24).toByte
    buf(1) = ((i >> 16) & 0xff).toByte
    buf(2) = ((i >> 8) & 0xff).toByte
    buf(3) = (i & 0xff).toByte

    buf
  }

  def bytes(count: Int): Array[Byte] = {
    val buf = new Array[Byte](count)
    fis.read(buf)
    buf
  }

  def readPlainFrame(): BackupFrame = {
    val len = uint32BE()
    val frameData = bytes(len)
    val frame = BackupProtos.BackupFrame.parseFrom(frameData)
    frame
  }
  def nextIv(iv: Array[Byte]): Array[Byte] = {
    val i = uint32BE(iv) + 1
    val res = iv.clone()
    res(0) = (i >> 24).toByte
    res(1) = (i >> 16).toByte
    res(2) = (i >> 8).toByte
    res(3) = i.toByte
    res
  }

  def readSecretFrame(iv: Array[Byte]): (BackupFrame, Array[Byte]) = {
    val len = uint32BE()
    val encFrameData = bytes(len - 10)
    val mac = bytes(10)
    cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cipherKey, "AES"), new IvParameterSpec(iv))
    val plainFrameData = cipher.doFinal(encFrameData)
    val frame = BackupProtos.BackupFrame.parseFrom(plainFrameData)

    val nextI =
      if (frame.hasAttachment) {
        val attachment = frame.getAttachment
        val attIv = nextIv(iv)
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cipherKey, "AES"), new IvParameterSpec(attIv))
        val encAtt = bytes(attachment.getLength)
        val attMac = bytes(10)
        val plainAtt = cipher.doFinal(encAtt)

        val out = new FileOutputStream(new File(attachmentsDir, "${attachment.getAttachmentId}.jpg"))
        out.write(plainAtt)
        out.close()

        nextIv(attIv)
      } else nextIv(iv)

    (frame, nextI)
  }

  val header = readPlainFrame().getHeader

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

  val salt = if (header.hasSalt) header.getSalt.toByteArray else null
  val keys = getBackupKey(pass, salt)

  val derived = new HKDFv3().deriveSecrets(keys, "Backup Export".getBytes(), 64)
  val cipherKey = derived.take(32)
  val macKey = derived.drop(32)

  val cipher = Cipher.getInstance("AES/CTR/NoPadding")
  val mac = Mac.getInstance("HmacSHA256")
  mac.init(new SecretKeySpec(macKey, "HmacSHA256"))

  val iv = header.getIv.toByteArray

  @tailrec
  def readNext(iv: Array[Byte]): Unit =
    if (fis.available() > 0) {
      val (frame, next) = readSecretFrame(iv)
      println(iv.mkString(","))
      println(next.mkString(","))
      println(frame)
      readNext(next)
    }

  readNext(iv)
}
