package net.virtualvoid.signal

import java.io.File
import java.io.FileInputStream
import java.io.InputStream

import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import org.thoughtcrime.securesms.backup.BackupProtos
import org.thoughtcrime.securesms.backup.BackupProtos.BackupFrame

import scala.annotation.tailrec

sealed trait RawBackupEvent
object RawBackupEvent {
  final case class FrameEvent(frame: BackupFrame) extends RawBackupEvent
  final case class FrameEventWithAttachment(frame: BackupFrame, attachmentData: Array[Byte]) extends RawBackupEvent
}

object FrameReader {
  val MaxFrameLength = 1000 * 1000
  val MaxAttachmentLength = 100 * 1000 * 1000

  def foldRawEvents[T](backupFile: File, password: String, initialT: T)(f: (T, RawBackupEvent) => T): T = {
    val fis = new FileInputStream(backupFile)
    val pass = password.trim.replaceAll(" ", "")

    val headerReader = new PlainInputStreamReader(fis)
    val header = headerReader.readPlainFrame().getHeader

    val salt = if (header.hasSalt) header.getSalt.toByteArray else null
    val keys = Crypto.getBackupKeys(pass, salt)

    val cipher = Cipher.getInstance("AES/CTR/NoPadding")

    val cipherSetup = CipherSetup(cipher, keys.encryptionKey)
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(new SecretKeySpec(keys.macKey, "HmacSHA256"))

    val iv = header.getIv.toByteArray

    val reader = new EncryptedInputStreamReader(fis, cipherSetup)

    @tailrec
    def readNext(iv: Array[Byte], t: T): T =
      if (fis.available() > 0) {
        val (event, nextIv) = reader.readSecretFrame(iv)
        val newT = f(t, event)
        readNext(nextIv, newT)
      } else t

    readNext(iv, initialT)
  }

  case class CipherSetup(cipher: Cipher, cipherKey: Array[Byte]) {
    def decrypt(iv: Array[Byte], data: Array[Byte]): Array[Byte] = {
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cipherKey, "AES"), new IvParameterSpec(iv))
      cipher.doFinal(data)
    }
  }

  class PlainInputStreamReader(fis: InputStream) {
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
      if (count > fis.available()) throw new IllegalStateException(s"Couldn't read [$count] bytes from stream, only [${fis.available()}] available")
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
  }

  class EncryptedInputStreamReader(fis: InputStream, cipherSetup: CipherSetup) extends PlainInputStreamReader(fis) {
    def nextIv(iv: Array[Byte]): Array[Byte] = {
      val i = uint32BE(iv) + 1
      val res = iv.clone()
      res(0) = (i >> 24).toByte
      res(1) = (i >> 16).toByte
      res(2) = (i >> 8).toByte
      res(3) = i.toByte
      res
    }

    def readSecretFrame(iv: Array[Byte]): (RawBackupEvent, Array[Byte]) = {
      val len = uint32BE()
      require(len < MaxFrameLength, s"Frame length [${len}] > MaxFrameLength [$MaxFrameLength]. Data corrupted?")
      val encFrameData = bytes(len - 10)
      val mac = bytes(10)
      val plainFrameData = cipherSetup.decrypt(iv, encFrameData)
      val frame = BackupProtos.BackupFrame.parseFrom(plainFrameData)

      val extraDataLength =
        if (frame.hasAttachment)
          frame.getAttachment.getLength
        else if (frame.hasAvatar)
          frame.getAvatar.getLength
        else -1

      if (extraDataLength >= 0) {
        require(extraDataLength < MaxAttachmentLength, s"Frame length [$extraDataLength] > MaxAttachmentLength [$MaxAttachmentLength]. Data corrupted?")

        val attIv = nextIv(iv)
        val encAtt = bytes(extraDataLength)
        val attMac = bytes(10)
        val plainAtt = cipherSetup.decrypt(attIv, encAtt)

        (RawBackupEvent.FrameEventWithAttachment(frame, plainAtt), nextIv(attIv))
      } else
        (RawBackupEvent.FrameEvent(frame), nextIv(iv))
    }
  }
}
