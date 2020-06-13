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

object RawFrameReader {
  val MaxFrameLength = 1000 * 1000
  val MaxAttachmentLength = 100 * 1000 * 1000

  trait RawBackupEventConsumer[U] {
    type T
    def initial: T
    def step(current: T, event: RawBackupEvent): T
    def finalStep(result: T): U

    def andThen[V](f: U => V): RawBackupEventConsumer[V] =
      RawBackupEventConsumer.apply[T, V](initial, step, t => f(finalStep(t)))

    def run(backupFile: File, pass: String): U =
      foldRawEvents(backupFile, pass)(this)
  }
  object RawBackupEventConsumer {
    def apply[_T](_initial: _T, _step: (_T, RawBackupEvent) => _T): RawBackupEventConsumer[_T] =
      apply[_T, _T](_initial, _step, identity)

    def apply[_T, U](_initial: _T, _step: (_T, RawBackupEvent) => _T, _finalStep: _T => U): RawBackupEventConsumer[U] =
      new RawBackupEventConsumer[U] {
        override type T = _T

        override def initial: T = _initial
        override def step(current: T, event: RawBackupEvent): T = _step(current, event)
        override def finalStep(result: _T): U = _finalStep(result)
      }
  }

  def foldRawEvents[U](backupFile: File, password: String)(consumer: RawBackupEventConsumer[U]): U = {
    val tResult = foldRawEvents(backupFile, password, consumer.initial)((t, event) => consumer.step(t, event))
    consumer.finalStep(tResult)
  }

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
      val res = iv.clone() // iv is 16 bytes long and we count only in the first 4 bytes
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
      val _ /*mac*/ = bytes(10)
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
        val _ /*attMac*/ = bytes(10)
        val plainAtt = cipherSetup.decrypt(attIv, encAtt)

        (RawBackupEvent.FrameEventWithAttachment(frame, plainAtt), nextIv(attIv))
      } else
        (RawBackupEvent.FrameEvent(frame), nextIv(iv))
    }
  }
}
