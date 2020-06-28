package net.virtualvoid.signal

import java.io.{ File, FileInputStream, FileOutputStream, InputStream }
import java.security.{ MessageDigest, SecureRandom }
import java.util

import com.google.protobuf.ByteString
import javax.crypto.{ Cipher, Mac }
import javax.crypto.spec.{ IvParameterSpec, SecretKeySpec }
import org.thoughtcrime.securesms.backup.BackupProtos
import org.thoughtcrime.securesms.backup.BackupProtos.BackupFrame

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

  def foldRawEvents[T](backupFile: File, password: String, initialT: T)(f: (T, RawBackupEvent) => T): T =
    rawEventIterator(backupFile, password).foldLeft(initialT)(f)

  def rawEventIterator(backupFile: File, password: String): Iterator[RawBackupEvent] = {
    val fis = new FileInputStream(backupFile)
    val pass = password.trim.replaceAll(" ", "")

    val headerReader = new PlainInputStreamReader(fis)
    val header = headerReader.readPlainFrame().getHeader

    val salt = if (header.hasSalt) header.getSalt.toByteArray else null
    val keys = Crypto.getBackupKeys(pass, salt)

    val cipher = Cipher.getInstance("AES/CTR/NoPadding")

    val mac = Mac.getInstance("HmacSHA256")
    val cipherSetup = CipherSetup(cipher, mac, keys.encryptionKey)
    mac.init(new SecretKeySpec(keys.macKey, "HmacSHA256"))

    val initialIv = header.getIv.toByteArray

    val reader = new EncryptedInputStreamReader(fis, cipherSetup)

    new Iterator[RawBackupEvent] {
      var iv: Array[Byte] = initialIv
      override def hasNext: Boolean = fis.available() > 0
      override def next(): RawBackupEvent = {
        val (event, nextIv) = reader.readSecretFrame(iv)
        iv = nextIv
        event
      }
    }
  }

  def writeEvents(backupFile: File, password: String, events: Iterator[RawBackupEvent]): Unit = {
    require(!backupFile.exists(), s"Target file already exists: ${backupFile.getAbsolutePath}")
    val pass = password.trim.replaceAll(" ", "")

    val random = new SecureRandom()
    val salt: Array[Byte] = new Array[Byte](32)
    val initialIv: Array[Byte] = new Array[Byte](16)
    random.nextBytes(salt)
    random.nextBytes(initialIv)

    val keys = Crypto.getBackupKeys(pass, salt)

    val cipher = Cipher.getInstance("AES/CTR/NoPadding")

    val mac = Mac.getInstance("HmacSHA256")
    mac.init(new SecretKeySpec(keys.macKey, "HmacSHA256"))
    val cipherSetup = CipherSetup(cipher, mac, keys.encryptionKey)

    val fos = new FileOutputStream(backupFile)
    def writeIntBE(i: Int): Unit = fos.write(uint32BE(i))
    def write(data: Array[Byte]): Unit = fos.write(data)

    def writeHeaderFrame(): Unit = {
      val headerFrameBytes =
        BackupProtos.BackupFrame.newBuilder()
          .setHeader(
            BackupProtos.Header.newBuilder()
              .setIv(ByteString.copyFrom(initialIv))
              .setSalt(ByteString.copyFrom(salt))
          )
          .build().toByteArray
      writeIntBE(headerFrameBytes.length)
      write(headerFrameBytes)
    }
    def writeFrame(iv: Array[Byte], frame: RawBackupEvent): Array[Byte] = frame match {
      case RawBackupEvent.FrameEvent(frame) =>
        val frameData = frame.toByteArray
        val encData = cipherSetup.encrypt(iv, frameData)
        val macData = mac.doFinal(encData).take(10)

        writeIntBE(encData.length + 10)
        write(encData)
        write(macData)
        nextIv(iv)

      case RawBackupEvent.FrameEventWithAttachment(frame, attachmentData) =>
        val next = writeFrame(iv, RawBackupEvent.FrameEvent(frame))
        require(attachmentData.size == getAttachmentLength(frame))
        val encAttData = cipherSetup.encrypt(next, attachmentData)
        write(encAttData)
        mac.update(next)
        write(mac.doFinal(encAttData).take(10))
        nextIv(next)
    }
    def getAttachmentLength(frame: BackupFrame): Int =
      if (frame.hasAttachment) frame.getAttachment.getLength
      else if (frame.hasAvatar) frame.getAvatar.getLength
      else if (frame.hasSticker) frame.getSticker.getLength
      else throw new IllegalArgumentException(s"Frame cannot have attachment ${frame}")

    writeHeaderFrame()
    events.foldLeft(initialIv)(writeFrame)
    fos.close()
  }

  case class CipherSetup(cipher: Cipher, mac: Mac, cipherKey: Array[Byte]) {
    def decrypt(iv: Array[Byte], data: Array[Byte]): Array[Byte] = {
      cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(cipherKey, "AES"), new IvParameterSpec(iv))
      cipher.doFinal(data)
    }
    def encrypt(iv: Array[Byte], data: Array[Byte]): Array[Byte] = {
      cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(cipherKey, "AES"), new IvParameterSpec(iv))
      cipher.doFinal(data)
    }
  }

  class PlainInputStreamReader(fis: InputStream) {
    def uint32BE(): Int =
      fis.read() << 24 |
        fis.read() << 16 |
        fis.read() << 8 |
        fis.read()

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
    def readSecretFrame(iv: Array[Byte]): (RawBackupEvent, Array[Byte]) = {
      val len = uint32BE()
      require(len < MaxFrameLength, s"Frame length [${len}] > MaxFrameLength [$MaxFrameLength]. Data corrupted?")
      val encFrameData = bytes(len - 10)
      val mac = bytes(10)
      val plainFrameData = cipherSetup.decrypt(iv, encFrameData)
      val actual = cipherSetup.mac.doFinal(encFrameData).take(10)
      val isSame = MessageDigest.isEqual(mac, actual)
      def print(data: Array[Byte]): String =
        data.map(_ formatted "%02x").mkString("[", " ", "]")
      require(isSame, s"Macs don't match ${print(actual)} ${print(mac)}")
      val frame = BackupProtos.BackupFrame.parseFrom(plainFrameData)

      val extraDataLength =
        if (frame.hasAttachment)
          frame.getAttachment.getLength
        else if (frame.hasAvatar)
          frame.getAvatar.getLength
        else if (frame.hasSticker)
          frame.getSticker.getLength
        else -1

      if (extraDataLength >= 0) {
        require(extraDataLength < MaxAttachmentLength, s"Frame length [$extraDataLength] > MaxAttachmentLength [$MaxAttachmentLength]. Data corrupted?")

        val attIv = nextIv(iv)
        val encAtt = bytes(extraDataLength)
        val attMac = bytes(10)
        cipherSetup.mac.update(attIv)
        val actual = cipherSetup.mac.doFinal(encAtt).take(10)
        require(MessageDigest.isEqual(attMac, actual), s"Macs don't match ${print(actual)} ${print(attMac)}")
        val plainAtt = cipherSetup.decrypt(attIv, encAtt)

        (RawBackupEvent.FrameEventWithAttachment(frame, plainAtt), nextIv(attIv))
      } else
        (RawBackupEvent.FrameEvent(frame), nextIv(iv))
    }
  }

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
  def nextIv(iv: Array[Byte]): Array[Byte] = {
    val i = uint32BE(iv) + 1
    val res = iv.clone() // iv is 16 bytes long and we count only in the first 4 bytes
    res(0) = (i >> 24).toByte
    res(1) = (i >> 16).toByte
    res(2) = (i >> 8).toByte
    res(3) = i.toByte
    res
  }
}
